"""Ingestion service: accept URLs into the queue, record finished analyses.

Part 9: Batch B-2 - automatic ThreatRadar ingestion.

Design (viva):
- ThreatRadar PUSHES newly found URLs to ``POST /api/v1/ingest``. C2 only validates and
  queues them and answers 202 at once - analysing one page takes 0.2-2 s plus the fetch,
  so ThreatRadar never waits for (or times out on) the models. A background worker
  (worker.py) analyses the queue at a safe, configurable rate with the 9B-1 engine.
- A daily PULL of ThreatRadar's data files (pull.py) is the backup: URLs a push missed
  (C2 down, network error) are queued as ``threatradar_pull``; nothing is lost.
- Dedupe: the same normalized URL analysed within the TTL (24 h) or still queued is not
  analysed again - a ``skipped_duplicate`` job points to the earlier one and reuses its
  result (a viral scam link is posted in many channels; re-fetching helps no one).
- Users' own checks (``POST /api/v1/analyze``) are stored too, so they show in history.
- Live results are NEVER added to training data automatically. Malicious results and
  high-risk Suspicious ones go to a human REVIEW queue; only confirmed labels are
  exported to the Part 1 manual feed. Self-training on the model's own verdicts would
  feed its mistakes back as "truth" (confirmation bias) and slowly poison the dataset.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field, replace
from datetime import timedelta

from c2_analyzer.api.guards import normalize_url
from c2_analyzer.dataset.feeds import is_allow_listed, load_threatradar_rules
from c2_analyzer.ingest.config import IngestConfig, ingest_config
from c2_analyzer.ingest.events import EventBus
from c2_analyzer.schemas.analysis import AnalysisRequest, AnalysisResponse, check_http_url
from c2_analyzer.schemas.ingest import RejectedUrl, ScanEvent
from c2_analyzer.store.repository import NewJob, ResultsStore, iso
from c2_analyzer.utils.defang import defang_url
from c2_analyzer.utils.pii import mask_url
from c2_analyzer.utils.url import extract_domain

log = logging.getLogger(__name__)

# AnalysisRequest.source (9B-1 contract) -> scan_jobs.source
REQUEST_SOURCE_TO_JOB = {"user": "user", "api": "api", "threatradar": "threatradar_push"}
# scan_jobs.source -> AnalysisRequest.source used by the worker
JOB_SOURCE_TO_REQUEST = {
    "user": "user",
    "api": "api",
    "threatradar_push": "threatradar",
    "threatradar_pull": "threatradar",
}

PASTED_HTML = "(pasted HTML)"


@dataclass
class EnqueueResult:
    accepted: int = 0
    duplicates: int = 0
    already_known: int = 0  # pull only: URL seen before (any time) -> not queued again
    rejected: list[RejectedUrl] = field(default_factory=list)
    job_ids: list[int] = field(default_factory=list)


@dataclass(frozen=True)
class UrlItem:
    url: str
    source_ref: dict = field(default_factory=dict)


def summarize(response: AnalysisResponse) -> dict:
    """The indexed columns of scan_results, from a full response."""
    url = response.input.final_url or response.input.submitted_url
    return {
        "verdict": response.verdict,
        "threat_class": response.threat_class,
        "risk_score": response.risk_score,
        "status": response.status,
        "page_language": response.page_language,
        "final_url_domain": extract_domain(url) if url else None,
        "top_findings": [
            {"id": f.id, "severity": f.severity, "title": f.title} for f in response.findings[:3]
        ],
    }


def review_reason(summary: dict, min_risk: int) -> str | None:
    """Why a result needs a person (None = it does not).

    Malicious always; Suspicious when the risk score reaches ``min_risk``.
    """
    if summary.get("verdict") == "Malicious":
        return "verdict Malicious"
    risk = summary.get("risk_score")
    if summary.get("verdict") == "Suspicious" and risk is not None and risk >= min_risk:
        return f"Suspicious with risk {risk} >= {min_risk}"
    return None


def display_url(url: str | None) -> str:
    """How a URL is shown in any read API: PII in the query masked, then defanged."""
    if not url:
        return PASTED_HTML
    return defang_url(mask_url(url) or url) or PASTED_HTML


class IngestService:
    """Queue + results bookkeeping shared by the API, the worker and the scripts."""

    def __init__(
        self,
        store: ResultsStore,
        bus: EventBus | None = None,
        config: IngestConfig | None = None,
        allow_list: tuple[str, ...] | None = None,
    ) -> None:
        self.store = store
        self.bus = bus or EventBus()
        self.config = config or ingest_config()
        self._allow_list = allow_list
        self._lock = threading.Lock()  # dedupe check + insert must not interleave
        self.on_enqueued = None  # set by the worker: wake it up when work arrives

    @property
    def allow_list(self) -> tuple[str, ...]:
        if self._allow_list is None:
            self._allow_list = load_threatradar_rules().allow_list
        return self._allow_list

    # ---- queue -----------------------------------------------------------------------

    def enqueue(
        self,
        items: list[UrlItem],
        source: str,
        *,
        demo: bool = False,
        skip_known: bool = False,
    ) -> EnqueueResult:
        """Validate, dedupe and queue URLs (one transaction per batch).

        ``skip_known`` (the daily pull): a URL that was EVER queued is ignored, so the pull
        never re-analyses the whole ThreatRadar history every day.
        """
        result = EnqueueResult()
        since = iso(self.store.clock() - timedelta(hours=self.config.dedupe_ttl_hours))
        with self._lock:
            valid: list[tuple[int, str, str, dict]] = []
            for index, item in enumerate(items):
                reason, url = self._check(item.url)
                if reason:
                    shown = (display_url(item.url) if item.url else "")[:200]
                    result.rejected.append(RejectedUrl(index=index, url=shown, reason=reason))
                    continue
                valid.append((index, url, normalize_url(url), item.source_ref))
            known = self.store.known_urls([key for *_, key, _ in valid]) if skip_known else set()

            new_jobs: list[tuple[int, NewJob]] = []
            duplicates: list[tuple[int, NewJob, int | str]] = []  # target: job id or key
            first_in_batch: dict[str, int] = {}
            room = self.config.max_queue_depth - self.store.queue_depth()
            for index, url, key, ref in valid:
                if key in known:
                    result.already_known += 1
                    continue
                job = NewJob(url=url, normalized_url=key, source=source, source_ref=ref, demo=demo)
                if key in first_in_batch:
                    duplicates.append((index, job, key))
                    continue
                earlier = None if demo else self.store.reusable_job(key, since)
                if earlier is not None:
                    duplicates.append((index, job, earlier))
                    continue
                if len(new_jobs) >= room:
                    result.rejected.append(
                        RejectedUrl(index=index, url=display_url(url)[:200], reason="queue full")
                    )
                    continue
                first_in_batch[key] = len(new_jobs)
                new_jobs.append((index, job))

            ids_by_index: dict[int, int] = {}
            new_ids = self.store.create_jobs([job for _, job in new_jobs])
            for (index, _), job_id in zip(new_jobs, new_ids, strict=True):
                ids_by_index[index] = job_id
            dup_rows = []
            for index, job, target in duplicates:
                target_id = new_ids[first_in_batch[target]] if isinstance(target, str) else target
                dup_rows.append(
                    (index, replace(job, status="skipped_duplicate", duplicate_of=target_id))
                )
            for (index, _), job_id in zip(
                dup_rows, self.store.create_jobs([job for _, job in dup_rows]), strict=True
            ):
                ids_by_index[index] = job_id

        result.accepted = len(new_jobs)
        result.duplicates = len(dup_rows)
        result.job_ids = [ids_by_index[index] for index in sorted(ids_by_index)]
        if result.accepted and self.on_enqueued is not None:
            self.on_enqueued()
        return result

    def url_problem(self, url: str) -> str | None:
        """Why this URL would be rejected (None = it would be queued)."""
        return self._check(url)[0]

    def _check(self, url: str) -> tuple[str | None, str]:
        """(rejection reason or None, cleaned URL)."""
        try:
            cleaned = check_http_url(url)
        except ValueError as error:
            return str(error), url
        if cleaned is None:
            return "empty url", url
        if self.config.skip_allow_listed and is_allow_listed(cleaned, self.allow_list):
            return "allow-listed", cleaned
        return None, cleaned

    # ---- results ---------------------------------------------------------------------

    def record_job_result(self, job_id: int, response: AnalysisResponse, source: str) -> None:
        """A queued job finished: store it, maybe queue it for review, tell the live feed."""
        summary = summarize(response)
        finished = self.store.complete(job_id, response.model_dump(mode="json"), summary)
        url = (self.store.job(job_id) or {}).get("url")
        self._after_result(job_id, url, summary, source, finished)

    def record_finished(
        self,
        url: str | None,
        response: AnalysisResponse,
        source: str,
        *,
        source_ref: dict | None = None,
        demo: bool = False,
        mode: str = "url",
    ) -> int:
        """Store an analysis that already happened (a user's /analyze call, a demo page)."""
        summary = summarize(response)
        key = normalize_url(url) if (url and mode == "url") else None
        job = NewJob(
            url=url or PASTED_HTML,
            normalized_url=key,
            source=source,
            source_ref=source_ref or {},
            demo=demo,
        )
        job_id, finished = self.store.insert_finished(
            job, response.model_dump(mode="json"), summary
        )
        self._after_result(job_id, url, summary, source, finished)
        return job_id

    def record_user_check(self, request: AnalysisRequest, response: AnalysisResponse) -> None:
        """Hook for ``POST /api/v1/analyze``: history must never break the analysis."""
        try:
            self.record_finished(
                request.url,
                response,
                REQUEST_SOURCE_TO_JOB.get(request.source, "api"),
                source_ref={"request_id": request.request_id} if request.request_id else {},
                mode=request.mode,
            )
        except Exception:  # noqa: BLE001 - logged; the caller still gets its answer
            log.exception("could not store the /analyze result")

    def _after_result(
        self, job_id: int, url: str | None, summary: dict, source: str, finished: str
    ) -> None:
        reason = review_reason(summary, self.config.suspicious_min_risk)
        if reason:
            self.store.add_review(job_id, reason)
        event = ScanEvent(
            id=job_id,
            url=display_url(url),
            verdict=summary["verdict"],
            threat_class=summary["threat_class"],
            risk_score=summary["risk_score"],
            source=source,
            created_at=finished,
        )
        self.bus.publish(event.model_dump())
