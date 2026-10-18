"""Contracts of the ThreatRadar ingest API and the read APIs for the team frontend.

Part 9: Batch B-2 - automatic ThreatRadar ingestion.

- ``POST /api/v1/ingest`` (ThreatRadar -> C2): ``IngestRequest`` -> 202 ``IngestResponse``.
  A bad URL never fails the whole batch: it is listed in ``rejected`` with the reason.
- Read APIs (C2 -> browser): every URL / domain is DEFANGED (``hxxps://x[.]com``) and
  no response ever contains page HTML (only the stored AnalysisResponse, which has none).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

MAX_INGEST_URLS = 500  # also configs/ingest.yaml ingest.max_urls_per_call (may be lower)

JobSource = Literal["user", "threatradar_push", "threatradar_pull", "api"]


class SourceRef(BaseModel):
    """Where ThreatRadar saw the URL (all optional, stored as given, shown to reviewers)."""

    model_config = ConfigDict(extra="ignore")  # newer ThreatRadar fields must not break ingest

    channel: str | None = Field(default=None, max_length=200)
    message_id: int | str | None = Field(default=None)
    subreddit: str | None = Field(default=None, max_length=200)
    post_id: str | None = Field(default=None, max_length=100)
    reasons: list[str] | None = Field(default=None, max_length=20)

    def compact(self) -> dict[str, Any]:
        data = self.model_dump(exclude_none=True)
        if isinstance(data.get("message_id"), str):
            data["message_id"] = data["message_id"][:64]
        if data.get("reasons"):
            data["reasons"] = [str(reason)[:200] for reason in data["reasons"]]
        return data


class IngestItem(BaseModel):
    url: str = Field(max_length=8192, description="http(s) URL, <= 2,048 characters")
    source_ref: SourceRef | None = None


class IngestRequest(BaseModel):
    """Body of ``POST /api/v1/ingest``."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "source": "threatradar_push",
                    "urls": [
                        {
                            "url": "https://paypa1-secure-login.com/verify",
                            "source_ref": {"channel": "lk_deals", "message_id": 4521},
                        },
                        {
                            "url": "https://usdt-double.xyz/",
                            "source_ref": {"subreddit": "CryptoScams", "post_id": "1abcde"},
                        },
                    ],
                }
            ]
        },
    )

    urls: list[IngestItem] = Field(min_length=1, max_length=MAX_INGEST_URLS)
    source: Literal["threatradar_push"] = "threatradar_push"


class RejectedUrl(BaseModel):
    index: int  # position in the request's urls list
    url: str  # defanged, cut to 200 characters
    reason: str


class IngestResponse(BaseModel):
    """202: the URLs are queued; results appear in /api/v1/scans and the live feed."""

    accepted: int
    duplicates: int  # analyzed within the TTL / already queued -> result reused
    rejected: list[RejectedUrl] = Field(default_factory=list)
    job_ids: list[int] = Field(default_factory=list)  # accepted + duplicate jobs, input order
    queue_depth: int = 0


class TopFinding(BaseModel):
    id: str
    severity: str
    title: str


class ScanSummary(BaseModel):
    """One row of ``GET /api/v1/scans`` (and the live feed event)."""

    id: int
    url: str  # defanged, PII-masked
    final_domain: str | None = None  # defanged
    verdict: str | None = None
    threat_class: str | None = None
    risk_score: int | None = None
    status: str  # ok | inconclusive | unreachable | error
    language: str | None = None
    source: JobSource
    demo: bool = False
    created_at: str


class ScanList(BaseModel):
    items: list[ScanSummary]
    next_cursor: str | None = None  # pass as ?cursor= for the next (older) page


class ScanEvent(BaseModel):
    """One Server-Sent Event of ``GET /api/v1/feed/stream`` (``event: scan``)."""

    id: int
    url: str
    verdict: str | None = None
    threat_class: str | None = None
    risk_score: int | None = None
    source: JobSource
    created_at: str


class WorkerStatus(BaseModel):
    enabled: bool
    running: bool
    state: str  # stopped | idle | busy | waiting_for_models | disabled
    concurrency: int
    jobs_per_second: float
    in_flight: int = 0
    processed: int = 0
    retried: int = 0
    failed: int = 0
    last_finished_at: str | None = None
    last_error: str | None = None


class CountItem(BaseModel):
    key: str
    count: int


class SeriesPoint(BaseModel):
    t: str  # bucket start (UTC, ISO)
    total: int
    flagged: int  # Suspicious + Malicious


class StatsOverview(BaseModel):
    """``GET /api/v1/stats/overview``."""

    window: str
    since: str
    generated_at: str
    total: int
    duplicates_skipped: int
    by_verdict: dict[str, int]
    by_status: dict[str, int]
    by_threat_class: dict[str, int]
    by_source: dict[str, int]
    by_language: dict[str, int]
    top_domains: list[CountItem]  # flagged scans, registrable domain (defanged)
    top_brands: list[CountItem]  # brand imitated by flagged scans
    series_bucket: Literal["hour", "day"]
    series: list[SeriesPoint]
    queue: dict[str, int]  # job counts by status (all time)
    review: dict[str, int]  # review queue by state
    worker: WorkerStatus
