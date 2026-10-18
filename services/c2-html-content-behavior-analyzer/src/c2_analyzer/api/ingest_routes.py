"""ThreatRadar ingest API + read APIs for the team frontend.

Part 9: Batch B-2 - automatic ThreatRadar ingestion.

- ``POST /api/v1/ingest`` (server to server): ThreatRadar pushes new URLs; 202 at once,
  the background worker analyses them. Protected by a shared secret in the
  ``X-C2-Ingest-Key`` header (INGEST_API_KEY in .env), compared in constant time
  (``hmac.compare_digest``) so response timing does not leak how much of a guessed key
  was right. No key configured -> 503 (ingest switched off), wrong / missing key -> 401.
- Read APIs (browser, CORS from CORS_ORIGINS): scans list + detail, overview statistics,
  live feed (Server-Sent Events), research summary. Every URL / domain is DEFANGED and no
  response contains page HTML - the store only ever holds AnalysisResponse JSON.
"""

from __future__ import annotations

import hmac
from datetime import UTC, date, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse

from c2_analyzer.api.dependencies import (
    get_event_bus,
    get_ingest_service,
    get_worker,
    settings_dependency,
)
from c2_analyzer.api.routes import require_json
from c2_analyzer.config import Settings, get_labels
from c2_analyzer.fusion.live_fetch import analyze_config
from c2_analyzer.ingest.events import EventBus, sse_stream
from c2_analyzer.ingest.service import IngestService, UrlItem, display_url
from c2_analyzer.ingest.stats import overview, research_summary
from c2_analyzer.ingest.worker import IngestWorker
from c2_analyzer.schemas.analysis import AnalysisResponse
from c2_analyzer.schemas.ingest import (
    IngestRequest,
    IngestResponse,
    JobSource,
    ScanList,
    ScanSummary,
    StatsOverview,
)
from c2_analyzer.store.repository import iso
from c2_analyzer.utils.defang import defang_analysis, defang_host

router = APIRouter()

ServiceDep = Annotated[IngestService, Depends(get_ingest_service)]
SettingsDep = Annotated[Settings, Depends(settings_dependency)]


def require_ingest_key(
    settings: SettingsDep,
    key: Annotated[str | None, Header(alias="X-C2-Ingest-Key")] = None,
) -> None:
    """503 if no INGEST_API_KEY is configured, 401 if the header is missing or wrong."""
    expected = settings.ingest_api_key.get_secret_value()
    if not expected:
        raise HTTPException(status_code=503, detail="ingest disabled (INGEST_API_KEY not set)")
    if not key or not hmac.compare_digest(key.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(status_code=401, detail="missing or invalid X-C2-Ingest-Key")


@router.post(
    "/api/v1/ingest",
    status_code=202,
    response_model=IngestResponse,
    tags=["ingest (Part 9B-2)"],
    summary="ThreatRadar pushes new URLs -> queued for background analysis (202)",
    dependencies=[Depends(require_ingest_key), Depends(require_json)],
    responses={
        401: {"description": "missing or invalid X-C2-Ingest-Key"},
        415: {"description": "body is not application/json"},
        422: {"description": "invalid body (no urls, more than the per-call limit)"},
        503: {"description": "ingest disabled (INGEST_API_KEY not set)"},
    },
)
def ingest(body: IngestRequest, service: ServiceDep) -> IngestResponse:
    """Queue up to 500 URLs. Invalid / allow-listed URLs are listed in ``rejected`` (the
    rest is still accepted); a URL analysed in the last 24 h or already queued counts as a
    duplicate and reuses that result. Results: ``GET /api/v1/scans`` and the live feed."""
    limit = service.config.max_urls_per_call
    if len(body.urls) > limit:
        raise HTTPException(status_code=422, detail=f"at most {limit} urls per call")
    items = [
        UrlItem(url=item.url, source_ref=item.source_ref.compact() if item.source_ref else {})
        for item in body.urls
    ]
    result = service.enqueue(items, body.source)
    return IngestResponse(
        accepted=result.accepted,
        duplicates=result.duplicates,
        rejected=result.rejected,
        job_ids=result.job_ids,
        queue_depth=service.store.queue_depth(),
    )


def _since(value: str | None) -> str | None:
    """?since= as a date (2026-10-17) or an ISO datetime -> stored timestamp format."""
    if not value:
        return None
    try:
        if len(value) == 10:
            moment = datetime.combine(date.fromisoformat(value), datetime.min.time(), UTC)
        else:
            moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
            moment = moment if moment.tzinfo else moment.replace(tzinfo=UTC)
    except ValueError:
        raise HTTPException(
            status_code=422, detail="since must be YYYY-MM-DD or ISO 8601"
        ) from None
    return iso(moment)


@router.get(
    "/api/v1/scans",
    response_model=ScanList,
    tags=["dashboard (Part 9B-2)"],
    summary="Scan history, newest first (defanged URLs, cursor pagination)",
)
def scans(
    service: ServiceDep,
    source: JobSource | None = None,
    verdict: Literal["Legitimate", "Suspicious", "Malicious", "none"] | None = None,
    threat_class: str | None = None,
    since: str | None = Query(default=None, description="YYYY-MM-DD or ISO 8601 (UTC)"),
    q: str | None = Query(default=None, max_length=200, description="text in URL / domain"),
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None, pattern=r"^\d{1,18}$"),
) -> ScanList:
    """Finished scans (``verdict=none`` = no verdict: unreachable / inconclusive)."""
    if threat_class and threat_class not in get_labels():
        raise HTTPException(status_code=422, detail=f"unknown threat_class {threat_class!r}")
    config = service.config
    size = min(limit or config.default_limit, config.max_limit)
    rows = service.store.list_scans(
        source=source,
        verdict=verdict,
        threat_class=threat_class,
        since=_since(since),
        q=q.strip() if q else None,
        limit=size + 1,
        before_id=int(cursor) if cursor else None,
    )
    more = len(rows) > size
    rows = rows[:size]
    items = [
        ScanSummary(
            id=row["id"],
            url=display_url(row["url"]),
            final_domain=defang_host(row["final_url_domain"]),
            verdict=row["verdict"],
            threat_class=row["threat_class"],
            risk_score=row["risk_score"],
            status=row["status"],
            language=row["page_language"],
            source=row["source"],
            demo=bool(row["demo"]),
            created_at=row["created_at"],
        )
        for row in rows
    ]
    return ScanList(items=items, next_cursor=str(rows[-1]["id"]) if more and rows else None)


@router.get(
    "/api/v1/scans/{scan_id}",
    response_model=AnalysisResponse,
    tags=["dashboard (Part 9B-2)"],
    summary="One stored analysis (c2.analysis.v1, URLs / domains defanged)",
    responses={404: {"description": "unknown scan, or no result yet (queued / failed)"}},
)
def scan_detail(scan_id: int, service: ServiceDep) -> Response:
    job = service.store.job(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="unknown scan id")
    result = service.store.result(scan_id)
    if result is None:
        detail = f"no result yet (job {job['status']})"
        if job["status"] == "failed" and job.get("error"):
            detail = f"job failed: {job['error']}"
        raise HTTPException(status_code=404, detail=detail)
    safe = AnalysisResponse.model_validate(defang_analysis(result))
    return Response(safe.model_dump_json(), media_type="application/json")


@router.get(
    "/api/v1/stats/overview",
    response_model=StatsOverview,
    tags=["dashboard (Part 9B-2)"],
    summary="Totals by verdict / class / source / language, top domains / brands, series",
)
def stats_overview(
    service: ServiceDep,
    worker: Annotated[IngestWorker, Depends(get_worker)],
    window: Literal["24h", "7d", "30d"] = "24h",
) -> StatsOverview:
    return overview(service.store, window, worker.status(), top_n=service.config.top_n)


@router.get(
    "/api/v1/feed/stream",
    tags=["dashboard (Part 9B-2)"],
    summary="Live feed: one Server-Sent Event (event: scan) per finished scan",
    response_class=StreamingResponse,
    responses={200: {"content": {"text/event-stream": {}}}},
)
async def feed_stream(
    request: Request,
    bus: Annotated[EventBus, Depends(get_event_bus)],
    service: ServiceDep,
) -> StreamingResponse:
    """Use from the browser with ``new EventSource(".../api/v1/feed/stream")`` and listen
    for ``scan`` events; data = {id, url (defanged), verdict, threat_class, risk_score,
    source, created_at}."""
    stream = sse_stream(bus, request.is_disconnected, service.config.sse_heartbeat_seconds)
    return StreamingResponse(
        stream,
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get(
    "/api/v1/research/summary",
    tags=["dashboard (Part 9B-2)"],
    summary="Read-only research numbers: dataset, ablation + CIs, operating points, models",
)
def research(
    version: str | None = Query(default=None, pattern=r"^v\d+\.\d+$"),
) -> dict:
    """Read from the reports earlier Parts wrote (nothing is recomputed)."""
    return research_summary(version or analyze_config()["serving_version"])
