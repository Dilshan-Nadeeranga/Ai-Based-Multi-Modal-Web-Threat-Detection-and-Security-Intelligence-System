"""Demo data for the dashboard: real analyses of the v0.3 TEST pages, stored as if
ThreatRadar had pushed them.

Part 9: Batch B-2 - automatic ThreatRadar ingestion.

Why: the frontend needs realistic history to be built against, but a local demo may not
fetch anything - the SSRF guard (rightly) refuses a local test server, and fetching live
scam sites from a laptop is unsafe. So each test page's SAVED HTML is analysed by the
real 9B-1 engine in html mode (no request is sent) and recorded with
``source=threatradar_push``, ``demo=1`` and ``source_ref.demo = true``. Their times are
spread over the last ``spread_hours`` so the per-hour chart has a shape.

Demo rows are clearly separable: they never count as "already analysed" for dedupe or the
pull, never get exported from the review queue, and ``--clear`` deletes them all.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from datetime import timedelta

from c2_analyzer.ingest.service import IngestService
from c2_analyzer.schemas.analysis import AnalysisRequest
from c2_analyzer.store.repository import ResultsStore, utc_now


def run_demo(
    store_path,
    version: str,
    count: int | None = None,
    xlmr: bool = True,
    spread_hours: float = 24.0,
    log: Callable[[str], None] = print,
) -> Counter:
    """Analyse up to ``count`` test pages and store them as demo scans; returns verdicts."""
    from c2_analyzer.api.dev_data import DevDataset
    from c2_analyzer.fusion.data import FusionData
    from c2_analyzer.fusion.orchestrator import Orchestrator, ServingModels

    models = ServingModels.load(version, xlmr_enabled=xlmr)
    if models.problems:
        raise RuntimeError("; ".join(models.problems))
    orchestrator = Orchestrator(models)
    test_ids = FusionData.load(version, models.fusion_config).ids("test")
    ids = test_ids[:count] if count else test_ids
    dataset = DevDataset.from_settings()

    started = utc_now()
    moment = {"value": started}
    store = ResultsStore(store_path, clock=lambda: moment["value"])
    service = IngestService(store)
    verdicts: Counter = Counter()
    step = timedelta(hours=spread_hours) / max(len(ids), 1)
    for index, sample_id in enumerate(ids):
        html, url = dataset.raw_html(version, sample_id)
        url = url or f"https://{sample_id.replace('_', '-')}.demo.invalid/"
        response = orchestrator.analyze(
            AnalysisRequest(html=html, url=url, source="threatradar", request_id=sample_id)
        )
        # oldest first, so ids grow with time like real traffic
        moment["value"] = started - step * (len(ids) - 1 - index)
        service.record_finished(
            url,
            response,
            "threatradar_push",
            source_ref={"demo": True, "sample_id": sample_id, "channel": "demo"},
            demo=True,
        )
        verdicts[response.verdict or response.status] += 1
        log(f"  {index + 1:>3}/{len(ids)} {sample_id:<28} {response.verdict or response.status}")
    store.close()
    return verdicts


def clear_demo(store_path) -> int:
    store = ResultsStore(store_path)
    try:
        return store.delete_demo()
    finally:
        store.close()
