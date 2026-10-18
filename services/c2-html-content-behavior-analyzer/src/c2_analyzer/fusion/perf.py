"""Latency + scalability of /api/v1/analyze on this machine (Part 9 evaluation; NFR1, NFR5).

Why it is measured in two pieces: url mode cannot be pointed at a local static file server
(the SSRF guard refuses localhost / private IPs - by design), and the dataset pages are
live scam sites we must not re-fetch for a benchmark. So:

(a) END-TO-END LATENCY (NFR1, target ≤ 5 s): N public BENIGN URLs of the frozen dataset
    (distinct registrable domains, seeded sample) are fetched with the API's own
    ``LiveFetcher`` (static mode, same limits / DNS checks as /analyze); the fetched HTML is
    then analysed in-process in html mode with the final URL. End-to-end per URL = fetch +
    analysis of THAT page, with and without XLM-R. Network time depends on the link and
    the site, so it is reported separately.
(b) CONCURRENCY (NFR5, proposal "50 URLs/s"): a real uvicorn server in a SUBPROCESS
    (production app, models warm, ingest worker off, a throw-away results DB, the per-client
    rate limit lifted) receives html-mode requests (the 68 test pages, cycled) from
    1 / 5 / 10 / 20 concurrent clients. Throughput = completed requests / wall time; p50 /
    p95 latency; server CPU (% of ALL cores) and peak RSS sampled with psutil.
    html mode = no network, so this is the analysis capacity of one process.

One API process is one Python interpreter: the pipeline is mostly pure Python (GIL), so
extra threads add little; capacity grows by running more processes / machines behind a
load balancer (see the report).
"""

from __future__ import annotations

import os
import random
import statistics
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import numpy as np

from c2_analyzer.config import project_root, resolve_path
from c2_analyzer.utils.url import registrable_domain

TARGET_SECONDS = 5.0
PROPOSAL_RATE = 50.0  # URLs / s


def _pct(values: list[float], q: float) -> float | None:
    return round(float(np.percentile(values, q)), 1) if values else None


def latency_summary(values_ms: list[float]) -> dict:
    return {
        "n": len(values_ms),
        "p50": _pct(values_ms, 50),
        "p95": _pct(values_ms, 95),
        "mean": round(statistics.fmean(values_ms), 1) if values_ms else None,
        "max": round(max(values_ms), 1) if values_ms else None,
        "within_target": sum(v <= TARGET_SECONDS * 1000 for v in values_ms),
    }


# ---- (a) fetch + analysis ----------------------------------------------------------------


def benign_urls(version: str, n: int = 20, seed: int = 42) -> list[tuple[str, str]]:
    """(sample_id, source_url) of ``n`` benign manifest pages with distinct domains."""
    import pandas as pd

    root = resolve_path(Path("data/metadata"))
    ids = set(pd.read_csv(root / "manifests" / f"dataset_{version}.csv", dtype=str).sample_id)
    meta = pd.read_csv(root / "metadata.csv", dtype=str).fillna("")
    meta = meta[meta.sample_id.isin(ids) & (meta.label == "benign") & (meta.source_url != "")]
    rows = sorted(zip(meta.sample_id, meta.source_url, strict=True))
    random.Random(seed).shuffle(rows)
    seen, out = set(), []
    for sample_id, url in rows:
        domain = registrable_domain(url) or url
        if domain not in seen:
            seen.add(domain)
            out.append((sample_id, url))
        if len(out) == n:
            break
    return out


def fetch_pages(urls: list[tuple[str, str]], log=print) -> list[dict]:
    from c2_analyzer.fusion.live_fetch import LiveFetcher

    fetcher = LiveFetcher()
    pages = []
    try:
        for sample_id, url in urls:
            tick = time.perf_counter()
            outcome = fetcher.fetch(url)
            wall = (time.perf_counter() - tick) * 1000
            pages.append(
                {
                    "sample_id": sample_id,
                    "status": outcome.status,
                    "reason": outcome.reason,
                    "fetch_ms": round(wall, 1),
                    "bytes": len(outcome.html.encode("utf-8")) if outcome.html else 0,
                    "html": outcome.html,
                    "final_url": outcome.final_url or url,
                }
            )
            log(f"  fetch {sample_id}: {outcome.status} {wall:.0f} ms")
    finally:
        fetcher.close()
    return pages


def analyse_fetched(version: str, pages: list[dict], xlmr: bool) -> dict:
    from c2_analyzer.fusion.orchestrator import Orchestrator, ServingModels
    from c2_analyzer.schemas.analysis import AnalysisRequest

    tick = time.perf_counter()
    orchestrator = Orchestrator(ServingModels.load(version, xlmr_enabled=xlmr))
    load_s = time.perf_counter() - tick
    ok = [p for p in pages if p["html"]]
    if ok:  # warm-up, not timed
        orchestrator.analyze(AnalysisRequest(html=ok[0]["html"], url=ok[0]["final_url"]))
    analysis, total, statuses = [], [], {}
    for page in ok:
        tick = time.perf_counter()
        result = orchestrator.analyze(AnalysisRequest(html=page["html"], url=page["final_url"]))
        ms = (time.perf_counter() - tick) * 1000
        analysis.append(ms)
        total.append(ms + page["fetch_ms"])
        statuses[result.status] = statuses.get(result.status, 0) + 1
    return {
        "xlmr": xlmr,
        "load_seconds": round(load_s, 1),
        "analysis_ms": latency_summary(analysis),
        "end_to_end_ms": latency_summary(total),
        "statuses": statuses,
    }


# ---- (b) concurrency ---------------------------------------------------------------------


def serve(port: int) -> None:
    """Entry point of the benchmark server subprocess (env set by ``start_server``)."""
    import uvicorn

    from c2_analyzer.api.dependencies import get_rate_limiter
    from c2_analyzer.api.guards import RateLimiter
    from c2_analyzer.api.main import create_app

    app = create_app("production", warm_up=True)
    unlimited = RateLimiter(10**9, 1)
    app.dependency_overrides[get_rate_limiter] = lambda: unlimited
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


def start_server(port: int, xlmr: bool, db_path: Path, timeout: float = 180) -> subprocess.Popen:
    import httpx

    env = {
        **os.environ,
        "XLMR_ENABLED": "true" if xlmr else "false",
        "INGEST_WORKER_ENABLED": "false",
        "RESULTS_DB": str(db_path),
        "APP_ENV": "production",
    }
    code = f"from c2_analyzer.fusion.perf import serve; serve({port})"
    proc = subprocess.Popen([sys.executable, "-c", code], cwd=project_root(), env=env)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"benchmark server exited with {proc.returncode}")
        try:
            if httpx.get(f"http://127.0.0.1:{port}/ready", timeout=2).status_code == 200:
                return proc
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    proc.kill()
    raise TimeoutError("benchmark server not ready")


def _tree(root) -> list:
    """The process and its children (a venv python.exe on Windows is a launcher that
    starts the real interpreter as a child)."""
    try:
        return [root, *root.children(recursive=True)]
    except Exception:  # noqa: BLE001 - process ended
        return [root]


def tree_rss(pid: int) -> int:
    import psutil

    total = 0
    for p in _tree(psutil.Process(pid)):
        try:
            total += p.memory_info().rss
        except Exception:  # noqa: BLE001
            pass
    return total


class _Sampler(threading.Thread):
    """CPU (% of all logical cores) and RSS of the server process TREE."""

    def __init__(self, pid: int, interval: float = 0.25) -> None:
        super().__init__(daemon=True)
        import psutil

        self.root = psutil.Process(pid)
        self.interval = interval
        self.cpu: list[float] = []
        self.rss: list[int] = []
        self._known: dict[int, object] = {}
        self._stop_event = threading.Event()

    def _sample(self) -> tuple[float, int]:
        cpu, rss = 0.0, 0
        for p in _tree(self.root):
            proc = self._known.setdefault(p.pid, p)
            try:
                cpu += proc.cpu_percent(None)
                rss += proc.memory_info().rss
            except Exception:  # noqa: BLE001 - child ended
                pass
        return cpu / (os.cpu_count() or 1), rss

    def run(self) -> None:
        self._sample()  # primes cpu_percent
        while not self._stop_event.wait(self.interval):
            cpu, rss = self._sample()
            self.cpu.append(cpu)
            self.rss.append(rss)

    def stop(self) -> dict:
        self._stop_event.set()
        self.join(2)
        return {
            "cpu_percent_all_cores_mean": (
                round(statistics.fmean(self.cpu), 1) if self.cpu else None
            ),
            "cpu_percent_all_cores_max": round(max(self.cpu), 1) if self.cpu else None,
            "rss_mb_peak": round(max(self.rss) / 2**20) if self.rss else None,
        }


def load_level(port: int, bodies: list[bytes], clients: int, requests: int, pid: int) -> dict:
    import httpx

    url = f"http://127.0.0.1:{port}/api/v1/analyze"
    latencies: list[float] = []
    codes: dict[int, int] = {}
    lock = threading.Lock()
    counter = iter(range(requests))

    def worker() -> None:
        with httpx.Client(timeout=120) as client:
            while True:
                with lock:
                    i = next(counter, None)
                if i is None:
                    return
                tick = time.perf_counter()
                r = client.post(
                    url,
                    content=bodies[i % len(bodies)],
                    headers={"Content-Type": "application/json"},
                )
                ms = (time.perf_counter() - tick) * 1000
                with lock:
                    latencies.append(ms)
                    codes[r.status_code] = codes.get(r.status_code, 0) + 1

    sampler = _Sampler(pid)
    sampler.start()
    tick = time.perf_counter()
    with ThreadPoolExecutor(clients) as pool:
        for _ in range(clients):
            pool.submit(worker)
    wall = time.perf_counter() - tick
    usage = sampler.stop()
    return {
        "clients": clients,
        "requests": requests,
        "wall_seconds": round(wall, 1),
        "throughput_per_s": round(requests / wall, 2),
        "latency_ms": latency_summary(latencies),
        "status_codes": codes,
        **usage,
    }


def test_bodies(version: str) -> list[bytes]:
    import json

    from c2_analyzer.api.dev_data import DevDataset
    from c2_analyzer.fusion.data import FusionData

    dataset = DevDataset.from_settings()
    bodies = []
    for sample_id in FusionData.load(version).ids("test"):
        html, url = dataset.raw_html(version, sample_id)
        bodies.append(json.dumps({"html": html, "url": url, "source": "api"}).encode("utf-8"))
    return bodies


def concurrency(
    version: str, xlmr: bool, levels: list[int], db_dir: Path, port: int, log=print
) -> dict:
    bodies = test_bodies(version)
    db_path = db_dir / f"bench_{'xlmr' if xlmr else 'noxlmr'}.db"
    tick = time.perf_counter()
    proc = start_server(port, xlmr, db_path)
    ready_s = time.perf_counter() - tick
    idle_rss = tree_rss(proc.pid)
    try:
        load_level(port, bodies, 2, 6, proc.pid)  # warm-up
        rows = []
        for clients in levels:
            requests = max(len(bodies), 4 * clients)
            row = load_level(port, bodies, clients, requests, proc.pid)
            log(
                f"  xlmr={xlmr} clients={clients}: {row['throughput_per_s']} req/s, "
                f"p95 {row['latency_ms']['p95']} ms"
            )
            rows.append(row)
    finally:
        proc.terminate()
        try:
            proc.wait(15)
        except subprocess.TimeoutExpired:
            proc.kill()
    return {
        "xlmr": xlmr,
        "ready_seconds": round(ready_s, 1),
        "idle_rss_mb": round(idle_rss / 2**20),
        "levels": rows,
    }


# ---- report ------------------------------------------------------------------------------


def machine() -> dict:
    import platform

    import psutil

    return {
        "cpu": platform.processor() or platform.machine(),
        "logical_cpus": os.cpu_count(),
        "physical_cpus": psutil.cpu_count(logical=False),
        "ram_gb": round(psutil.virtual_memory().total / 2**30, 1),
        "os": platform.platform(),
        "python": platform.python_version(),
    }


def _ms(v) -> str:
    return "—" if v is None else f"{v:,.0f} ms"


def _n_bad(row: dict) -> int:
    return sum(v for k, v in row["status_codes"].items() if str(k) != "200")


def _errors(row: dict) -> str:
    bad = {k: v for k, v in row["status_codes"].items() if str(k) != "200"}
    return ", ".join(f"{v}× {k}" for k, v in sorted(bad.items())) or "0"


def markdown(result: dict) -> str:
    m = result["machine"]
    fetch = result["fetch"]
    lines = [
        f"# Latency and scalability - {result['version']}",
        "",
        f"Machine: {m['cpu']}, {m['physical_cpus']} cores / {m['logical_cpus']} threads, "
        f"{m['ram_gb']} GB RAM, {m['os']}, Python {m['python']}. CPU only, warm models. "
        f"Measured {result['measured_at']}.",
        "",
        "## (a) End-to-end latency (NFR1: ≤ 5 s per URL)",
        "",
        f"{fetch['n_urls']} public benign dataset URLs (distinct domains, seed 42) fetched with "
        "the API's own LiveFetcher (static mode, DNS / SSRF checks, 10 s timeout), then the same "
        "HTML analysed in html mode. End-to-end = fetch + analysis of that page. url mode "
        "cannot target a local file server (private IPs are refused by design) and the scam "
        "pages are not re-fetched.",
        "",
        f"Fetch: {fetch['ok']} ok, statuses {fetch['statuses']}; fetch time (ok pages) "
        f"p50 {_ms(fetch['fetch_ms']['p50'])}, p95 {_ms(fetch['fetch_ms']['p95'])}, "
        f"max {_ms(fetch['fetch_ms']['max'])}; median page {fetch['median_kb']} KB.",
        "",
        "| config | model load | analysis p50 | analysis p95 | end-to-end p50 | end-to-end p95 "
        "| end-to-end max | ≤ 5 s |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for run in result["end_to_end"]:
        a, e = run["analysis_ms"], run["end_to_end_ms"]
        name = "4 arms (with XLM-R)" if run["xlmr"] else "3 arms (no XLM-R)"
        lines.append(
            f"| {name} | {run['load_seconds']} s | {_ms(a['p50'])} | {_ms(a['p95'])} | "
            f"{_ms(e['p50'])} | {_ms(e['p95'])} | {_ms(e['max'])} | "
            f"{e['within_target']}/{e['n']} |"
        )
    lines += [
        "",
        "## (b) Concurrency (NFR5) - one API process, html mode",
        "",
        "Real uvicorn server in a subprocess (production app, models warm, ingest worker off, "
        "throw-away results DB, per-client rate limit lifted); clients send the 68 test pages "
        "cycled. CPU = server process, % of ALL logical cores. 504 = the request waited "
        "past the 30 s time budget (configs/analyze.yaml) - the queue, not a crash.",
        "",
        "| config | clients | requests | non-200 | throughput | p50 | p95 | CPU mean / max "
        "| peak RSS |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for run in result["concurrency"]:
        name = "with XLM-R" if run["xlmr"] else "no XLM-R"
        for row in run["levels"]:
            lat = row["latency_ms"]
            lines.append(
                f"| {name} | {row['clients']} | {row['requests']} | {_errors(row)} | "
                f"{row['throughput_per_s']} req/s | {_ms(lat['p50'])} | {_ms(lat['p95'])} | "
                f"{row['cpu_percent_all_cores_mean']} / {row['cpu_percent_all_cores_max']} % | "
                f"{row['rss_mb_peak']} MB |"
            )
    lines += [""]
    for run in result["concurrency"]:
        name = "with XLM-R" if run["xlmr"] else "no XLM-R"
        lines.append(
            f"- {name}: server ready in {run['ready_seconds']} s, idle RSS "
            f"{run['idle_rss_mb']} MB."
        )
    lines += ["", "## Reading", ""] + [f"- {x}" for x in result["reading"]]
    return "\n".join(lines) + "\n"


def reading(result: dict) -> list[str]:
    """Plain-language conclusions computed from the numbers (no hand-typed figures)."""
    out = []
    for run in result["end_to_end"]:
        e = run["end_to_end_ms"]
        name = "with XLM-R" if run["xlmr"] else "without XLM-R"
        verdict = "MET" if e["p95"] is not None and e["p95"] <= TARGET_SECONDS * 1000 else "NOT met"
        out.append(
            f"NFR1 {name}: end-to-end p95 {_ms(e['p95'])} vs 5 s → {verdict} "
            f"({e['within_target']}/{e['n']} URLs ≤ 5 s; network time dominates the tail)."
        )
    for run in result["concurrency"]:
        best = max(run["levels"], key=lambda r: r["throughput_per_s"])
        name = "with XLM-R" if run["xlmr"] else "without XLM-R"
        need = (
            int(np.ceil(PROPOSAL_RATE / best["throughput_per_s"]))
            if best["throughput_per_s"]
            else None
        )
        out.append(
            f"NFR5 {name}: peak {best['throughput_per_s']} req/s at {best['clients']} clients "
            f"(p95 {_ms(best['latency_ms']['p95'])}); more clients only queue (throughput flat, "
            f"latency grows, {sum(_n_bad(r) for r in run['levels'])} request(s) hit the 30 s "
            "budget at the highest level). 50 URLs/s is a SERVER-scale target: it "
            f"would need ≈ {need} such processes (e.g. one per core on several machines behind a "
            "load balancer) - NOT met on one laptop process."
        )
    out.append(
        "Horizontal scaling needs: the in-process pieces moved out - SQLite results store → "
        "PostgreSQL, in-process queue / worker → a shared queue (Redis / RabbitMQ) with "
        "separate worker processes, the per-process result cache and rate limiter → Redis, "
        "the SSE event bus → pub/sub; each process loads its own models (~"
        + str(max((r["idle_rss_mb"] for r in result["concurrency"]), default=0))
        + " MB RSS for the largest configuration measured), so RAM per box limits processes "
        "per box. url mode adds network "
        "time per request, which is I/O-bound and overlaps well across threads."
    )
    return out
