"""Evaluation reports: Wilson CIs, the real-page behavior benchmark, fairness subgroups,
the latency / scalability summary. Synthetic inputs only - no network, no models."""

from __future__ import annotations

from types import SimpleNamespace

import pandas as pd
import pytest

from c2_analyzer.behavior import benchmark
from c2_analyzer.fusion import fairness, perf
from c2_analyzer.utils.stats import wilson


def test_wilson_known_values_and_edges():
    half = wilson(5, 10)
    assert half.rate == 0.5
    assert half.low == pytest.approx(0.2366, abs=1e-4)
    assert half.high == pytest.approx(0.7634, abs=1e-4)
    zero = wilson(0, 10)
    assert zero.low == 0.0 and zero.high == pytest.approx(0.2775, abs=1e-4)
    assert wilson(10, 10).high == 1.0
    assert wilson(0, 0).rate is None and wilson(0, 0).text() == "n = 0"
    with pytest.raises(ValueError):
        wilson(3, 2)


def _finding(pattern, severity):
    return SimpleNamespace(pattern_id=pattern, severity=severity)


def _rows():
    rows = [
        {
            "sample_id": f"p{i}",
            "pattern": "anti_analysis",
            "expected": "positive",
            "confirmed": "false",
            "reason": "r",
        }
        for i in range(4)
    ]
    rows += [
        {
            "sample_id": f"n{i}",
            "pattern": "anti_analysis",
            "expected": "negative",
            "confirmed": "true",
            "reason": "r",
        }
        for i in range(3)
    ]
    rows.append(
        {
            "sample_id": "k0",
            "pattern": "keylogging",
            "expected": "positive",
            "confirmed": "false",
            "reason": "only one",
        }
    )
    rows.append(
        {
            "sample_id": "gone",
            "pattern": "keylogging",
            "expected": "negative",
            "confirmed": "false",
            "reason": "r",
        }
    )
    return rows


def _loader(sample_id):
    found = {
        "p0": [_finding("anti_analysis", "low")],
        "p1": [_finding("anti_analysis", "medium"), _finding("forced_redirect", "high")],
        "p2": [_finding("anti_analysis", "high")],
        "p3": [_finding("forced_redirect", "high")],  # miss
        "n0": [_finding("anti_analysis", "low")],  # false alarm
        "n1": [],
        "n2": [_finding("credential_access", "low")],
        "k0": [],
    }
    if sample_id == "gone":
        return "no current Part 8 result"
    return SimpleNamespace(findings=found[sample_id])


def test_benchmark_rates_misses_false_alarms_and_measurability():
    cases = benchmark.evaluate_cases(_rows(), "v0", load=_loader)
    summary = benchmark.summarize(cases)
    anti = summary["per_pattern"]["anti_analysis"]
    assert (anti["any"]["tp"], anti["any"]["n_pos"], anti["any"]["fp"]) == (3, 4, 1)
    assert anti["any"]["tpr"]["measurable"] and anti["any"]["fpr"]["measurable"]
    assert anti["high"]["tp"] == 1  # only p2 is high / critical
    key = summary["per_pattern"]["keylogging"]["any"]
    assert key["n_pos"] == 1 and not key["tpr"]["measurable"]
    assert key["n_neg"] == 0  # the missing page is not counted
    assert [m["sample_id"] for m in summary["misses"]] == ["p3", "k0"]
    assert summary["misses"][0]["other_patterns"] == ["forced_redirect"]
    assert [f["sample_id"] for f in summary["false_alarms"]] == ["n0"]
    assert summary["errors"] == [{"sample_id": "gone", "error": "no current Part 8 result"}]
    assert summary["n_confirmed"] == 3
    text = benchmark.render_markdown(summary, cases, "v0", {"p3": "NOTE-P3"})
    assert "PRELIMINARY, UNCONFIRMED, SMALL n" in text
    assert "NOTE-P3" in text and "**keylogging**: 1 real positive" in text
    assert "not measurable" in text


def test_benchmark_candidates_file_is_valid_and_unconfirmed(tmp_path):
    rows = benchmark.load_candidates()
    assert rows and all(r["source"] == "real" for r in rows)
    assert {r["pattern"] for r in rows} <= set(benchmark.PATTERNS)
    bad = tmp_path / "c.csv"
    bad.write_text("sample_id,pattern,expected,reason\nx,keyloging,positive,r\n", "utf-8")
    with pytest.raises(ValueError, match="unknown pattern"):
        benchmark.load_candidates(bad)


@pytest.mark.parametrize(
    ("notes", "url", "group"),
    [
        ("Local cafe SME", "https://cafe.example.com/", "lk_sme"),
        ("Local company", "https://x.com/", "lk_sme"),
        ("", "https://www.shop.lk/", "lk_other"),
        ("", "https://www.news.com.lk/a", "lk_other"),
        ("Central Bank of Sri Lanka", "https://cbsl.gov.example/", "lk_other"),
        ("Popular site", "https://www.wikipedia.org/", "non_lk"),
        ("", "not a url", "non_lk"),
    ],
)
def test_lk_tagging_rule(notes, url, group):
    assert fairness.lk_group(notes, url, "") == group


def test_lk_tagging_uses_the_final_url_too():
    assert fairness.lk_group("", "https://short.example/x", "https://www.daraz.lk/") == "lk_other"


def test_group_rates_counts_ci_fisher_and_higher_flag():
    frame = pd.DataFrame(
        {
            "verdict": ["Suspicious", "Legitimate", "Malicious", "Legitimate"]
            + ["Legitimate"] * 8
            + ["Suspicious"] * 2,
            "group": ["lk"] * 4 + ["ref"] * 10,
        },
        index=[f"s{i}" for i in range(14)],
    )
    rows = {r["group"]: r for r in fairness.group_rates(frame, "group", "ref")}
    lk, ref = rows["lk"], rows["ref"]
    assert (lk["n"], lk["flagged"]["k"], lk["malicious"]["k"]) == (4, 2, 1)
    assert (ref["flagged"]["k"], ref["malicious"]["k"]) == (2, 0)
    assert lk["flagged"]["higher_than_reference"] and lk["malicious"]["higher_than_reference"]
    assert 0 < lk["flagged"]["fisher_p_vs_reference"] <= 1
    assert "fisher_p_vs_reference" not in ref["flagged"]
    assert lk["examples_flagged"] == ["s0", "s2"]


def _perf_result():
    level = {
        "clients": 5,
        "requests": 68,
        "wall_seconds": 20.0,
        "throughput_per_s": 3.4,
        "latency_ms": perf.latency_summary([100.0, 200.0, 6000.0]),
        "status_codes": {200: 68},
        "cpu_percent_all_cores_mean": 20.0,
        "cpu_percent_all_cores_max": 30.0,
        "rss_mb_peak": 900,
    }
    run = {
        "xlmr": True,
        "load_seconds": 7.0,
        "analysis_ms": perf.latency_summary([500.0, 900.0]),
        "end_to_end_ms": perf.latency_summary([1500.0, 2500.0]),
    }
    return {
        "version": "v0",
        "measured_at": "now",
        "machine": perf.machine(),
        "fetch": {
            "n_urls": 2,
            "ok": 2,
            "statuses": {"ok": 2},
            "fetch_ms": perf.latency_summary([1000.0, 1600.0]),
            "median_kb": 50,
        },
        "end_to_end": [run],
        "concurrency": [
            {"xlmr": True, "ready_seconds": 8.0, "idle_rss_mb": 800, "levels": [level]}
        ],
    }


def test_latency_summary_and_reading_are_computed_from_the_numbers():
    s = perf.latency_summary([100.0, 200.0, 6000.0])
    assert s["n"] == 3 and s["within_target"] == 2 and s["max"] == 6000.0
    assert perf.latency_summary([])["p50"] is None
    result = _perf_result()
    result["reading"] = perf.reading(result)
    assert "MET" in result["reading"][0] and "NOT met" not in result["reading"][0]
    assert "15 such processes" in result["reading"][1]  # ceil(50 / 3.4)
    text = perf.markdown(result)
    assert "3.4 req/s" in text and "2/2" in text and "800 MB" in text


def test_migration_skips_steps_another_connection_applied_meanwhile(tmp_path):
    """Two first requests on a NEW results DB (load test): the second must not re-run the
    CREATE TABLE steps the first applied while it waited for the write lock."""
    import sqlite3
    import threading

    from c2_analyzer.store import db

    path = tmp_path / "race.db"
    stale = sqlite3.connect(path, isolation_level=None, check_same_thread=False)

    class StaleFirstRead:
        """Answers the FIRST user_version read with 0 (read before the other migrated)."""

        def __init__(self, conn):
            self.conn, self.first = conn, True

        def execute(self, sql, *args):
            if self.first and sql.strip().upper() == "PRAGMA USER_VERSION":
                self.first = False
                return self.conn.execute("SELECT 0")
            return self.conn.execute(sql, *args)

    db.connect(path).close()  # the other connection migrates fully
    assert db.migrate(StaleFirstRead(stale)) == db.SCHEMA_VERSION
    errors = []

    def open_new(i):
        try:
            db.connect(tmp_path / "parallel.db").close()
        except Exception as error:  # noqa: BLE001
            errors.append(error)

    threads = [threading.Thread(target=open_new, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    stale.close()
