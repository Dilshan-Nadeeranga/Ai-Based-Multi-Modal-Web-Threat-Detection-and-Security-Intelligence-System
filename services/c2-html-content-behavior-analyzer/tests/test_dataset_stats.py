"""Tests for Part 1 Batch D, Task 13: dataset statistics, figures and frozen versions.

Why: the numbers in the progress report and the dataset version named in
every later experiment come from this code, so the view definitions, the
imbalance/readiness logic and the manifest checks are pinned down here.
Synthetic pages only (no network); everything is written under tmp_path.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

from c2_analyzer.config import project_root
from c2_analyzer.dataset.collector import register_file
from c2_analyzer.dataset.manifest import freeze, list_versions, manifests_dir, verify
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dataset.statistics import (
    compute_statistics,
    imbalance,
    peer_summary,
    read_page_facts,
    readiness,
    view_statistics,
)
from c2_analyzer.dataset.stats_report import FIGURE_NAMES, make_figures, write_report
from c2_analyzer.dataset.verifier import relabel_sample
from c2_analyzer.dataset.views import select_view

ROOT = project_root()
PNG_MAGIC = b"\x89PNG"

LOGIN_FORM = "<form action='/p.php'><input type='email'><input type='password'></form>"


def page(number: int, extra: str = "") -> str:
    """A small unique page (unique text -> unique sha256)."""
    return (
        f"<html><head><title>Page {number}</title><script>var n={number};</script></head>"
        f"<body><h1>Welcome {number}</h1><p>{'word ' * (20 * number)}</p>{extra}</body></html>"
    )


def add(store: MetadataStore, html: str, label: str, language: str = "en") -> str:
    number = len(store.df) + 1
    source = store.raw_dir.parent / f"incoming_{number}.html"
    source.write_text(html, encoding="utf-8")
    record, _ = register_file(store, source, label, language, "manual", f"https://s{number}.ex/")
    return record.sample_id


@pytest.fixture
def store(tmp_path: Path) -> MetadataStore:
    """10 samples covering every case a view can filter on.

    benign  b1 (verified), b2, b3 (si)
    phishing p1 (cluster rep), p2 (duplicate of p1), p3 (excluded), p4 (empty flag),
             p5 (redirected_offsite, si), p6 (relabelled -> crypto_scam)
    malware  m1
    """
    store = MetadataStore(tmp_path / "metadata" / "metadata.csv", tmp_path / "raw")
    b1 = add(store, page(1), "benign")
    add(store, page(2), "benign")
    add(store, page(3), "benign", "si")
    p1 = add(store, page(4, LOGIN_FORM), "phishing")
    p2 = add(store, page(5, LOGIN_FORM), "phishing")
    p3 = add(store, page(6), "phishing")
    p4 = add(store, page(7), "phishing")
    p5 = add(store, page(8, LOGIN_FORM), "phishing", "si")
    p6 = add(store, page(9), "phishing")
    add(store, page(10), "malware_delivery")

    store.update(b1, verified=True, verified_by="Tester", verification_date=date.today())
    store.update(p1, cluster_id="cl_000001")
    store.update(p2, cluster_id="cl_000001", is_duplicate_of=p1)
    store.update(p3, quality_flag="parked_domain", excluded=True, exclusion_reason="parked_domain")
    store.update(p4, quality_flag="empty")
    store.update(p5, quality_flag="redirected_offsite")
    store.save()
    relabel_sample(store, p6, "crypto_scam", "Tester")  # saves; file moves to crypto_scam/
    return store


# ---- views -------------------------------------------------------------------------------------


def test_view_filters(store):
    df = store.df
    assert len(select_view(df, "all")) == 10
    usable = select_view(df, "usable")  # minus excluded p3 and empty p4
    assert len(usable) == 8
    assert "c2_phishing_000005" in set(usable["sample_id"])  # redirected_offsite is usable
    clean = select_view(df, "clean")  # minus duplicate p2
    assert len(clean) == 7
    assert "c2_phishing_000002" not in set(clean["sample_id"])
    with pytest.raises(ValueError):
        select_view(df, "everything")


def test_view_statistics(store):
    facts = read_page_facts(store, store.df)
    stats = view_statistics(select_view(store.df, "all"), facts)
    assert stats["per_label"] == {
        "benign": 3,
        "phishing": 5,
        "fake_ecommerce": 0,
        "crypto_scam": 1,
        "malware_delivery": 1,
    }
    assert stats["label_by_language"]["benign"]["si"] == 1
    assert stats["verification"]["benign"] == {
        "verified": 1,
        "unverified": 2,
        "percent_verified": 33.3,
    }
    assert stats["quality_flags"]["parked_domain"] == 1 and stats["quality_flags"]["ok"] == 7
    assert stats["excluded"] == 1 and stats["excluded_by_reason"] == {"parked_domain": 1}
    clusters = stats["clusters"]
    assert clusters["largest"] == [{"cluster_id": "cl_000001", "label": "phishing", "size": 2}]
    assert clusters["duplicates_per_label"]["phishing"] == 1
    assert clusters["rows_without_cluster"] == 8
    assert stats["relabels"] == {"relabelled": 1, "matrix": {"phishing": {"crypto_scam": 1}}}
    assert stats["per_fetch_mode"]["manual"] == 10

    pages = stats["page_stats"]["phishing"]
    assert pages["pages"] == 5 and pages["missing_files"] == 0
    assert pages["percent_with_password"] == 60.0  # p1, p2, p5 of 5
    assert pages["percent_with_script"] == 100.0
    assert pages["text_chars_median"] < pages["text_chars_p90"]
    assert stats["page_stats"]["fake_ecommerce"]["file_size_median"] is None

    assert sum(stats["timeline"][day]["phishing"] for day in stats["timeline"]) == 5


def test_missing_file_is_counted_not_fatal(store):
    (store.raw_dir / "benign" / "c2_benign_000002.html").unlink()
    facts = read_page_facts(store, store.df)
    stats = view_statistics(store.df, facts)
    assert stats["page_stats"]["benign"]["missing_files"] == 1
    assert stats["page_stats"]["benign"]["pages"] == 2


# ---- imbalance, readiness, peer ------------------------------------------------------------------


def test_imbalance():
    result = imbalance({"benign": 10, "phishing": 5, "crypto_scam": 2})
    assert result["majority"] == "benign" and result["minority"] == "crypto_scam"
    assert result["ratio"] == 5.0
    assert result["percent"] == {"benign": 58.8, "phishing": 29.4, "crypto_scam": 11.8}
    assert imbalance({"benign": 4, "phishing": 0})["ratio"] is None  # a class is missing
    assert imbalance({"benign": 0})["majority"] is None  # empty dataset


def test_readiness_uses_the_clean_view(store):
    targets = {
        "overall": {"benign": 3, "phishing": 3, "crypto_scam": 1},
        "per_language": {"si": {"benign": 1, "phishing": 2}, "ta": {}},
    }
    result = readiness(select_view(store.df, "clean"), targets)
    labels = result["labels"]
    assert labels["benign"]["status"] == "ready" and labels["benign"]["ready"]
    # clean phishing = p1 + p5 (p2 duplicate, p3 excluded, p4 empty); only p5 is si
    assert labels["phishing"]["have"] == 2
    assert labels["phishing"]["status"] == "1 more needed, 1 more si needed"
    assert labels["crypto_scam"]["status"] == "ready"
    assert labels["fake_ecommerce"]["status"] == "ready"  # no target = nothing missing
    assert not result["all_ready"]
    assert result["language_coverage"]["si"]["samples"] == 2
    assert result["language_coverage"]["ta"]["samples"] == 0


def test_peer_summary(tmp_path):
    assert peer_summary(tmp_path / "missing.json") is None
    path = tmp_path / "peer_agreement.json"
    path.write_text(
        json.dumps(
            {
                "rated_samples": 20,
                "agreement_percent": 90.0,
                "cohen_kappa": 0.85,
                "kappa_interpretation": "almost perfect",
                "disagreements": [{"sample_id": "x"}, {"sample_id": "y"}],
            }
        ),
        encoding="utf-8",
    )
    assert peer_summary(path) == {
        "rated_samples": 20,
        "agreement_percent": 90.0,
        "cohen_kappa": 0.85,
        "kappa_interpretation": "almost perfect",
        "disagreements": 2,
    }
    path.write_text("{broken", encoding="utf-8")
    assert "error" in peer_summary(path)


# ---- report + figures --------------------------------------------------------------------------


def test_write_report_creates_json_markdown_and_figures(store, tmp_path):
    reports = tmp_path / "reports"
    facts = read_page_facts(store, store.df)
    stats = compute_statistics(store, reports, facts=facts)
    paths = write_report(stats, store.df, facts, reports)

    assert len(paths) == 2 + len(FIGURE_NAMES)
    for path in paths:
        assert path.is_file() and path.stat().st_size > 0
    for name in FIGURE_NAMES:
        assert (reports / "figures" / name).read_bytes().startswith(PNG_MAGIC)

    saved = json.loads((reports / "dataset_stats.json").read_text(encoding="utf-8"))
    assert saved["dataset_version"] == "unfrozen"
    assert set(saved["views"]) == {"all", "usable", "clean"}
    assert saved["views"]["clean"]["total"] == 7
    assert saved["figures"][0] == "figures/label_distribution.png"
    markdown = (reports / "dataset_stats.md").read_text(encoding="utf-8")
    assert "| view | total |" in markdown and "## Readiness" in markdown
    assert "phishing -> crypto_scam" in markdown


def test_figures_work_for_an_empty_dataset(tmp_path):
    store = MetadataStore(tmp_path / "metadata.csv", tmp_path / "raw")
    paths = make_figures(store.df, {}, tmp_path / "figures")
    assert [path.name for path in paths] == list(FIGURE_NAMES)
    assert all(path.stat().st_size > 0 for path in paths)


# ---- dataset versions --------------------------------------------------------------------------


def test_freeze_writes_manifest_and_refuses_overwrite(store, tmp_path):
    csv_path, info = freeze(store, "v0.1", notes="test freeze")
    assert csv_path == manifests_dir(store) / "dataset_v0.1.csv"
    lines = csv_path.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "sample_id,label,language,cluster_id,sha256,file_path"
    assert len(lines) == 1 + 7  # clean view only
    assert "https://" not in csv_path.read_text(encoding="utf-8")  # no URLs: safe for git
    assert info["total"] == 7 and info["counts_per_label"]["crypto_scam"] == 1
    saved = json.loads(csv_path.with_suffix(".json").read_text(encoding="utf-8"))
    assert saved["version"] == "v0.1" and saved["notes"] == "test freeze"
    assert "created_at" in saved and "git_commit" in saved

    with pytest.raises(FileExistsError):
        freeze(store, "v0.1")
    assert list_versions(manifests_dir(store)) == ["v0.1"]

    # the statistics now name the frozen version
    stats = compute_statistics(store, tmp_path / "reports", views=("clean",), facts={})
    assert stats["dataset_version"] == "v0.1"
    store.update("c2_benign_000002", excluded=True, exclusion_reason="other")
    stats = compute_statistics(store, tmp_path / "reports", views=("clean",), facts={})
    assert stats["dataset_version"] == "unfrozen"
    assert stats["latest_frozen_version"] == "v0.1"


def test_verify_detects_changed_and_missing_files(store):
    freeze(store, "v0.1")
    assert verify(store, "v0.1").ok

    (store.raw_dir / "benign" / "c2_benign_000001.html").write_text("changed", encoding="utf-8")
    (store.raw_dir / "malware_delivery" / "c2_malware_delivery_000001.html").unlink()
    result = verify(store, "v0.1")
    assert not result.ok
    assert result.changed == ["c2_benign_000001"]
    assert result.missing == ["c2_malware_delivery_000001"]

    with pytest.raises(FileNotFoundError):
        verify(store, "v9.9")


def test_freeze_refuses_bad_version_and_broken_files(store):
    with pytest.raises(ValueError, match="invalid version"):
        freeze(store, "../escape")
    (store.raw_dir / "benign" / "c2_benign_000001.html").unlink()
    with pytest.raises(ValueError, match="1 file\\(s\\) missing"):
        freeze(store, "v0.1")
    assert not (manifests_dir(store) / "dataset_v0.1.csv").exists()


def test_versions_sort_numerically(tmp_path):
    for version in ("v0.10", "v0.2", "v1"):
        (tmp_path / f"dataset_{version}.json").write_text("{}", encoding="utf-8")
    assert list_versions(tmp_path) == ["v0.2", "v0.10", "v1"]


# ---- command line ------------------------------------------------------------------------------


def run_cli(store: MetadataStore, reports: Path, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONIOENCODING": "utf-8"}
    command = [
        sys.executable, str(ROOT / "scripts" / "dataset_stats.py"),
        "--metadata", str(store.csv_path), "--raw-dir", str(store.raw_dir),
        "--reports-dir", str(reports), *args,
    ]  # fmt: skip
    return subprocess.run(command, capture_output=True, text=True, cwd=ROOT, env=env)


def test_cli_stats_freeze_verify(store, tmp_path):
    reports = tmp_path / "reports"
    result = run_cli(store, reports, "stats")
    assert result.returncode == 0, result.stderr
    assert "Clean view" in result.stdout and "Readiness" in result.stdout
    assert (reports / "figures" / "verification_progress.png").is_file()

    result = run_cli(store, reports, "freeze", "--version", "v0.1")
    assert result.returncode == 0, result.stderr
    assert "Froze dataset v0.1: 7 clean sample(s)" in result.stdout
    result = run_cli(store, reports, "freeze", "--version", "v0.1")
    assert result.returncode == 1 and "already exists" in result.stderr

    assert run_cli(store, reports, "verify", "--version", "v0.1").returncode == 0
    (store.raw_dir / "benign" / "c2_benign_000001.html").write_text("x", encoding="utf-8")
    result = run_cli(store, reports, "verify", "--version", "v0.1")
    assert result.returncode == 1 and "changed" in result.stdout
