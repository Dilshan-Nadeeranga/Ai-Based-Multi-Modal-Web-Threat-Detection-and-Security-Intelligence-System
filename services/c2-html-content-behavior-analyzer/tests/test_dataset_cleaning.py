"""Tests for Part 1 Batch C, Task 11: quality flags and near-duplicate clustering.

Why: these steps decide which pages the models train on and how the data is
split, so their rules are pinned down here with small synthetic pages (no
network, no real scam pages). Every test uses tmp_path; data/ is never touched.
"""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
from pathlib import Path

import pytest

from c2_analyzer.config import project_root
from c2_analyzer.dataset.collector import register_file
from c2_analyzer.dataset.deduplicator import (
    DedupSettings,
    UnionFind,
    choose_representative,
    fingerprint,
    jaccard,
    normalize_text,
    run_dedup,
    shingles,
)
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dataset.page_view import parse_page
from c2_analyzer.dataset.quality import check_page, run_quality

ROOT = project_root()
QUALITY = ROOT / "tests" / "fixtures" / "quality"
PAGES = ROOT / "tests" / "fixtures" / "sample_pages"


def flag_of(path: Path, label: str = "phishing", notes: str | None = None) -> str:
    html = path.read_text(encoding="utf-8")
    return check_page(parse_page(html), html, label, notes)


# ---- quality -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "label", "expected"),
    [
        ("normal.html", "benign", "ok"),
        ("empty.html", "phishing", "empty"),
        ("parked.html", "phishing", "parked_domain"),
        ("error_page.html", "phishing", "error_page"),
        ("nginx_default.html", "malware_delivery", "error_page"),
        ("bot_challenge.html", "phishing", "bot_challenge"),
        ("suspended_hosting.html", "phishing", "suspended_hosting"),
        ("login_wall.html", "benign", "login_wall"),
        # a phishing page IS a login page: never flagged as a login wall
        ("login_wall.html", "phishing", "ok"),
        # Cloudflare script + captcha widget on a real phishing page: not a challenge page
        ("phishing_with_captcha.html", "phishing", "ok"),
    ],
)
def test_quality_flags(fixture, label, expected):
    assert flag_of(QUALITY / fixture, label) == expected


@pytest.mark.parametrize("page", ["sinhala_urgency.html", "tamil_page.html", "mixed_page.html"])
def test_sinhala_and_tamil_pages_not_falsely_flagged(page):
    assert flag_of(PAGES / page) == "ok"


def test_redirected_offsite_comes_from_the_batch_b_note():
    notes = "urlhaus tags=x; redirected to paypal.com - check the label"
    assert flag_of(QUALITY / "normal.html", notes=notes) == "redirected_offsite"
    # a content problem is more important than the redirect
    assert flag_of(QUALITY / "error_page.html", notes=notes) == "error_page"


def test_long_page_mentioning_an_error_phrase_is_ok():
    article = "<html><body><p>" + "Our guide explains what page not found means. " * 80
    assert check_page(parse_page(article), article, "benign") == "ok"


# ---- helpers to build a small dataset ---------------------------------------------------------


def make_store(tmp_path: Path) -> MetadataStore:
    return MetadataStore(tmp_path / "metadata" / "metadata.csv", tmp_path / "raw")


def add_page(store: MetadataStore, html: str, label: str = "phishing", language: str = "en"):
    """Register an HTML string as a sample (like the collector does)."""
    number = len(store.df) + 1
    source = store.raw_dir.parent / f"incoming_{number}.html"
    source.write_text(html, encoding="utf-8")
    record, _ = register_file(
        store, source, label, language, "manual", f"https://site{number}.example/"
    )
    store.save()
    return record.sample_id


def words(seed: int, count: int, vocabulary: list[str]) -> list[str]:
    rng = random.Random(seed)
    return [rng.choice(vocabulary) for _ in range(count)]


ENGLISH = (
    "account bank verify login secure update password card payment urgent suspended click "
    "confirm details identity limited access review security customer service team notice "
    "within hours failure result permanent closure please immediately information required"
).split()
SINHALA = (
    "ඔබගේ ගිණුම බැංකු තහවුරු කරන්න වහාම පැය ඇතුළත අත්හිටුවනු ලැබේ තොරතුරු මුරපදය "
    "කාඩ්පත ගෙවීම ආරක්ෂාව පාරිභෝගික සේවා දැනුම්දීම අවසන් අවස්ථාව ක්ලික් කරන්න මෙතන"
).split()


def kit_page(text_words: list[str], brand: str, tracking: int) -> str:
    """One phishing-kit layout; only the brand word and a tracking number change."""
    body = " ".join(text_words)
    return (
        f"<html><head><title>{brand} secure login</title></head><body>"
        f"<div class='box'><h1>{brand}</h1><p>{body}</p>"
        f"<form action='/post.php' method='post'><input type='email'><input type='password'>"
        f"<button>Continue</button></form><small>ref {tracking}</small></div></body></html>"
    )


# ---- dedup building blocks ---------------------------------------------------------------------


def test_text_normalization_and_shingles():
    assert normalize_text("Pay  NOW\n 2026 ගිණුම 123") == "pay now ගිණුම"
    assert shingles(["a", "b", "c"], 2) == {"a b", "b c"}
    assert shingles(["a"], 5) == {"a"} and shingles([], 5) == set()
    assert jaccard({"a", "b"}, {"b", "c"}) == pytest.approx(1 / 3)
    assert jaccard(set(), set()) == 0.0


def test_near_duplicate_rule():
    rule = DedupSettings()
    assert rule.is_near_duplicate(0.92, 0.10)  # same text
    assert rule.is_near_duplicate(0.75, 0.97)  # same layout, similar text
    assert not rule.is_near_duplicate(0.60, 0.99)  # same layout, different text
    assert not rule.is_near_duplicate(0.85, 0.80)


def test_union_find_groups_chains():
    groups = UnionFind(["a", "b", "c", "d"])
    groups.union("a", "b")
    groups.union("c", "b")
    assert sorted(groups.groups()) == [["a", "b", "c"], ["d"]]


def test_representative_rules():
    rows = [
        {"sample_id": "c2_phishing_000001", "verified": "false", "collection_date": "2026-01-01"},
        {"sample_id": "c2_phishing_000002", "verified": "true", "collection_date": "2026-03-01"},
        {"sample_id": "c2_phishing_000003", "verified": "false", "collection_date": "2026-02-01"},
    ]
    lengths = {"c2_phishing_000001": 100, "c2_phishing_000002": 50, "c2_phishing_000003": 900}
    assert choose_representative(rows, lengths) == "c2_phishing_000002"  # verified first
    unverified = [rows[0], rows[2]]
    assert choose_representative(unverified, lengths) == "c2_phishing_000003"  # longest text
    same_length = {"c2_phishing_000001": 100, "c2_phishing_000003": 100}
    assert choose_representative(unverified, same_length) == "c2_phishing_000001"  # oldest


def test_fingerprint_ignores_digits():
    settings = DedupSettings()
    a = parse_page(kit_page(words(1, 300, ENGLISH), "PayPal", 111))
    b = parse_page(kit_page(words(1, 300, ENGLISH), "PayPal", 999))
    assert jaccard(fingerprint(a.text, a.tags, settings).text,
                   fingerprint(b.text, b.tags, settings).text) == 1.0  # fmt: skip


# ---- dedup on a store --------------------------------------------------------------------------


def test_near_identical_kits_clustered_and_marked(tmp_path):
    store = make_store(tmp_path)
    text = words(7, 400, ENGLISH)
    kit_a = add_page(store, kit_page(text, "PayPal", 1001))
    kit_b = add_page(store, kit_page(text, "PayPaI", 2002))  # other domain, typo brand
    other = add_page(store, kit_page(words(99, 400, ENGLISH), "Netflix", 3))  # same layout!

    result = run_dedup(store, reports_dir=tmp_path / "reports")

    a, b, c = store.get(kit_a), store.get(kit_b), store.get(other)
    assert a.cluster_id == b.cluster_id != c.cluster_id
    assert c.cluster_id is not None and c.is_duplicate_of is None  # singleton still gets an id
    assert {a.is_duplicate_of, b.is_duplicate_of} == {None, a.sample_id}  # oldest/first kept
    assert result.summary()["duplicates_marked"] == 1
    assert len(result.multi_clusters) == 1 and result.conflicts == []


def test_sinhala_near_duplicates_clustered(tmp_path):
    store = make_store(tmp_path)
    text = words(3, 300, SINHALA)
    changed = text.copy()
    changed[150] = "අලුත්"  # one word different
    first = add_page(store, kit_page(text, "BOC", 1), language="si")
    second = add_page(store, kit_page(changed, "BOC", 2), language="si")
    run_dedup(store, reports_dir=tmp_path / "reports")
    assert store.get(second).is_duplicate_of == first


def test_mixed_label_cluster_is_a_conflict_not_a_duplicate(tmp_path):
    store = make_store(tmp_path)
    text = words(5, 300, ENGLISH)
    phish = add_page(store, kit_page(text, "Binance", 1), label="phishing")
    crypto = add_page(store, kit_page(text, "Binance", 2), label="crypto_scam")

    result = run_dedup(store, reports_dir=tmp_path / "reports")

    assert store.get(phish).cluster_id == store.get(crypto).cluster_id
    assert store.get(phish).is_duplicate_of is None and store.get(crypto).is_duplicate_of is None
    assert len(result.conflicts) == 1 and result.conflicts[0].labels == [
        "crypto_scam",
        "phishing",
    ]
    report = json.loads((tmp_path / "reports" / "dedup_report.json").read_text("utf-8"))
    assert report["summary"]["label_conflicts"] == 1
    assert report["label_conflicts"][0]["members"] == sorted([phish, crypto])


def test_flagged_and_excluded_pages_are_not_compared(tmp_path):
    store = make_store(tmp_path)
    text = words(11, 300, ENGLISH)
    keep = add_page(store, kit_page(text, "Bank", 1))
    excluded = add_page(store, kit_page(text, "Bank", 2))
    flagged = add_page(store, kit_page(text, "Bank", 3))
    store.update(excluded, excluded=True, exclusion_reason="other")
    store.update(flagged, quality_flag="error_page")

    result = run_dedup(store, reports_dir=tmp_path / "reports")

    ids = {store.get(s).cluster_id for s in (keep, excluded, flagged)}
    assert len(ids) == 3  # three singletons
    assert result.not_compared == {excluded: "excluded", flagged: "quality_flag error_page"}


def test_dry_run_saves_nothing_and_rerun_is_stable(tmp_path):
    store = make_store(tmp_path)
    text = words(13, 300, ENGLISH)
    add_page(store, kit_page(text, "Bank", 1))
    add_page(store, kit_page(text, "Bank", 2))
    before = store.csv_path.read_bytes()

    run_dedup(store, dry_run=True, reports_dir=tmp_path / "reports")
    assert store.csv_path.read_bytes() == before
    assert not (tmp_path / "reports").exists()

    run_dedup(MetadataStore(store.csv_path, store.raw_dir), reports_dir=tmp_path / "reports")
    saved = store.csv_path.read_bytes()
    again = run_dedup(MetadataStore(store.csv_path, store.raw_dir), reports_dir=tmp_path / "r2")
    assert again.changed == 0 and store.csv_path.read_bytes() == saved
    assert (tmp_path / "reports" / "dedup_report.csv").is_file()


def test_quality_run_sets_flags_and_never_deletes(tmp_path):
    store = make_store(tmp_path)
    ok = add_page(store, (QUALITY / "normal.html").read_text("utf-8"))
    parked = add_page(store, (QUALITY / "parked.html").read_text("utf-8"))
    files = sorted(store.raw_dir.rglob("*.html"))

    result = run_quality(MetadataStore(store.csv_path, store.raw_dir))

    reloaded = MetadataStore(store.csv_path, store.raw_dir)
    assert reloaded.get(ok).quality_flag == "ok"
    assert reloaded.get(parked).quality_flag == "parked_domain"
    assert result.counts == {"ok": 1, "parked_domain": 1}
    assert sorted(store.raw_dir.rglob("*.html")) == files  # nothing deleted
    assert reloaded.validate_all() == []


def test_cli_all(tmp_path):
    store = make_store(tmp_path)
    text = words(17, 300, ENGLISH)
    add_page(store, kit_page(text, "Bank", 1))
    add_page(store, kit_page(text, "Bank", 2))
    add_page(store, (QUALITY / "parked.html").read_text("utf-8"))
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONIOENCODING": "utf-8"}
    command = [
        sys.executable, str(ROOT / "scripts" / "deduplicate.py"),
        "--metadata", str(store.csv_path), "--raw-dir", str(store.raw_dir),
        "--reports-dir", str(tmp_path / "reports"), "all",
    ]  # fmt: skip
    result = subprocess.run(command, capture_output=True, text=True, cwd=ROOT, env=env)
    assert result.returncode == 0, result.stderr
    assert "parked_domain: 1   (proposed for exclusion)" in result.stdout
    assert "duplicates marked:             1" in result.stdout
    assert (tmp_path / "reports" / "dedup_report.json").is_file()
