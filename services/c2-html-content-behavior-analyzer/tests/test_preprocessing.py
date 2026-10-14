"""Tests for Part 2: HTML preprocessing pipeline (raw HTML -> ParsedPage).

Why: Parts 3-9 trust these extracted facts, so every rule from the Part 2
spec is pinned down here: broken HTML, comments, CSS, hidden text,
Sinhala/Tamil normalization, forms and labels, PII masking, scripts,
frames, caps, error isolation, saving/skipping and the CLI.
Synthetic fixtures only (tests/fixtures/preprocessing/) - no network.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from c2_analyzer.config import project_root
from c2_analyzer.dataset.collector import register_file
from c2_analyzer.dataset.manifest import freeze
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.preprocessing import batch, parser, pipeline
from c2_analyzer.preprocessing.batch import process_task, run_version
from c2_analyzer.preprocessing.loader import from_file, from_string
from c2_analyzer.preprocessing.pipeline import preprocess, preprocess_html, to_json
from c2_analyzer.preprocessing.report import describe_page, render_markdown, summarize
from c2_analyzer.preprocessing.settings import default_settings
from c2_analyzer.preprocessing.text_utils import clean_chars, normalize_block, normalize_inline
from c2_analyzer.schemas.parsed_page import SCHEMA_VERSION, ParsedPage
from c2_analyzer.utils.pii import luhn_valid, mask_pii, mask_url
from c2_analyzer.utils.url import domain_of_host, is_external, registrable_domain

ROOT = project_root()
FIXTURES = ROOT / "tests" / "fixtures" / "preprocessing"
SAMPLES = ROOT / "tests" / "fixtures" / "sample_pages"
PAGE_URL = "https://www.bank-site.example/login/index.html"
SRI_LANKA = "ශ්‍රී ලංකා"  # ශ්‍රී ලංකා (with ZWJ)
TAMIL = "இலங்கை"  # இலங்கை


def parse_fixture(name: str, url: str | None = PAGE_URL, folder: Path = FIXTURES) -> ParsedPage:
    return preprocess(from_file(folder / name, page_url=url))


@pytest.fixture(scope="module")
def full() -> ParsedPage:
    return parse_fixture("full_page.html")


# ---- parsing -----------------------------------------------------------------------------------


def test_malformed_html_parses():
    page = parse_fixture("malformed.html")
    assert page.meta.errors == [] and page.meta.parser_used == "lxml"
    assert "Unclosed paragraph" in page.visible_text and "After the form" in page.visible_text
    assert "cell one cell two" in page.visible_text
    assert page.forms[0].inputs[1].type == "password"
    assert page.event_handlers[0].attribute == "onerror"


def test_lxml_failure_falls_back_to_html_parser(monkeypatch):
    real = parser.BeautifulSoup

    def broken(markup, features):
        if features == "lxml":
            raise RuntimeError("simulated lxml crash")
        return real(markup, features)

    monkeypatch.setattr(parser, "BeautifulSoup", broken)
    page = preprocess_html("<p>Hello <b>world</p>", PAGE_URL)
    assert page.meta.parser_used == "html.parser"
    assert "lxml failed: RuntimeError" in page.meta.errors[0]
    assert page.visible_text == "Hello world"


def test_empty_and_binary_input_never_crash():
    assert preprocess_html("").visible_text == ""
    page = preprocess(from_string("\x00\x01<p>ok</p>\x00"))
    # NUL becomes U+FFFD (as in a browser), other control characters are removed
    assert page.visible_text.split("\n") == ["�", "ok", "�"]
    assert page.meta.errors == []


# ---- comments, CSS, text -----------------------------------------------------------------------


def test_comments_removed_and_counted(full):
    assert full.comments.count == 2
    assert full.comments.samples == ["kit by phisher v2", "second comment"]
    assert "kit by" not in full.visible_text and "kit by" not in full.hidden_text


def test_style_content_not_in_text_but_style_attributes_stay(full):
    assert "STYLE_MARKER" not in full.visible_text and "STYLE_MARKER" not in full.hidden_text
    assert full.css.inline_style_blocks_count == 1 and full.css.inline_style_total_chars > 0
    assert full.css.style_attribute_count == 5  # still in the DOM for Part 3
    sheets = full.css.external_stylesheets
    assert sheets[0].href_abs == "https://cdn.bank-site.example/app/css/site.css"
    assert not sheets[0].is_external and sheets[1].is_external


def test_hidden_text_is_separated(full):
    for how in ("display none", "attribute", "aria", "opacity", "font size"):
        assert f"Hidden by {how}" in full.hidden_text
        assert f"Hidden by {how}" not in full.visible_text
    assert "Please enable JavaScript" in full.hidden_text  # <noscript>


def test_visible_text_blocks_and_order(full):
    lines = full.visible_text.split("\n")
    assert lines[:3] == ["Welcome back", "Step one", "First paragraph."]
    assert "Second bold paragraph." in lines
    assert "Item one" in lines and "Item two" in lines
    assert "headScript" not in full.visible_text and "{{name}}" not in full.visible_text


def test_title_meta_headings_paragraphs(full):
    assert full.title == "Secure Login"
    assert full.meta_description == "Sign in to your account"
    assert full.meta_keywords == "bank, login"
    assert full.lang_attr == "en" and full.charset_declared == "utf-8"
    assert [(h.level, h.text) for h in full.headings] == [(1, "Welcome back"), (3, "Step one")]
    assert full.paragraphs[:2] == ["First paragraph.", "Second bold paragraph."]
    assert any(tag.property == "og:title" for tag in full.meta_tags)


def test_sinhala_zwj_and_tamil_preserved_byte_exact():
    page = parse_fixture("sinhala_tamil.html")
    assert page.headings[0].text == SRI_LANKA
    assert page.headings[0].text.encode("utf-8") == SRI_LANKA.encode("utf-8")
    assert page.paragraphs[0] == SRI_LANKA  # written as numeric entities in the HTML
    assert page.paragraphs[1].startswith(TAMIL)
    assert page.paragraphs[2] == "abcdef"  # zero-width space and BOM removed
    assert "‍" in page.visible_text and "​" not in page.visible_text
    assert page.title.startswith(SRI_LANKA)


def test_text_normalization_rules():
    assert clean_chars("a​b⁠c﻿d") == "abcd"
    assert clean_chars("x‍y‌z") == "x‍y‌z"  # ZWJ/ZWNJ kept
    assert clean_chars("a\x07b\x1b[2Jc\x85d") == "ab[2Jcd"  # C0/C1 controls removed
    assert clean_chars("é") == "é"  # NFC
    assert normalize_inline("  a \n\t b  ") == "a b"
    assert normalize_block(" a  b \n\n\n c \n") == "a b\nc"


# ---- forms -------------------------------------------------------------------------------------


def test_form_actions_resolved(full):
    login, search, external, fragment, script = full.forms
    # relative action resolved against <base href>; PII in the query masked
    assert login.action_abs == "https://cdn.bank-site.example/app/post.php?email=[EMAIL]&lang=en"
    assert login.action_raw == "post.php?email=[EMAIL]&lang=en"
    assert login.method == "POST" and login.action_domain == "bank-site.example"
    assert not login.is_external_action
    assert search.action_abs == PAGE_URL and search.method == "GET"  # empty action = page URL
    assert external.is_external_action and external.action_domain == "evil.example"
    assert fragment.action_abs == PAGE_URL
    assert script.action_abs is None and not script.is_external_action


def test_form_inputs_labels_and_pii(full):
    login = full.forms[0]
    fields = {field.name: field for field in login.inputs}
    assert fields["email"].type == "email" and fields["email"].label_text == "Email address"
    assert fields["email"].required and fields["email"].autocomplete == "username"
    assert fields["email"].value_masked == "[EMAIL]"
    assert fields["pw"].label_text.startswith("Password")  # wrapping <label>
    assert fields["pw"].value_present and fields["pw"].value_masked == "[REDACTED]"
    assert fields["phone"].hidden and fields["phone"].value_masked == "[PHONE]"
    assert fields["nic"].hidden and fields["nic"].maxlength == 12  # hidden by inline style
    assert fields["nic"].value_masked == "[NIC]"
    assert fields["country"].tag == "select" and fields["country"].value_masked == "lk"
    assert fields["note"].value_masked == "Call [PHONE]"
    assert fields["mobile"].type == "tel"  # outside the form, linked with form="login"
    assert [(b.type, b.text) for b in login.buttons] == [("submit", "Sign in"), ("submit", "Go")]
    assert full.forms[2].inputs[0].value_masked == "[CARD]"


def test_inputs_outside_forms(full):
    assert [field.name for field in full.inputs_outside_forms] == ["otp"]
    otp = full.inputs_outside_forms[0]
    assert otp.placeholder == "Enter OTP" and otp.label_text == "One-time code"


def test_visible_text_is_not_masked():
    page = preprocess_html("<p>Call 0771234567 or mail help@bank.lk</p>", PAGE_URL)
    assert page.visible_text == "Call 0771234567 or mail help@bank.lk"


# ---- PII and URL helpers -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("victim@mail.com", "[EMAIL]"),
        ("0771234567", "[PHONE]"),
        ("+94 77 123 4567", "[PHONE]"),
        ("011-2345678", "[PHONE]"),
        ("901234567V", "[NIC]"),
        ("199012345678", "[NIC]"),
        ("4111 1111 1111 1111", "[CARD]"),
        ("1697040000000", "1697040000000"),  # a timestamp, not a card (fails Luhn)
        ("session=abc123", "session=abc123"),
    ],
)
def test_mask_pii(text, expected):
    assert mask_pii(text) == expected


def test_mask_url_only_touches_pii_values():
    url = "https://x.test/a?email=v%40mail.com&lang=si&id=42#victim@mail.com"
    assert mask_url(url) == "https://x.test/a?email=[EMAIL]&lang=si&id=42#[EMAIL]"
    assert mask_url("https://x.test/a?b=1") == "https://x.test/a?b=1"
    assert mask_url("mailto:victim@mail.com") == "mailto:[EMAIL]"
    assert luhn_valid("4111111111111111") and not luhn_valid("4111111111111112")


def test_registrable_domains_offline():
    assert domain_of_host("login.secure.bank.com.lk") == "bank.com.lk"
    assert domain_of_host("www.example.co.uk") == "example.co.uk"
    assert domain_of_host("192.168.1.10") == "192.168.1.10"
    assert registrable_domain("javascript:alert(1)") is None
    assert not is_external("https://cdn.bank-site.example/x", PAGE_URL)
    assert is_external("https://other.example/x", PAGE_URL)
    assert is_external("https://other.example/x", None)  # page URL unknown
    assert not is_external("/relative", PAGE_URL)


# ---- scripts, links, frames --------------------------------------------------------------------


def test_scripts(full):
    assert [s.position for s in full.scripts_inline] == ["head", "body", "body"]
    assert full.scripts_inline[2].type == "module"
    assert all("schema.org" not in s.content for s in full.scripts_inline)
    assert full.structured_data[0].type == "application/ld+json"  # JSON-LD is data, not JS
    assert full.templates[0].type == "text/template"
    app, tracker = full.scripts_external
    assert app.src_abs == "https://cdn.bank-site.example/app/js/app.js" and not app.is_external
    assert app.defer and app.has_integrity and app.crossorigin == "anonymous" and not app.is_async
    assert tracker.is_external and tracker.is_async and "[EMAIL]" in tracker.src_abs
    dumped = json.loads(to_json(full))
    assert dumped["scripts_external"][1]["async"] is True  # JSON uses the alias


def test_event_handlers_and_javascript_urls(full):
    assert {(h.tag, h.attribute, h.code) for h in full.event_handlers} == {
        ("body", "onload", "init()"),
        ("button", "onclick", "doSomething()"),
    }
    assert {(j.tag, j.attribute) for j in full.javascript_urls} == {
        ("form", "action"),
        ("a", "href"),
        ("img", "src"),
    }


def test_meta_refresh_resolved(full):
    refresh = full.meta_refresh
    assert refresh.redirect_url == "https://cdn.bank-site.example/next?user=[EMAIL]"


def test_links(full):
    help_link, about, other, script, mail = full.links
    assert help_link.href_abs == "https://cdn.bank-site.example/help" and not help_link.is_external
    assert about.rel == "noopener" and about.target == "_blank" and not about.is_external
    assert other.is_external and other.domain == "other-site.example"
    assert script.href_abs is None and script.domain is None
    assert mail.href_abs == "mailto:[EMAIL]"


def test_embedded_hidden_frames(full):
    zero, styled, visible, embed = full.embedded
    assert zero.hidden and zero.is_external and zero.width == "0"
    assert styled.hidden and not styled.is_external
    assert not visible.hidden and visible.height == "315"
    assert embed.tag == "embed"


def test_dom_summary(full):
    dom = full.dom
    assert dom.element_count == sum(dom.tag_counts.values())
    assert dom.node_count > dom.element_count and dom.max_depth >= 4
    assert dom.skeleton.tag == "html"
    form = next(node for node in dom.skeleton.children[1].children if node.tag == "form")
    assert form.id == "login"
    assert not full.meta.truncated
    # saved JSON drops empty skeleton fields but loads back to the same page
    assert '"class": null' not in to_json(full)
    assert ParsedPage.model_validate_json(to_json(full)) == full


# ---- caps and error isolation ------------------------------------------------------------------


def test_skeleton_cap_sets_truncated():
    html = "<html><body>" + "<div>" * 60 + "deep" + "</div>" * 60 + "</body></html>"
    settings = replace(default_settings(), skeleton_max_depth=10, skeleton_max_nodes=5)
    page = preprocess(from_string(html), settings)
    assert page.meta.truncated
    assert any("skeleton" in reason for reason in page.meta.truncation_reasons)
    assert page.dom.max_depth > 60  # counts still cover the whole tree
    assert page.visible_text == "deep"


def test_size_cap_sets_truncated():
    settings = replace(default_settings(), max_html_bytes=1000)
    page = preprocess(from_string("<p>" + "x" * 5000 + "</p>", settings=settings), settings)
    assert page.meta.truncated and page.meta.html_size_bytes > 5000
    assert len(page.visible_text) < 1000


def test_one_failing_extractor_gives_partial_result(monkeypatch):
    def boom(*args, **kwargs):
        raise ValueError("simulated bug")

    monkeypatch.setattr(pipeline.form_extractor, "extract_forms", boom)
    page = parse_fixture("full_page.html")
    assert page.meta.errors == ["forms: ValueError: simulated bug"]
    assert page.forms == []  # the failed step's fields stay empty
    assert page.title == "Secure Login" and page.scripts_external  # the others still ran


# ---- existing sample pages + performance -------------------------------------------------------


def test_existing_sample_pages():
    phishing = parse_fixture("phishing_external_form.html", "https://bank.example/", SAMPLES)
    assert phishing.forms[0].is_external_action
    assert {field.type for field in phishing.forms[0].inputs} == {"email", "password", "hidden"}
    sinhala = parse_fixture("sinhala_urgency.html", None, SAMPLES)
    assert sinhala.lang_attr == "si" and sinhala.links[0].is_external
    js = parse_fixture("js_exfiltration.html", "https://bank.example/", SAMPLES)
    assert "exfil.example-attacker.test" in js.scripts_inline[0].content
    assert js.forms[0].action_abs == "https://bank.example/"


def test_one_megabyte_page_under_two_seconds():
    block = (FIXTURES / "full_page.html").read_text(encoding="utf-8")
    body = block.split("<body", 1)[1].split(">", 1)[1].rsplit("</body>", 1)[0]
    html = "<html><body>" + body * (1_000_000 // len(body) + 1) + "</body></html>"
    assert len(html.encode()) > 1_000_000
    preprocess(from_string("<p>warm-up</p>", PAGE_URL))  # one-time imports are not per-page cost
    started = time.perf_counter()
    page = preprocess(from_string(html, PAGE_URL))
    assert time.perf_counter() - started < 2.0
    assert page.meta.errors == []


# ---- saving, skipping, CLI ---------------------------------------------------------------------


@pytest.fixture
def frozen_store(tmp_path: Path) -> MetadataStore:
    store = MetadataStore(tmp_path / "metadata" / "metadata.csv", tmp_path / "raw")
    for number, name in enumerate(["phishing_external_form.html", "sinhala_urgency.html"], 1):
        source = tmp_path / f"in_{number}.html"
        source.write_bytes((SAMPLES / name).read_bytes())
        record, _ = register_file(
            store, source, "phishing", "en", "manual", f"https://p{number}.ex/"
        )
        store.update(record.sample_id, cluster_id=f"cl_{number:06d}")
    store.update(
        "c2_phishing_000001", verified=True, verified_by="T", verification_date=date.today()
    )
    store.save()
    freeze(store, "v0.1")
    return store


def test_run_version_saves_json_and_txt_and_skips_unchanged(frozen_store, tmp_path):
    out = tmp_path / "parsed"
    results, _ = run_version(frozen_store, "v0.1", workers=1, out_dir=out, show_progress=False)
    assert [r["status"] for r in results] == ["processed", "processed"]
    saved = json.loads((out / "c2_phishing_000001.json").read_text(encoding="utf-8"))
    assert saved["meta"]["dataset_version"] == "v0.1"
    assert saved["meta"]["schema_version"] == SCHEMA_VERSION
    assert saved["meta"]["page_url"] == "https://p1.ex/"
    text = (out / "c2_phishing_000002.txt").read_text(encoding="utf-8")
    assert text.startswith("හදිසි")

    again, _ = run_version(frozen_store, "v0.1", workers=1, out_dir=out, show_progress=False)
    assert [r["status"] for r in again] == ["skipped", "skipped"]
    forced, _ = run_version(
        frozen_store, "v0.1", workers=1, out_dir=out, force=True, show_progress=False
    )
    assert [r["status"] for r in forced] == ["processed", "processed"]

    summary = summarize(forced, "v0.1", 1.0, {})
    assert summary["counts"]["processed"] == 2
    assert summary["per_label"]["phishing"]["pct_with_password_input"] == 50.0
    assert "| phishing | 2 |" in render_markdown(summary)


def test_run_refuses_when_manifest_verify_fails(frozen_store, tmp_path):
    (frozen_store.raw_dir / "phishing" / "c2_phishing_000001.html").write_text("x", "utf-8")
    with pytest.raises(ValueError, match="failed verification"):
        run_version(frozen_store, "v0.1", workers=1, out_dir=tmp_path / "o", show_progress=False)


def test_failed_page_is_recorded_not_raised(tmp_path):
    task = {
        "sample_id": "c2_phishing_000009",
        "label": "phishing",
        "file": str(tmp_path / "missing.html"),
        "page_url": None,
        "sha256": "0" * 64,
        "version": "v0.1",
        "out_dir": str(tmp_path),
        "force": False,
    }
    result = process_task(task)
    assert result["status"] == "failed" and "FileNotFoundError" in result["error"]


def test_parallel_workers(frozen_store, tmp_path):
    out = tmp_path / "parallel"
    results, _ = batch.run_version(
        frozen_store, "v0.1", workers=2, out_dir=out, show_progress=False
    )
    assert {r["status"] for r in results} == {"processed"}
    assert len(list(out.glob("*.json"))) == 2


def run_cli(store: MetadataStore, tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONIOENCODING": "utf-8"}
    command = [
        sys.executable, str(ROOT / "scripts" / "preprocess_html.py"),
        "--metadata", str(store.csv_path), "--raw-dir", str(store.raw_dir),
        "--out-dir", str(tmp_path / "out"), "--reports-dir", str(tmp_path / "reports"), *args,
    ]  # fmt: skip
    return subprocess.run(command, capture_output=True, text=True, cwd=ROOT, env=env)


def test_cli_run_and_one(frozen_store, tmp_path):
    result = run_cli(frozen_store, tmp_path, "run", "--version", "v0.1", "--workers", "2")
    assert result.returncode == 0, result.stderr
    assert "processed 2, unchanged 0, failed 0" in result.stdout
    assert (tmp_path / "reports" / "v0.1_summary.json").is_file()
    assert (tmp_path / "reports" / "v0.1_summary.md").is_file()

    result = run_cli(frozen_store, tmp_path, "one", "--sample-id", "c2_phishing_000001")
    assert result.returncode == 0, result.stderr
    assert "Form [0]: POST https://collector.example-attacker.test/login.php" in result.stdout
    assert "(external)" in result.stdout

    page_file = FIXTURES / "full_page.html"
    result = run_cli(frozen_store, tmp_path, "one", "--file", str(page_file), "--url", PAGE_URL)
    assert result.returncode == 0, result.stderr
    assert "Title:      Secure Login" in result.stdout

    result = run_cli(frozen_store, tmp_path, "run", "--version", "v9.9")
    assert result.returncode == 1 and "Error" in result.stderr


def test_describe_page_is_terminal_safe():
    page = preprocess_html("<title>Bank\x1b[2J</title><p>hi</p>")
    text = describe_page(page)
    assert "\x1b" not in text and "Title:      Bank" in text
