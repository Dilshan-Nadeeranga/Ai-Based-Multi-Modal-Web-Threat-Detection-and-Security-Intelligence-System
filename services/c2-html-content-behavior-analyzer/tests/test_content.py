"""Tests for Part 5 (Batch A): text extraction, CTA / form labels, language ID, page_text.

Part 5: Multilingual scam content analyzer.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import json
from pathlib import Path

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from c2_analyzer.api.dependencies import get_dev_dataset
from c2_analyzer.api.dev_data import DevDataset
from c2_analyzer.api.main import create_app
from c2_analyzer.content import extractor, language
from c2_analyzer.content.batch import INDEX_COLUMNS, INDEX_NAME, run_version
from c2_analyzer.content.cta import from_html, is_short_imperative
from c2_analyzer.content.extractor import build_page_text, content_for_html, extract_content
from c2_analyzer.content.language import (
    LangdetectBackend,
    NoBackend,
    detect_language,
    detect_segment,
    latin_backend,
    script_ratios,
)
from c2_analyzer.content.report import describe_result, mismatches, summarize, write_report
from c2_analyzer.dataset.collector import register_file
from c2_analyzer.dataset.manifest import freeze, manifests_dir
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.preprocessing.loader import from_string
from c2_analyzer.preprocessing.pipeline import preprocess
from c2_analyzer.schemas.content import TextSegment

FIXTURES = Path(__file__).parent / "fixtures" / "content"
SAMPLES = Path(__file__).parent / "fixtures" / "sample_pages"
SCRIPT = Path(__file__).parents[1] / "scripts" / "build_text_corpus.py"
URL = "https://bank-help.test/login"
SRI = "ශ්‍රී"  # Sri: virama + ZERO WIDTH JOINER + ra - must survive extraction


def page_of(name: str, folder: Path = FIXTURES):
    return content_for_html((folder / name).read_text(encoding="utf-8"), URL)[1]


def texts(result, field: str) -> list[str]:
    return [segment.text for segment in result.by_field(field)]


@pytest.fixture(autouse=True)
def fresh_caches():
    """Every test starts with the real configs and backend (some tests swap them)."""
    language.reset_caches()
    extractor.reset_caches()
    yield
    language.reset_caches()
    extractor.reset_caches()


# ---- page language: en / si / ta / mixed / Singlish / Tanglish --------------------------


@pytest.mark.parametrize(
    "name, expected",
    [
        ("english_login.html", "en"),
        ("sinhala_cta.html", "si"),
        ("tamil.html", "ta"),
        ("mixed.html", "mixed"),
        ("singlish.html", "si_latn"),
        ("tanglish.html", "ta_latn"),
    ],
)
def test_page_language(name, expected):
    result = page_of(name)
    assert result.language.language == expected
    assert 0 < result.language.confidence <= 1
    assert result.language.method != "none"


def test_existing_sinhala_urgency_fixture_is_sinhala():
    result = page_of("sinhala_urgency.html", SAMPLES)
    assert result.language.language == "si" and result.language.method == "script"
    assert result.language.script_ratios["si"] > 0.9
    assert texts(result, "cta") == ["දැන් තහවුරු කරන්න"]


def test_methods_and_script_ratios():
    # 8 Sinhala code points (the ZWJ is not a letter of any script) + 3 Latin letters
    ratios = script_ratios(f"{SRI} ලංකා abc")
    assert ratios == {"si": round(8 / 11, 4), "ta": 0.0, "latin": round(3 / 11, 4), "other": 0.0}
    assert script_ratios("123 !!") == {"si": 0.0, "ta": 0.0, "latin": 0.0, "other": 0.0}
    assert detect_segment("Привет, как дела у тебя сегодня").guess.language == "other"
    assert detect_segment("12345").guess.language == "unknown"
    mixed = detect_segment("Verify now ඔබගේ ගිණුම තහවුරු කරන්න")
    assert mixed.guess.language == "mixed" and mixed.guess.method == "script"
    singlish = detect_segment("oya mage account eka verify karanna")
    assert singlish.guess.language == "si_latn" and singlish.guess.method == "lexicon"
    # English words alone never look like Singlish
    english = detect_segment("Your account has been suspended, verify your details now")
    assert english.guess.language == "en"
    assert detect_language("Bitte bestätigen Sie Ihr Konto innerhalb von 24 Stunden") == "other"


def test_short_segment_inherits_page_language():
    result = page_of("sinhala_cta.html")
    ok = next(s for s in result.segments if s.text == "OK")
    assert ok.field == "cta" and ok.language == "si" and ok.lang_method == "inherited"
    short = detect_segment("Login")
    assert short.inherit and short.guess.method == "inherited"


def test_tiny_page_of_short_latin_texts_is_judged_together():
    html = "<form><label for=e>Email</label><input id=e><button>Sign in</button></form>"
    result = content_for_html(html)[1]
    assert result.language.language == "en"
    assert all(s.lang_method == "inherited" for s in result.segments)


# ---- extraction: fields, CTA, labels, dedup, cleaning --------------------------------------


def test_fields_are_extracted_with_order():
    result = page_of("english_login.html")
    assert texts(result, "title") == ["Account Security Center"]
    assert texts(result, "meta_description") == [
        "Protect your online banking account with our security center."
    ]
    assert result.by_field("heading")[0].level == 1
    assert [s.order for s in result.segments] == list(range(len(result.segments)))
    assert result.segments[0].field == "title" and result.segments[0].segment_id == "s0001"
    assert result.meta.cta_source == "html" and result.has_cta and result.has_form_labels
    assert result.meta.schema_version == "text_v1" and result.meta.rules_hash


def test_cta_detection():
    ctas = texts(page_of("english_login.html"), "cta")
    assert "Confirm identity" in ctas  # <input type=submit value=...>
    assert "Cancel" in ctas  # <button>
    assert "Continue to secure page" in ctas  # <a class="btn ...">
    assert "Get help now" in ctas  # role=button
    assert "Claim refund" in ctas  # short link with an imperative verb
    assert "Hidden trap" not in ctas  # display:none button
    assert not any("quarterly report" in text for text in ctas)  # long link: not a CTA
    # Sinhala / Tamil CTAs (verb inflected, at the end of the phrase)
    assert texts(page_of("sinhala_cta.html"), "cta")[0] == "දැන් තහවුරු කරන්න"
    assert texts(page_of("tamil.html"), "cta") == ["இப்போது சரிபார்க்கவும்"]
    assert is_short_imperative("Log in") and not is_short_imperative("Target audience")
    # icon-only button: aria-label; wrapper div with real buttons does not count itself
    found = from_html(
        '<div class="btn-group"><a href="#">Home page</a>'
        '<button aria-label="Verify"></button></div>'
    )
    assert found.ctas == ["Verify"]


def test_form_labels_placeholders_and_aria_label_deduplicated():
    result = page_of("english_login.html")
    assert texts(result, "form_label") == ["Email address", "One-time code"]  # label + aria
    assert texts(result, "placeholder") == ["Enter your password"]
    # "you@example.com" is only an email -> junk; a hidden input has no label
    html = (
        '<form><input placeholder="Email" aria-label="Email"><label>Email'
        "<input name=x></label></form>"
    )
    result = content_for_html(html)[1]
    assert texts(result, "form_label") == ["Email"] and texts(result, "placeholder") == []


def test_menus_and_footers_are_merged_and_junk_dropped():
    result = page_of("english_login.html")
    menu = next(s for s in result.segments if s.text == "Home Help Contact")
    assert menu.field == "visible_other" and menu.count == 3
    all_text = " ".join(s.text for s in result.segments)
    assert "12/10/2026" not in all_text and "https://bank-help.test/terms" not in all_text
    assert result.meta.dropped["junk"] >= 2 and result.meta.dropped["duplicate"] >= 2
    # a form row made only of labels + CTA is not repeated as visible text
    form_row = "<form><label for=a>Email</label><input id=a><button>Sign in</button></form>"
    assert texts(content_for_html(form_row)[1], "visible_other") == []


def test_pii_masked_wording_kept():
    result = page_of("english_login.html")
    assert "For help, write to [EMAIL] or call [PHONE] today." in texts(result, "paragraph")
    assert "077 123 4567" not in result.page_text and "support@" not in result.page_text


def test_alert_banners_and_hidden_text():
    result = page_of("english_login.html")
    alerts = texts(result, "alert_banner")
    assert alerts[0] == "Your account has been suspended due to unusual activity."  # role=alert
    assert any("within 24 hours" in text for text in alerts)  # short + urgency marker
    assert all(s.count == 1 for s in result.by_field("alert_banner"))
    assert texts(result, "hidden") == ["Hidden trap"]
    assert "Hidden trap" not in result.page_text  # hidden text never reaches the model


def test_zwj_is_preserved():
    result = page_of("sinhala_cta.html")
    assert SRI in texts(result, "title")[0] and SRI in texts(result, "paragraph")[0]
    assert SRI in result.page_text


def test_empty_page():
    result = content_for_html("<html><body><script>var a=1</script></body></html>")[1]
    assert result.empty and result.segments == [] and result.page_text == ""
    assert result.language.language == "unknown"


def test_without_html_ctas_come_from_the_parsed_page():
    page = preprocess(from_string((FIXTURES / "english_login.html").read_text("utf-8"), URL))
    result = extract_content(page)
    assert result.meta.cta_source == "parsed_page" and result.meta.warnings
    assert {"Confirm identity", "Cancel", "Claim refund"} <= set(texts(result, "cta"))


# ---- page_text --------------------------------------------------------------------------


def test_page_text_field_order_and_markers():
    text = page_of("english_login.html").page_text
    order = [text.index(m) for m in ("[TITLE]", "[CTA]", "[LABEL]", "[HEADING]", "[ALERT]")]
    assert order == sorted(order)
    assert text.index("[ALERT]") < text.index("[DESC]") < text.index("[TEXT]")
    assert text.startswith("[TITLE] Account Security Center\n[CTA] ")
    assert len(text) <= 3000


def test_page_text_truncation_keeps_priority_fields():
    rules = dataclasses.replace(extractor.content_rules(), page_max_chars=80, min_tail_chars=10)
    segments = [
        TextSegment(segment_id="s1", field="paragraph", text="word " * 40, order=0, chars=200),
        TextSegment(segment_id="s2", field="title", text="Verify account", order=1, chars=14),
        TextSegment(segment_id="s3", field="cta", text="Claim now", order=2, chars=9),
    ]
    text, truncated = build_page_text(segments, rules)
    assert truncated and len(text) <= 80
    assert text.startswith("[TITLE] Verify account\n[CTA] Claim now\n[TEXT] word")
    assert not text.endswith(" ")  # cut at a word boundary
    short, cut = build_page_text(segments[1:], rules)
    assert not cut and short == "[TITLE] Verify account\n[CTA] Claim now"


# ---- fallback when the fastText model is missing -----------------------------------------


def test_fallback_when_fasttext_model_missing(monkeypatch, tmp_path):
    real = language.settings()
    missing = dataclasses.replace(real, fasttext_model=tmp_path / "missing.ftz")
    monkeypatch.setattr(language, "settings", lambda: missing)
    language.latin_backend.cache_clear()
    extractor.rules_hash.cache_clear()
    assert isinstance(latin_backend(), LangdetectBackend)
    result = page_of("english_login.html")
    assert result.language.language == "en" and result.language.backend == "langdetect"
    assert detect_language("Bitte bestätigen Sie Ihr Konto innerhalb von 24 Stunden") == "other"
    first_hash = extractor.rules_hash()

    nothing = dataclasses.replace(real, backend_order=())
    monkeypatch.setattr(language, "settings", lambda: nothing)
    language.latin_backend.cache_clear()
    extractor.rules_hash.cache_clear()
    assert isinstance(latin_backend(), NoBackend)
    result = page_of("english_login.html")
    assert result.language.language == "en" and result.language.method == "script_only"
    assert page_of("sinhala_cta.html").language.language == "si"  # scripts need no model
    assert extractor.rules_hash() != first_hash  # another backend -> results are redone


# ---- API == CLI, dev endpoint, batch + report -------------------------------------------


def load_cli():
    spec = importlib.util.spec_from_file_location("build_text_corpus_cli", SCRIPT)
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    return cli


def comparable(data: dict) -> dict:
    data = json.loads(json.dumps(data))
    data["meta"].pop("processing_ms")
    return data


def test_public_api_matches_pipeline_and_cli(tmp_path, capsys):
    html = (FIXTURES / "english_login.html").read_text(encoding="utf-8")
    client = TestClient(create_app("production"))
    response = client.post("/api/v1/content", json={"html": html, "url": URL})
    assert response.status_code == 200, response.text
    body = response.json()
    expected = content_for_html(html, URL)[1].model_dump(mode="json")
    assert comparable(body) == comparable(expected)

    page = tmp_path / "page.html"
    page.write_bytes(html.encode("utf-8"))  # write_text would turn \n into \r\n on Windows
    assert load_cli().main(["one", "--file", str(page), "--url", URL, "--json"]) == 0
    assert comparable(json.loads(capsys.readouterr().out)) == comparable(body)
    assert load_cli().main(["one", "--file", str(page)]) == 0
    printed = capsys.readouterr().out
    assert "Page language: en" in printed and "== cta (" in printed and "== page_text" in printed

    assert client.post("/api/v1/content", json={"url": URL}).status_code == 422
    big = client.post("/api/v1/content", json={"html": "a" * (5 * 1024 * 1024 + 1)})
    assert big.status_code == 413
    schema = client.get("/openapi.json").json()["components"]["schemas"]["ContentRequest"]
    assert schema["examples"]


@pytest.fixture
def frozen_store(tmp_path: Path) -> MetadataStore:
    store = MetadataStore(tmp_path / "metadata" / "metadata.csv", tmp_path / "raw")
    pages = [
        ("english_login.html", "phishing", "en", FIXTURES),
        ("sinhala_urgency.html", "phishing", "en", SAMPLES),  # wrong metadata on purpose
        ("benign_simple.html", "benign", "en", SAMPLES),
    ]
    for number, (name, label, lang, folder) in enumerate(pages, 1):
        source = tmp_path / f"in_{number}.html"
        source.write_bytes((folder / name).read_bytes())
        record, _ = register_file(store, source, label, lang, "manual", f"https://p{number}.ex/")
        store.update(record.sample_id, cluster_id=f"cl_{number:06d}")
    store.save()
    freeze(store, "v0.1")
    return store


def run(store: MetadataStore, tmp_path: Path, **kwargs):
    return run_version(
        store,
        "v0.1",
        workers=1,
        out_dir=tmp_path / "text",
        parsed_dir=tmp_path / "parsed",
        show_progress=False,
        **kwargs,
    )


def test_batch_index_skip_report_and_mismatch_list(frozen_store, tmp_path):
    results, seconds, stored, index_path = run(frozen_store, tmp_path)
    assert sorted(r["status"] for r in results) == ["processed"] * 3
    assert index_path.name == INDEX_NAME
    index = pd.read_csv(index_path)
    assert list(index.columns) == INDEX_COLUMNS
    row = index.set_index("sample_id").loc["c2_phishing_000002"]
    assert row["page_language"] == "si" and row["si_ratio"] > 0.9 and row["has_cta"] == 1

    again, _, _, _ = run(frozen_store, tmp_path)
    assert [r["status"] for r in again] == ["skipped"] * 3
    forced, _, _, _ = run(frozen_store, tmp_path, label="benign", force=True)
    assert [r["status"] for r in forced] == ["processed"]
    assert len(pd.read_csv(index_path)) == 3  # a --label run never shrinks the index

    summary = summarize(stored, results, "v0.1", seconds, {})
    assert summary["language_distribution"]["phishing"]["si"] == 1
    assert summary["metadata_vs_detected"]["en"]["si"] == 1
    assert summary["top_ctas"]["phishing"][0]["pages"] >= 1
    assert summary["counts"]["failed"] == 0 and summary["empty_pages"] == []
    assert [m["sample_id"] for m in mismatches(stored)] == ["c2_phishing_000002"]
    paths = write_report(summary, stored, tmp_path / "reports")
    assert [p.name for p in paths] == [
        "v0.1_summary.json",
        "v0.1_summary.md",
        "v0.1_language_mismatch.csv",
    ]
    review = pd.read_csv(paths[2])
    assert review.loc[0, "detected_language"] == "si" and review.loc[0, "metadata_language"] == "en"
    assert "Metadata language" in paths[1].read_text(encoding="utf-8")
    # metadata.csv was not changed by the report
    assert (
        MetadataStore(frozen_store.csv_path, frozen_store.raw_dir)
        .get("c2_phishing_000002")
        .language
        == "en"
    )
    assert "== page_text" in describe_result(stored[0][1], "phishing")


def test_dev_endpoint_stored_and_on_the_fly(frozen_store, tmp_path):
    run(frozen_store, tmp_path)
    dataset = DevDataset(
        manifests_dir(frozen_store),
        tmp_path / "parsed_root",
        frozen_store.raw_dir,
        metadata_csv=frozen_store.csv_path,
        content_root=tmp_path,  # <root>/<version>/
    )
    (tmp_path / "v0.1").mkdir()
    for path in (tmp_path / "text").glob("c2_*.json"):
        (tmp_path / "v0.1" / path.name).write_bytes(path.read_bytes())
    app = create_app("development")
    app.dependency_overrides[get_dev_dataset] = lambda: dataset
    client = TestClient(app)
    stored = client.get("/api/v1/dev/samples/c2_phishing_000002/content")
    assert stored.status_code == 200 and stored.headers["x-content-source"] == "stored"
    assert stored.json()["language"]["language"] == "si"
    (tmp_path / "v0.1" / "c2_phishing_000002.json").unlink()
    fresh = client.get("/api/v1/dev/samples/c2_phishing_000002/content")
    assert fresh.headers["x-content-source"] == "on-the-fly"
    assert comparable(fresh.json()) == comparable(stored.json())
    assert not (tmp_path / "v0.1" / "c2_phishing_000002.json").exists()  # read-only
    assert client.get("/api/v1/dev/samples/c2_phishing_999999/content").status_code == 404
    production = TestClient(create_app("production"))
    assert production.get("/api/v1/dev/samples/c2_phishing_000002/content").status_code == 404
