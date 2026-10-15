"""Tests for Part 3: DOM structural analysis (feature vector + evidence).

Why: Part 4 trains on these numbers, so every feature group is pinned on a
hand-made page with known answers, the vector's order and finiteness are
checked against the YAML dictionary, and the batch/CSV/API paths must give the
same numbers for the same page.
"""

from __future__ import annotations

import json
import math
from datetime import date
from pathlib import Path

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from c2_analyzer.api.dependencies import get_dev_dataset
from c2_analyzer.api.dev_data import DevDataset
from c2_analyzer.api.main import create_app
from c2_analyzer.config import load_yaml_config
from c2_analyzer.dataset.collector import register_file
from c2_analyzer.dataset.manifest import freeze, manifests_dir
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dom import dictionary as dom_dictionary
from c2_analyzer.dom import pipeline as dom_pipeline
from c2_analyzer.dom.batch import run_version
from c2_analyzer.dom.dictionary import feature_names, load_dictionary
from c2_analyzer.dom.exporter import ID_COLUMNS, csv_columns
from c2_analyzer.dom.form_features import classify_field
from c2_analyzer.dom.pipeline import dom_features_for_html, extract_dom_features
from c2_analyzer.dom.report import describe_dictionary, describe_result, summarize
from c2_analyzer.dom.tree import from_parsed_page, measure, parse
from c2_analyzer.dom.vectorizer import FeatureVectorError, build_vector, to_list
from c2_analyzer.preprocessing.loader import from_string
from c2_analyzer.preprocessing.pipeline import preprocess
from c2_analyzer.schemas.parsed_page import InputField

ROOT = Path(__file__).resolve().parents[1]
DOM_FIXTURES = ROOT / "tests" / "fixtures" / "dom"
SAMPLES = ROOT / "tests" / "fixtures" / "sample_pages"
URL = "https://bank.example/login"


def features_of(html: str, url: str | None = URL) -> dict:
    return dom_features_for_html(html, url).features


def fixture(name: str) -> str:
    return (DOM_FIXTURES / name).read_text(encoding="utf-8")


def page(body: str, head: str = "<title>t</title>") -> str:
    return f"<!doctype html><html><head>{head}</head><body>{body}</body></html>"


# ---- 1-3: tree ----------------------------------------------------------------------------------

TREE_PAGE = (
    "<html><head><title>T</title></head>"
    "<body><div><p>a</p><p>b</p></div><span></span></body></html>"
)


def test_tree_metrics_on_known_page():
    tree = measure(parse(TREE_PAGE))
    # html1 head2 title3 body2 div3 p4 p4 span3 -> 8 elements; texts T, a, b
    assert tree.element_count == 8 and tree.node_count == 11
    assert tree.max_depth == 4
    assert tree.avg_depth == pytest.approx(22 / 8)
    assert tree.leaf_ratio == pytest.approx(4 / 8)  # title, p, p, span
    assert tree.distinct_tag_count == 7


def test_tree_agrees_with_part2_and_skeleton_fallback():
    parsed = preprocess(from_string(TREE_PAGE, URL))
    tree = measure(parse(TREE_PAGE))
    assert (tree.node_count, tree.element_count, tree.max_depth) == (
        parsed.dom.node_count,
        parsed.dom.element_count,
        parsed.dom.max_depth,
    )
    assert from_parsed_page(parsed) == tree  # skeleton not capped -> exactly the same
    result = extract_dom_features(parsed, html=None)
    assert result.tree_source == "parsed_page"
    assert any("raw HTML not available" in w for w in result.warnings)


def test_very_deep_page_does_not_crash():
    html = "<html><body>" + "<div>" * 20000 + "x" + "</div>" * 20000 + "</body></html>"
    result = dom_features_for_html(html, URL)
    assert result.errors == []
    assert result.features["max_depth"] > 250  # lxml caps nesting; no RecursionError either way
    assert result.features["element_count"] > 250


# ---- 4-7: forms, credentials, hidden inputs ------------------------------------------------------


def field(**kwargs) -> InputField:
    return InputField(tag=kwargs.pop("tag", "input"), type=kwargs.pop("type", "text"), **kwargs)


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"type": "password"}, "password"),
        ({"type": "text", "autocomplete": "current-password"}, "password"),
        ({"type": "password", "label_text": "මුරපදය"}, "password"),
        ({"type": "email"}, "email"),
        ({"autocomplete": "email"}, "email"),
        ({"name": "user_email"}, "email"),
        ({"label_text": "ඊමේල් ලිපිනය"}, "email"),
        ({"label_text": "மின்னஞ்சல்"}, "email"),
        ({"autocomplete": "username"}, "username"),
        ({"name": "login_id"}, "username"),
        ({"label_text": "පරිශීලක නාමය"}, "username"),
        ({"label_text": "பயனர் பெயர்"}, "username"),
        ({"autocomplete": "one-time-code"}, "otp_pin"),
        ({"name": "sms_code"}, "otp_pin"),
        ({"placeholder": "Enter PIN"}, "otp_pin"),
        ({"label_text": "සත්‍යාපන කේතය"}, "otp_pin"),
        ({"label_text": "ஒருமுறை கடவுச்சொல்"}, "otp_pin"),
        ({"autocomplete": "cc-number"}, "card"),
        ({"autocomplete": "cc-csc"}, "card"),
        ({"autocomplete": "cc-exp"}, "card"),
        ({"name": "cvv"}, "card"),
        ({"placeholder": "MM/YY"}, "card"),
        ({"label_text": "කාඩ්පත් අංකය"}, "card"),
        ({"tag": "select", "type": "select", "name": "expiry_month"}, "card"),
        ({"placeholder": "National Identity Card Number"}, None),  # NIC is not a payment card
        ({"name": "captcha", "placeholder": "verification code"}, None),
        ({"type": "hidden", "name": "email"}, None),  # carries data, does not ask for it
        ({"type": "checkbox", "name": "remember_email"}, None),
        ({"type": "submit", "name": "login"}, None),
        ({"name": "search"}, None),
    ],
)
def test_field_classification(kwargs, expected):
    assert classify_field(field(**kwargs)) == expected


def test_credentials_page_counts():
    f = features_of(fixture("credentials.html"))
    assert f["form_count"] == 1 and f["has_form"] == 1
    assert f["inputs_total"] == 13 and f["inputs_outside_forms_count"] == 1
    assert f["password_field_count"] == 1 and f["has_password_field"] == 1
    assert f["email_field_count"] == 2  # Sinhala label + type=email outside the form
    assert f["username_field_count"] == 1  # Tamil label
    assert f["otp_pin_field_count"] == 1
    assert f["card_field_count"] == 3  # number, cvv, expiry (NIC excluded)
    assert f["sensitive_field_count"] == 5  # password + otp + 3 card
    assert f["hidden_input_count"] == 2  # type=hidden + display:none
    assert f["hidden_input_ratio"] == pytest.approx(2 / 13, abs=1e-4)


def test_no_inputs_no_division_error():
    f = features_of(page("<p>hello</p>"))
    assert f["inputs_total"] == 0 and f["hidden_input_ratio"] == 0.0


# ---- 8: form actions -----------------------------------------------------------------------------

LOGIN = '<input type="email" name="e"><input type="password" name="p">'


@pytest.mark.parametrize(
    ("form", "expected"),
    [
        (f'<form action="https://evil.test/x" method="post">{LOGIN}</form>',
         {"has_external_form_action": 1, "external_form_action_count": 1,
          "password_form_external_action": 1}),
        ('<form action="https://evil.test/x" method="post"><input name="q"></form>',
         {"has_external_form_action": 1, "password_form_external_action": 0}),
        (f'<form action="/login" method="post">{LOGIN}</form>',
         {"has_external_form_action": 0, "password_form_external_action": 0}),
        (f'<form action="https://submit-form.com/abc" method="post">{LOGIN}</form>',
         {"form_action_to_known_form_service": 1, "password_form_external_action": 1}),
        (f'<form action="https://api.formspree.io/f/x" method="post">{LOGIN}</form>',
         {"form_action_to_known_form_service": 1}),
        (f'<form action="http://203.0.113.7/post.php" method="post">{LOGIN}</form>',
         {"form_action_to_ip": 1}),
        (f'<form action="" method="post">{LOGIN}</form>', {"form_action_empty_or_js": 1}),
        (f'<form action="#" method="post">{LOGIN}</form>', {"form_action_empty_or_js": 1}),
        (f'<form action="javascript:send()">{LOGIN}</form>', {"form_action_empty_or_js": 1}),
        (f"<form>{LOGIN}</form>",
         {"form_action_empty_or_js": 1, "form_method_get_with_password": 1}),
        (f'<form action="/l" method="post">{LOGIN}</form>',
         {"form_action_empty_or_js": 0, "form_method_get_with_password": 0,
          "form_action_to_ip": 0, "form_action_to_known_form_service": 0}),
    ],
)  # fmt: skip
def test_form_actions(form, expected):
    f = features_of(page(form))
    for name, value in expected.items():
        assert f[name] == value, name


def test_unknown_page_url_zeroes_external_features_but_not_others():
    form = f'<form action="https://submit-form.com/abc" method="post">{LOGIN}</form>'
    links = '<a href="https://other.test/">x</a><a href="#">y</a>'
    f = features_of(page(form + links), url=None)
    assert f["base_url_known"] == 0
    assert f["has_external_form_action"] == 0 and f["password_form_external_action"] == 0
    assert f["external_link_count"] == 0 and f["external_link_ratio"] == 0.0
    assert f["internal_link_count"] == 0 and f["distinct_external_domains"] == 0
    # facts that do not depend on the page's own address are still there
    assert f["form_action_to_known_form_service"] == 1
    assert f["null_link_count"] == 1 and f["link_count"] == 2
    assert features_of(page(form), url=URL)["base_url_known"] == 1


# ---- 9-11: iframes, scripts, hidden elements -----------------------------------------------------


def test_iframes():
    body = (
        '<iframe src="/same"></iframe>'
        '<iframe src="https://ads.test/x"></iframe>'
        '<iframe src="https://evil.test/x" width="0" height="0"></iframe>'
        '<iframe src="/hidden" style="display:none"></iframe>'
        '<embed src="https://x.test/a.swf">'
    )
    f = features_of(page(body))
    assert f["iframe_count"] == 4  # <embed> is not an iframe
    assert f["external_iframe_count"] == 2
    assert f["hidden_iframe_count"] == 2


def test_scripts_are_counted_not_interpreted():
    body = (
        "<script>var a = 1;</script><script>eval(atob('x'))</script>"
        '<script type="application/ld+json">{"a": 1}</script>'
        '<script src="/app.js"></script><script src="https://cdn.a.test/x.js"></script>'
        '<script src="https://cdn.a.test/y.js"></script><script src="https://b.test/z.js"></script>'
        '<button onclick="go()">x</button><body onload="init()"></body>'
        '<a href="javascript:void(0)">j</a>'
    )
    f = features_of(page(body))
    assert f["inline_script_count"] == 2  # JSON-LD is data, not code
    assert f["external_script_count"] == 4
    assert f["external_script_domain_count"] == 2  # a.test, b.test
    assert f["inline_script_chars_total"] == len("var a = 1;") + len("eval(atob('x'))")
    assert f["event_handler_count"] >= 1
    assert f["javascript_url_count"] == 1


def test_hidden_elements_each_method_once():
    result = dom_features_for_html(fixture("hidden_elements.html"), URL)
    f = result.features
    assert f["hidden_element_count"] == 9
    evidence = next(e for e in result.evidence if e.feature == "hidden_element_count")
    assert evidence.details["by_method"] == {
        "hidden attribute": 1,
        "aria-hidden": 1,
        "inline style": 4,
        "zero size": 1,
        "off-screen": 2,
    }
    assert f["hidden_text_chars"] > 0 and 0 < f["hidden_text_ratio"] < 1


# ---- 12: links -----------------------------------------------------------------------------------


def test_link_ratios_and_null_links():
    body = (
        '<a href="/a">a</a><a href="https://bank.example/b">b</a>'
        '<a href="https://www.brand.test/1">c</a><a href="https://brand.test/2">d</a>'
        '<a href="https://other.test/">e</a>'
        '<a href="#">f</a><a href="">g</a><a href="javascript:void(0)">h</a>'
        '<a href="mailto:x@y.test">m</a>'
    )
    f = features_of(page(body))
    assert f["link_count"] == 9
    assert f["internal_link_count"] == 2 and f["external_link_count"] == 3
    assert f["external_link_ratio"] == pytest.approx(3 / 5)
    assert f["null_link_count"] == 3 and f["null_link_ratio"] == pytest.approx(3 / 9, abs=1e-4)
    assert f["distinct_external_domains"] == 2


def test_zero_links_no_division_error():
    f = features_of(page("<p>no links</p>"))
    assert f["link_count"] == 0
    assert f["external_link_ratio"] == 0.0 and f["null_link_ratio"] == 0.0


def test_meta_resources():
    head = (
        '<title>Bank</title><meta http-equiv="refresh" content="0;url=https://evil.test/">'
        '<link rel="stylesheet" href="/a.css"><link rel="stylesheet" href="https://cdn.test/b.css">'
    )
    f = features_of(page("<p>x</p>", head))
    assert f["has_meta_refresh"] == 1 and f["meta_refresh_external"] == 1
    assert f["external_stylesheet_ratio"] == pytest.approx(0.5)
    assert f["has_title"] == 1 and f["title_length"] == 4
    assert features_of(page("<p>x</p>", ""))["has_title"] == 0


# ---- 13: the vector ------------------------------------------------------------------------------


def test_vector_length_order_and_finite():
    yaml_names = [item["name"] for item in load_yaml_config("dom_features")["features"]]
    assert list(feature_names()) == yaml_names  # dictionary order IS the vector order
    assert feature_names() == feature_names()  # stable
    for html in (fixture("credentials.html"), fixture("hidden_elements.html"), page("")):
        result = dom_features_for_html(html, URL)
        assert list(result.features) == yaml_names
        assert all(math.isfinite(value) for value in to_list(result.features))
        assert len(to_list(result.features)) == len(yaml_names)
    binary = [s.name for s in load_dictionary().features if s.type == "binary"]
    values = dom_features_for_html(fixture("credentials.html"), URL).features
    assert all(values[name] in (0, 1) for name in binary)


def test_build_vector_rejects_bad_input():
    good = {name: 0 for name in feature_names()}
    assert list(build_vector(good)) == list(feature_names())
    with pytest.raises(FeatureVectorError, match="missing"):
        build_vector({k: v for k, v in good.items() if k != "node_count"})
    with pytest.raises(FeatureVectorError, match="unknown"):
        build_vector({**good, "made_up": 1})
    with pytest.raises(FeatureVectorError, match="finite"):
        build_vector({**good, "avg_depth": float("nan")})
    with pytest.raises(FeatureVectorError, match="0 or 1"):
        build_vector({**good, "has_form": 2})


def test_dictionary_validation():
    raw = load_yaml_config("dom_features")
    duplicate = {**raw, "features": raw["features"] + [raw["features"][0]]}
    with pytest.raises(ValueError, match="duplicate"):
        dom_dictionary._validate(duplicate)
    bad_group = {**raw, "features": [{**raw["features"][0], "group": "nope"}]}
    with pytest.raises(ValueError, match="unknown group"):
        dom_dictionary._validate(bad_group)
    for spec in load_dictionary().features:
        assert spec.description and spec.source  # every feature explains itself (viva)


def test_failing_group_is_isolated(monkeypatch):
    def broken(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(dom_pipeline, "link_features", broken)
    result = dom_features_for_html(page('<a href="/x">x</a><form><input></form>'), URL)
    assert any("links/meta_resources: RuntimeError: boom" in e for e in result.errors)
    assert list(result.features) == list(feature_names())  # still complete
    assert result.features["link_count"] == 0 and result.features["form_count"] == 1


# ---- evidence ------------------------------------------------------------------------------------


def test_evidence_only_for_nonzero_features_with_template():
    result = dom_features_for_html(
        (SAMPLES / "phishing_external_form.html").read_text("utf-8"), URL
    )
    specs = {s.name: s for s in load_dictionary().features}
    assert result.evidence
    for item in result.evidence:
        assert result.features[item.feature] != 0
        assert specs[item.feature].evidence is not None
    strong = next(e for e in result.evidence if e.feature == "password_form_external_action")
    assert strong.severity == "high"
    assert strong.message == "Password form submits to external domain example-attacker.test"
    assert strong.details["domain"] == "example-attacker.test"
    assert result.evidence[0].severity == "high"  # most severe first

    benign = dom_features_for_html((SAMPLES / "benign_simple.html").read_text("utf-8"), URL)
    assert all(item.severity != "high" for item in benign.evidence)


def test_ratio_evidence_respects_min_value():
    few = page('<a href="https://o.test/">x</a>' + '<a href="/i">i</a>' * 9)
    assert not [e for e in dom_features_for_html(few, URL).evidence
                if e.feature == "external_link_ratio"]  # fmt: skip
    many = page('<a href="https://o.test/">x</a>' * 9 + '<a href="/i">i</a>')
    item = next(e for e in dom_features_for_html(many, URL).evidence
                if e.feature == "external_link_ratio")  # fmt: skip
    assert item.message.startswith("90% of web links point to other domains")


def test_existing_fixtures():
    phishing = features_of((SAMPLES / "phishing_external_form.html").read_text("utf-8"))
    assert phishing["has_external_form_action"] == 1
    assert phishing["password_form_external_action"] == 1
    benign = features_of((SAMPLES / "benign_simple.html").read_text("utf-8"))
    assert benign["has_external_form_action"] == 0
    assert benign["password_form_external_action"] == 0


# ---- 14: batch, CSV, report, CLI text ------------------------------------------------------------


@pytest.fixture
def frozen_store(tmp_path: Path) -> MetadataStore:
    store = MetadataStore(tmp_path / "metadata" / "metadata.csv", tmp_path / "raw")
    pages = [
        ("phishing_external_form.html", "phishing"),
        ("benign_simple.html", "benign"),
        ("sinhala_urgency.html", "phishing"),
    ]
    for number, (name, label) in enumerate(pages, 1):
        source = tmp_path / f"in_{number}.html"
        source.write_bytes((SAMPLES / name).read_bytes())
        record, _ = register_file(store, source, label, "en", "manual", f"https://p{number}.ex/")
        store.update(record.sample_id, cluster_id=f"cl_{number:06d}")
    store.update(
        "c2_phishing_000001", verified=True, verified_by="T", verification_date=date.today()
    )
    store.save()
    freeze(store, "v0.1")
    return store


def run(store: MetadataStore, tmp_path: Path, **kwargs):
    return run_version(
        store,
        "v0.1",
        workers=1,
        out_dir=tmp_path / "dom",
        parsed_dir=tmp_path / "parsed",
        show_progress=False,
        **kwargs,
    )


def test_batch_writes_csv_json_dictionary_and_skips(frozen_store, tmp_path):
    results, _, rows, csv_path = run(frozen_store, tmp_path)
    assert sorted(r["status"] for r in results) == ["processed"] * 3
    assert all(r["part2"] == "processed" for r in results)  # Part 2 was missing -> run + saved
    assert len(list((tmp_path / "parsed").glob("*.json"))) == 3

    table = pd.read_csv(csv_path)
    assert list(table.columns) == csv_columns() == ID_COLUMNS + list(feature_names())
    assert len(table) == 3 and set(table["cluster_id"]) == {"cl_000001", "cl_000002", "cl_000003"}
    row = table.set_index("sample_id").loc["c2_phishing_000001"]
    assert row["password_form_external_action"] == 1

    stored = json.loads((tmp_path / "dom" / "c2_phishing_000001.json").read_text("utf-8"))
    assert stored["feature_set_version"] == "dom_v1" and stored["evidence"]
    dictionary = json.loads((tmp_path / "dom" / "feature_dictionary.json").read_text("utf-8"))
    assert [f["name"] for f in dictionary["features"]] == list(feature_names())

    again, _, _, _ = run(frozen_store, tmp_path)
    assert [r["status"] for r in again] == ["skipped"] * 3
    forced, _, _, _ = run(frozen_store, tmp_path, force=True)
    assert [r["status"] for r in forced] == ["processed"] * 3
    assert all(r["part2"] == "stored" for r in forced)

    # a --label run must not shrink the CSV
    _, _, rows, csv_path = run(frozen_store, tmp_path, label="benign", force=True)
    assert len(pd.read_csv(csv_path)) == 3


def test_report_summary_and_texts(frozen_store, tmp_path):
    results, seconds, rows, _ = run(frozen_store, tmp_path)
    summary = summarize(rows, results, "v0.1", seconds, {})
    assert summary["counts"]["rows_in_csv"] == 3
    assert summary["labels"] == ["benign", "phishing"]
    assert summary["per_label"]["phishing"]["pages"] == 2
    assert "base_url_known" in summary["warnings"]["constant_features"]
    assert summary["separation"] and len(summary["top_separating"]) <= 12
    assert all(math.isfinite(row["mutual_information"]) for row in summary["separation"])

    result = dom_features_for_html(fixture("credentials.html"), URL)
    text = describe_result(result, "phishing")
    assert "[credentials]" in text and "password_form_external_action" in text
    assert "[HIGH" in text
    assert "base_url_known" in describe_dictionary()


# ---- API = CLI -----------------------------------------------------------------------------------


def test_public_api_matches_pipeline():
    client = TestClient(create_app("production"))
    html = fixture("credentials.html")
    response = client.post("/api/v1/dom-features", json={"html": html, "url": URL})
    assert response.status_code == 200
    assert response.json()["features"] == dom_features_for_html(html, URL).features
    too_big = client.post("/api/v1/dom-features", json={"html": "a" * (5 * 1024 * 1024 + 1)})
    assert too_big.status_code == 413


def test_dev_endpoint_matches_batch(frozen_store, tmp_path):
    run(frozen_store, tmp_path)
    dataset = DevDataset(
        manifests_dir(frozen_store),
        tmp_path / "parsed_root",
        frozen_store.raw_dir,
        metadata_csv=frozen_store.csv_path,
        dom_root=tmp_path,  # <root>/<version>/ -> the batch wrote to tmp_path/"dom"
    )
    (tmp_path / "v0.1").mkdir()
    for path in (tmp_path / "dom").glob("*.json"):
        (tmp_path / "v0.1" / path.name).write_bytes(path.read_bytes())
    app = create_app("development")
    app.dependency_overrides[get_dev_dataset] = lambda: dataset
    client = TestClient(app)

    stored = client.get("/api/v1/dev/samples/c2_phishing_000001/dom-features")
    assert stored.status_code == 200 and stored.headers["x-features-source"] == "stored"
    batch_json = json.loads((tmp_path / "dom" / "c2_phishing_000001.json").read_text("utf-8"))
    assert stored.json()["features"] == batch_json["features"]

    (tmp_path / "v0.1" / "c2_phishing_000001.json").unlink()
    fresh = client.get("/api/v1/dev/samples/c2_phishing_000001/dom-features")
    assert fresh.headers["x-features-source"] == "on-the-fly"
    assert fresh.json()["features"] == batch_json["features"]  # same numbers either way

    info = client.get("/api/v1/dev/dom-dictionary").json()
    assert [f["name"] for f in info["features"]] == list(feature_names())
    assert client.get("/api/v1/dev/samples/c2_phishing_999999/dom-features").status_code == 404
    assert TestClient(create_app("production")).get("/api/v1/dev/dom-dictionary").status_code == 404
