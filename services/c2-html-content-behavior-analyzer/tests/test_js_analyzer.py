"""Tests for Part 7: Static JavaScript intent analyzer.

Why: Part 8 builds intent on these detections, so each task (5-15) is pinned on
a fixture that also contains the ALIASES attackers use and the look-alikes that
must NOT be reported. The safety limits (size, time, depth, broken code, no
tree-sitter) must never crash, library code must stay out of the page-own
counts, and the batch / CSV / API / CLI paths must give the same numbers.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import json
from collections import Counter
from datetime import date
from pathlib import Path

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from c2_analyzer.api.dependencies import get_dev_dataset
from c2_analyzer.api.dev_data import DevDataset
from c2_analyzer.api.main import create_app
from c2_analyzer.dataset.collector import register_file
from c2_analyzer.dataset.manifest import freeze, manifests_dir
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.js_analyzer import ast_parser
from c2_analyzer.js_analyzer.ast_parser import parse_js
from c2_analyzer.js_analyzer.batch import CSV_NAME, DICTIONARY_NAME, ID_COLUMNS, run_version
from c2_analyzer.js_analyzer.detectors import PageUrls
from c2_analyzer.js_analyzer.extractor import CodeUnit
from c2_analyzer.js_analyzer.lexical_scanner import blank_comments, scan
from c2_analyzer.js_analyzer.obfuscation import string_lengths
from c2_analyzer.js_analyzer.pipeline import analyze_js, analyze_unit, js_analysis_for_html
from c2_analyzer.js_analyzer.report import describe_dictionary, describe_result, summarize
from c2_analyzer.js_analyzer.rules import feature_names, load_rules
from c2_analyzer.preprocessing.loader import from_string
from c2_analyzer.preprocessing.pipeline import preprocess
from c2_analyzer.schemas.js import JsAnalysisResult

ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / "tests" / "fixtures" / "js"
SAMPLES = ROOT / "tests" / "fixtures" / "sample_pages"
SCRIPT = ROOT / "scripts" / "analyze_js.py"
URL = "https://bank.example/login"


def js(name: str) -> str:
    return (JS / name).read_text(encoding="utf-8")


def analyze(code: str, url: str | None = URL, extra_html: str = "") -> JsAnalysisResult:
    return js_analysis_for_html(
        f"<html><body>{extra_html}<script>{code}</script></body></html>", url
    )


def tally(result: JsAnalysisResult) -> Counter:
    return Counter((d.api, d.access) for d in result.detections)


def apis(result: JsAnalysisResult, api: str) -> list:
    return [d for d in result.detections if d.api == api]


# ---- tasks 1-4: inputs and parsing -----------------------------------------------------


def test_inputs_come_from_part2_handlers_and_javascript_urls():
    html = (
        '<script type="application/ld+json">{"eval": "x"}</script>'
        "<script>var ok = 1;</script>"
        '<body oncontextmenu="return false"><button onclick="document.cookie=\'a=1\'">x</button>'
        '<a href="javascript:location.replace(%27https://x.evil.test/%27)">go</a>'
        '<script src="https://cdn.jsdelivr.net/npm/jquery@3/dist/jquery.min.js" async></script>'
        '<script src="http://203.0.113.9/kit.js"></script>'
        '<script src="https://kit.pages.dev/a.js" integrity="sha384-x"></script>'
        '<script src="data:text/javascript,alert(1)"></script></body>'
    )
    result = js_analysis_for_html(html, URL)
    sources = Counter(s.source for s in result.scripts)
    assert sources == {"inline": 1, "event_handler": 2, "javascript_url": 1}  # JSON-LD excluded
    assert ("contextmenu_listener", "listener") in tally(result)  # the attribute itself
    cookie = apis(result, "document.cookie")[0]
    assert cookie.source == "event_handler" and cookie.access == "write"
    replace = apis(result, "location.replace")[0]
    assert replace.source == "javascript_url" and replace.args.url_is_external  # %27 decoded
    external = {
        s.src.split("/")[2] if "//" in s.src else "data": s for s in result.external_scripts
    }
    assert external["data"].flags == ["data_url"]
    assert (
        external["cdn.jsdelivr.net"].known_cdn and external["cdn.jsdelivr.net"].library == "jQuery"
    )
    assert external["cdn.jsdelivr.net"].is_async
    assert external["203.0.113.9"].flags == ["raw_ip", "insecure_http"]
    assert (
        external["kit.pages.dev"].flags == ["free_hosting"]
        and external["kit.pages.dev"].has_integrity
    )
    assert all(s.suspicious_host for s in result.external_scripts if not s.known_cdn)
    assert result.features["external_script_suspicious_host_count"] == 3
    assert any("not downloaded" in line for line in result.limitations)


def test_modern_syntax_parses_cleanly():
    result = analyze(js("modern.js"))
    script = result.scripts[0]
    assert script.parser == "tree-sitter" and not script.has_error and script.error_ratio == 0
    fetch = apis(result, "fetch")[0]
    assert fetch.confidence == "high" and fetch.args.http_method == "POST"
    assert fetch.args.first_arg_kind == "template" and fetch.args.url is None  # host is dynamic
    assert fetch.enclosing_function == "send"


def test_broken_js_falls_back_to_lexical_low_confidence():
    result = analyze(js("broken.js"))
    script = result.scripts[0]
    assert script.parser == "lexical" and not script.parsed_ok and script.error_ratio > 0.5
    found = {(d.api, d.access, d.confidence) for d in result.detections}
    assert {("document.cookie", "write", "low"), ("eval", "call", "low")} <= found
    assert ("fetch", "call", "low") in found
    assert result.features["parse_failure_ratio"] == 1.0
    assert result.summary.flags["parse_fallback_used"]


def test_missing_tree_sitter_uses_the_lexical_scanner(monkeypatch):
    monkeypatch.setattr(ast_parser, "_parser", lambda: None)
    result = analyze(js("cookie.js"))
    assert result.scripts[0].parser == "lexical"
    assert all(d.confidence == "low" for d in result.detections)
    assert Counter(d.access for d in apis(result, "document.cookie")) == {"read": 2, "write": 3}


def test_huge_script_is_truncated_not_skipped():
    code = "var a = 1;\n" * 60_000 + "eval(x);"  # 660 KB, eval beyond the cap
    outcome = parse_js(code, max_bytes=500_000)
    assert outcome.truncated and len(outcome.source) <= 500_000 and outcome.usable
    result = analyze(code)
    assert result.scripts[0].truncated and result.features["truncated_script_count"] == 1
    assert not apis(result, "eval")  # the part after the limit is not analysed


def test_truncated_inside_a_string_is_cut_back_to_a_statement():
    code = "var ok = fetch('/a');\n" * 15_000 + "var s = '" + "x" * 600_000 + "';"
    outcome = parse_js(code, max_bytes=500_000)
    assert outcome.truncated and outcome.usable and outcome.text.endswith("\n")
    assert apis(analyze(code), "fetch")


def test_parse_timeout_is_handled():
    code = "var a = [" + ",".join(f'"s{i}"' for i in range(40_000)) + "];"  # ~350 KB
    outcome = parse_js(code, timeout_ms=0.001)
    assert outcome.timed_out and outcome.tree is None and not outcome.usable
    rules = load_rules()
    fast = dataclasses.replace(rules, limits={**rules.limits, "parse_timeout_ms": 0.001})
    unit = CodeUnit(source="inline", origin="script #0 (body)", text=code + "eval(1)", chars=0)
    info, found, _ = analyze_unit(unit, 0, fast, PageUrls(URL, URL))
    assert info.timed_out and info.parser == "lexical"
    assert [d.api for d in found] == ["eval"] and found[0].confidence == "low"
    assert parse_js(code).usable  # the normal limit is plenty


def test_deep_nesting_does_not_crash():
    code = "x = " + "(" * 5000 + "1" + ")" * 5000 + "; eval(y);"
    result = analyze(code)
    assert result.meta.errors == []
    assert apis(result, "eval") or result.scripts[0].depth_capped


# ---- tasks 5-15: detectors (with aliases and look-alikes) ---------------------------------


def test_task5_eval_aliases_and_string_timers():
    result = analyze(js("eval_aliases.js"))
    counts = tally(result)
    assert counts[("eval", "call")] == 9  # direct + 8 aliases, not the string / comment
    assert counts[("execScript", "call")] == 1
    assert (
        counts[("setTimeout_string", "call")] == 2 and counts[("setInterval_string", "call")] == 1
    )
    callees = {d.callee for d in apis(result, "eval")}
    assert {"window.eval", "(0, eval)", "e (alias of eval)", "eval.call", "self.eval"} <= callees
    assert result.features["eval_count"] == 10 and result.features["string_timer_count"] == 3


def test_task6_function_constructor():
    result = analyze(js("function_constructor.js"))
    found = apis(result, "Function")
    assert len(found) == 5  # not this.constructor(a, b)
    assert not any("this.constructor" in (d.callee or "") for d in found)
    assert result.features["function_constructor_count"] == 5


def test_task7_document_write():
    result = analyze(js("document_write.js"))
    assert tally(result) == {("document.write", "call"): 2, ("document.writeln", "call"): 1}


def test_task8_innerhtml_and_friends():
    result = analyze(js("innerhtml.js"))
    counts = tally(result)
    assert counts[("innerHTML", "assign")] == 2  # = and +=, not the read
    assert counts[("outerHTML", "assign")] == 1 and counts[("insertAdjacentHTML", "call")] == 1
    assert counts[("srcdoc", "assign")] == 2  # property and setAttribute
    assert apis(result, "innerHTML")[0].selector == "#box"
    assert result.features["innerhtml_assign_count"] == 6


def test_task9_fetch_beacons_sockets():
    result = analyze(js("network_fetch.js"))
    fetches = apis(result, "fetch")
    assert len(fetches) == 3
    first = fetches[0]
    assert first.args.url_domain == "evil.test" and first.args.url_is_external
    assert first.args.http_method == "POST" and first.args.identifiers_used == ["user"]
    assert fetches[1].args.url == "https://bank.example/api/local"
    assert fetches[1].args.url_is_external is False
    assert len(apis(result, "image_beacon")) == 2  # not logo.src = "/logo.png"
    assert apis(result, "WebSocket")[0].args.url_is_external
    assert apis(result, "WebSocket")[0].assigned_to == "socket"
    features = result.features
    assert features["beacon_count"] == 3 and features["websocket_count"] == 2
    assert features["external_request_count"] == 5  # fetch, beacon, socket, 2 image beacons


def test_task10_xhr():
    result = analyze(js("xhr.js"))
    opened = apis(result, "xhr.open")[0]
    assert opened.args.http_method == "POST" and opened.args.url_is_external
    assert opened.target == "xhr"
    sent = apis(result, "xhr.send")[0]
    assert sent.args.identifiers_used == ["user", "pass"]
    assert len(apis(result, "XMLHttpRequest")) == 2  # incl. ActiveXObject
    ajax = apis(result, "jquery.ajax")
    assert [d.args.http_method for d in ajax] == ["POST", "POST", "GET"]
    assert result.features["xhr_count"] == 5


def test_task11_form_submission():
    result = analyze(js("form_submit.js"))
    counts = tally(result)
    assert counts[("form.submit", "call")] == 3 and counts[("form.requestSubmit", "call")] == 1
    assert counts[("submit_event", "call")] == 2 and counts[("submit_listener", "listener")] == 1
    actions = apis(result, "form.action")
    assert len(actions) == 2 and actions[0].selector == "forms[pay]"
    assert actions[0].args.url_is_external and actions[1].args.url_is_external is False
    assert apis(result, "form.submit")[0].selector == "forms[0]"
    assert result.features["form_submit_count"] == 6


def test_task12_redirects():
    result = analyze(js("redirects.js"))
    counts = tally(result)
    assert counts[("location.href", "assign")] == 5  # not location.hash = / reading location.href
    assert counts[("location.assign", "call")] == 1 and counts[("location.replace", "call")] == 2
    assert counts[("window.open", "call")] == 1 and counts[("meta_refresh", "assign")] == 2
    assert counts[("history.pushState", "call")] == 1  # only the external one
    top = [d for d in apis(result, "location.href") if d.target == "top"]
    assert len(top) == 1 and top[0].callee == "top.location.href"
    features = result.features
    assert features["redirect_count"] == 12 and features["external_redirect_count"] == 7
    assert features["location_replace_count"] == 2


def test_task13_cookie_read_vs_write():
    result = analyze(js("cookie.js"))
    assert tally(result) == {("document.cookie", "read"): 2, ("document.cookie", "write"): 3}
    assert apis(result, "document.cookie")[0].assigned_to == "all"
    assert result.features["cookie_read_count"] == 2 and result.features["cookie_write_count"] == 3


def test_task14_storage_methods_properties_brackets_and_aliases():
    result = analyze(js("storage.js"))
    counts = tally(result)
    assert counts[("localStorage", "write")] == 4 and counts[("localStorage", "read")] == 2
    assert counts[("sessionStorage", "write")] == 1 and counts[("sessionStorage", "read")] == 2
    members = {d.member for d in apis(result, "localStorage")}
    assert {"setItem", "getItem", "user", "removeItem", "theme"} <= members
    assert any(d.callee.startswith("store.getItem") for d in apis(result, "sessionStorage"))
    assert (
        result.features["storage_read_count"] == 4 and result.features["storage_write_count"] == 5
    )


def test_task15_clipboard():
    result = analyze(js("clipboard.js"), extra_html='<div oncopy="track()">x</div>')
    counts = tally(result)
    assert counts[("navigator.clipboard.writeText", "write")] == 1
    assert counts[("navigator.clipboard.readText", "read")] == 1
    assert counts[("document.execCommand", "write")] == 1  # copy, not bold
    assert counts[("document.execCommand", "read")] == 1  # paste
    assert counts[("clipboard_event", "listener")] == 3  # addEventListener, oncut =, oncopy attr
    assert counts[("clipboardData.setData", "write")] == 1
    assert counts[("clipboardData.getData", "read")] == 1
    setter = apis(result, "clipboardData.setData")[0]
    assert setter.enclosing_function == "<callback: addEventListener copy>"
    features = result.features
    assert features["clipboard_write_count"] == 3 and features["clipboard_read_count"] == 3
    assert features["clipboard_listener_count"] == 3


def test_credential_reads_listeners_decoders_downloads():
    code = """
    var field = document.getElementById("password");
    var pw = field.value;
    var em = document.querySelector("input[type=email]").value;
    var card = $("#cc_number").val();
    var count = stats.value;              // unknown object: not an input read
    var it = gen.next().value;            // iterator: not an input read
    var fd = new FormData(document.forms["login"]);
    document.addEventListener("keydown", function (e) { log(e.key); });
    window.onbeforeunload = function () { return "stay"; };
    document.oncontextmenu = function () { return false; };
    var s = atob("aGk=") + String.fromCharCode(104, 105) + unescape("%41");
    var hidden = "\\x65\\x76\\x61\\x6c\\x20\\x61\\x6c\\x65\\x72\\x74\\x31";
    var arabic = "\\u0627\\u0644\\u0644\\u063a\\u0629\\u0627\\u0644\\u0639\\u0631\\u0628";
    var a = document.createElement("a"); a.download = "invoice.exe";
    a.href = URL.createObjectURL(new Blob([data]));
    navigator.msSaveBlob(blob, "x.exe");
    """
    result = analyze(code)
    reads = apis(result, "input.value")
    assert [(d.selector, d.assigned_to, d.credential_hint) for d in reads] == [
        ("#password", "pw", True),  # through the element alias
        ("input[type=email]", "em", True),
        ("#cc_number", "card", True),
    ]
    assert apis(result, "FormData")[0].selector == "forms[login]"
    features = result.features
    assert features["input_value_read_count"] == 3 and features["credential_value_read_count"] == 3
    assert features["formdata_count"] == 1 and features["key_listener_count"] == 1
    assert features["beforeunload_listener_count"] == 1 and features["contextmenu_block_count"] == 1
    assert features["decode_call_count"] == 3
    assert features["escape_heavy_string_count"] == 1  # hidden ASCII yes, escaped Arabic no
    assert features["download_trigger_count"] == 3


def test_existing_exfiltration_fixture_reports_both_facts():
    html = (SAMPLES / "js_exfiltration.html").read_text(encoding="utf-8")
    result = js_analysis_for_html(html, URL)
    reads = apis(result, "input.value")
    assert {(d.selector, d.assigned_to) for d in reads} == {
        ("#password", "pwd"),
        ("#username", "usr"),
    }
    assert all(d.credential_hint for d in reads)
    fetch = apis(result, "fetch")[0]
    assert fetch.args.url_domain == "example-attacker.test" and fetch.args.url_is_external
    assert fetch.args.identifiers_used == ["usr", "pwd"]
    assert fetch.enclosing_function == "<callback: addEventListener submit>"
    assert apis(result, "submit_listener")[0].selector == "#login"
    flags = result.summary.flags
    assert flags["credential_value_read"] and flags["external_request"]
    # Part 7 only reports the facts; the "credential exfiltration" pattern is Part 8's
    assert "pattern" not in result.model_dump_json()


# ---- URLs, base_url, PII ---------------------------------------------------------------------


def test_external_urls_use_base_url_and_mask_pii():
    code = (
        'fetch("/collect?email=victim@mail.com&id=7");'
        'fetch("https://bank.example/ok");'
        'location.href = "https://login.bank.example/next";'
    )
    html = (
        '<html><head><base href="https://cdn.other.test/app/"></head><body>'
        f"<script>{code}</script></body></html>"
    )
    result = js_analysis_for_html(html, URL)
    relative, same, sub = apis(result, "fetch") + apis(result, "location.href")
    assert relative.args.url.startswith("https://cdn.other.test/collect?email=[EMAIL]")
    assert relative.args.url_is_external  # resolved against <base>, compared with the page
    assert "victim@mail.com" not in result.model_dump_json()
    assert "[EMAIL]" in relative.snippet and "[EMAIL]" in relative.args.literal_value
    assert same.args.url_is_external is False
    assert sub.args.url_is_external is False  # a subdomain of the same site

    unknown = js_analysis_for_html(f"<script>{code}</script>", None)
    first, second, _ = apis(unknown, "fetch") + apis(unknown, "location.href")
    assert first.args.url_is_external is None  # relative, page unknown
    assert second.args.url_is_external is True  # absolute, page unknown (Part 2 rule)


def test_snippets_are_single_line_short_and_positions_exact():
    code = "var a = 1;\n  document.write(\n  '<b>' +\n  x);\n" + "eval('" + "y" * 500 + "');"
    result = analyze(code)
    write, ev = apis(result, "document.write")[0], apis(result, "eval")[0]
    assert (write.line, write.column, write.end_line) == (2, 3, 4)
    assert "\n" not in write.snippet and write.snippet == "document.write( '<b>' + x)"
    assert len(ev.snippet) <= 200 and ev.snippet.endswith("...")
    source = result.scripts[0]
    assert source.analyzed_chars == len(code)
    assert code.encode()[write.start_byte : write.end_byte].startswith(b"document.write(")


# ---- library awareness ---------------------------------------------------------------------


def test_library_code_is_tagged_and_not_counted():
    own = 'document.getElementById("out").innerHTML = msg;'
    html = f"<script>{js('jquery_like.min.js')}</script><script>{own}</script>"
    result = js_analysis_for_html(html, URL)
    library, page = result.scripts
    assert library.library == "jQuery" and page.library is None
    lib_detections = [d for d in result.detections if d.in_library]
    assert {d.api for d in lib_detections} >= {"innerHTML", "XMLHttpRequest", "document.cookie"}
    assert result.features["innerhtml_assign_count"] == 1  # only the page's own
    assert result.features["xhr_count"] == 0 and result.features["cookie_read_count"] == 0
    assert result.features["library_script_count"] == 1
    assert result.summary.categories_library["html_injection"] == 1
    assert result.summary.libraries == ["jQuery"]
    counts = {c.api: c for c in result.counts}
    assert (counts["innerHTML"].page_own, counts["innerHTML"].library) == (1, 1)


def test_snippet_library_needs_a_short_script():
    gtm = "(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':new Date().getTime()});})"
    assert (
        js_analysis_for_html(f"<script>{gtm}</script>").scripts[0].library == "Google Tag Manager"
    )
    padded = gtm + ";" + "document.cookie = 'x';" * 400  # a kit hiding behind the snippet
    result = js_analysis_for_html(f"<script>{padded}</script>")
    assert result.scripts[0].library is None and result.features["cookie_write_count"] == 400


# ---- obfuscation statistics -------------------------------------------------------------------


def test_obfuscation_separates_minified_from_packed():
    minified = analyze(js("jquery_like.min.js")).scripts[0].obfuscation
    packed = analyze(js("packed.js")).scripts[0].obfuscation
    assert minified.minified and minified.signatures == []
    assert {"packer", "hex_identifiers"} <= set(packed.signatures)
    assert packed.hex_identifier_ratio > 0.2 > minified.hex_identifier_ratio
    assert packed.escape_ratio > minified.escape_ratio
    plain = analyze(js("redirects.js")).scripts[0].obfuscation
    assert not plain.minified and plain.signatures == [] and plain.lines > 10


def test_obfuscation_string_array_jsfuck_and_escapes():
    array = "var _0xab12=[" + ",".join(f"'s{i}'" for i in range(120)) + "];"
    stats = analyze(array + "_0xab12[0x1];").scripts[0].obfuscation
    assert stats.string_array_size == 120 and "string_array" in stats.signatures
    jsfuck = "[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]]" * 40
    assert "jsfuck" in analyze(jsfuck).scripts[0].obfuscation.signatures
    escaped_text = '"' + "\\u0627\\u0644" * 200 + '"'  # escaped Arabic is not hiding
    assert analyze(escaped_text).scripts[0].obfuscation.escape_ratio == 0


def test_string_scanner_is_linear_on_broken_quotes():
    assert string_lengths('a = "abc"; b = \'x\\\'y\'; c = "open\nd="ok"') == [3, 4, 2]
    assert string_lengths('"' + 'a\\"' * 200_000) == []  # used to take minutes


def test_lexical_fallback_ignores_comments_but_not_strings():
    code = 'x = "http://a.test/eval(";  // eval(1)\n/* document.cookie = 1 */ eval(2)'
    blanked = blank_comments(code)
    assert len(blanked) == len(code) and blanked.count("\n") == 1
    assert "http://a.test/eval(" in blanked and "eval(1)" not in blanked and "eval(2)" in blanked
    rules = load_rules()
    found = scan(code, rules, 0, "inline", PageUrls(URL, URL))
    assert [(d.api, d.line) for d in found] == [("eval", 1), ("eval", 2)]  # string + real call
    assert blank_comments("'" + 'a"b' * 200_000)  # unclosed quotes: still fast


# ---- feature vector, batch, CSV, report ---------------------------------------------------


def test_vector_matches_the_dictionary_and_is_finite():
    names = list(feature_names())
    assert len(names) == len(set(names)) == len(load_rules().features)
    for code in (js("eval_aliases.js"), js("broken.js"), ""):
        values = analyze(code).features
        assert list(values) == names
        assert all(isinstance(v, (int, float)) and v == v for v in values.values())
    empty = js_analysis_for_html("<p>no scripts</p>")
    assert all(v == 0 for v in empty.features.values()) and empty.scripts == []


@pytest.fixture
def frozen_store(tmp_path: Path) -> MetadataStore:
    store = MetadataStore(tmp_path / "metadata" / "metadata.csv", tmp_path / "raw")
    pages = [("js_exfiltration.html", "phishing"), ("benign_simple.html", "benign")]
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
        out_dir=tmp_path / "js",
        parsed_dir=tmp_path / "parsed",
        show_progress=False,
        **kwargs,
    )


def test_batch_csv_dictionary_skip_and_report(frozen_store, tmp_path):
    results, seconds, rows, csv_path = run(frozen_store, tmp_path)
    assert sorted(r["status"] for r in results) == ["processed", "processed"]
    assert all(r["part2"] == "processed" for r in results)
    table = pd.read_csv(csv_path)
    assert csv_path.name == CSV_NAME
    assert list(table.columns) == ID_COLUMNS + list(feature_names())
    row = table.set_index("sample_id").loc["c2_phishing_000001"]
    assert row["credential_value_read_count"] == 2 and row["external_request_count"] == 1
    dictionary = json.loads((tmp_path / "js" / DICTIONARY_NAME).read_text("utf-8"))
    assert [f["name"] for f in dictionary["features"]] == list(feature_names())

    again, _, _, _ = run(frozen_store, tmp_path)
    assert [r["status"] for r in again] == ["skipped", "skipped"]
    forced, _, _, _ = run(frozen_store, tmp_path, force=True)
    assert [r["status"] for r in forced] == ["processed", "processed"]
    _, _, _, csv_path = run(frozen_store, tmp_path, label="benign", force=True)
    assert len(pd.read_csv(csv_path)) == 2  # a --label run never shrinks the CSV

    summary = summarize(rows, results, "v0.1", seconds, {})
    assert summary["labels"] == ["benign", "phishing"]
    phishing = summary["per_label"]["phishing"]
    assert phishing["category_pct"]["network_fetch"] == 100.0
    assert phishing["category_pct"]["credential_access"] == 100.0
    assert summary["parsing"]["parse_success_rate"] == 100.0
    assert summary["top_apis"][0]["api"] == "input.value"


def test_describe_texts():
    result = js_analysis_for_html((SAMPLES / "js_exfiltration.html").read_text("utf-8"), URL)
    text = describe_result(result, "phishing")
    assert "network_fetch" in text and "line 6:7" in text and "EXTERNAL" in text
    assert "selector #password" in text and "-> pwd" in text
    assert "eval_count" in describe_dictionary() and "| `eval_count` |" in describe_dictionary(True)


# ---- API == CLI == batch --------------------------------------------------------------------


def test_public_api_matches_pipeline_and_cli(tmp_path, capsys):
    spec = importlib.util.spec_from_file_location("analyze_js_cli", SCRIPT)
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    html = (SAMPLES / "js_exfiltration.html").read_text(encoding="utf-8")
    client = TestClient(create_app("production"))
    response = client.post("/api/v1/js-analysis", json={"html": html, "url": URL})
    assert response.status_code == 200
    body = response.json()
    expected = analyze_js(preprocess(from_string(html, URL)))
    assert body["features"] == expected.features
    assert [d["api"] for d in body["detections"]] == [d.api for d in expected.detections]
    assert (
        client.post("/api/v1/js-analysis", json={"html": "a" * (5 * 1024 * 1024 + 1)}).status_code
        == 413
    )
    examples = client.get("/openapi.json").json()["components"]["schemas"]["JsAnalysisRequest"]
    assert examples["examples"]

    page = tmp_path / "page.html"
    page.write_bytes(html.encode("utf-8"))  # write_text would turn \n into \r\n on Windows
    assert cli.main(["one", "--file", str(page), "--url", URL, "--json"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["features"] == body["features"]


def test_dev_endpoint_stored_and_on_the_fly(frozen_store, tmp_path):
    run(frozen_store, tmp_path)
    dataset = DevDataset(
        manifests_dir(frozen_store),
        tmp_path / "parsed_root",
        frozen_store.raw_dir,
        metadata_csv=frozen_store.csv_path,
        js_root=tmp_path,  # <root>/<version>/
    )
    (tmp_path / "v0.1").mkdir()
    for path in (tmp_path / "js").glob("c2_*.json"):
        (tmp_path / "v0.1" / path.name).write_bytes(path.read_bytes())
    app = create_app("development")
    app.dependency_overrides[get_dev_dataset] = lambda: dataset
    client = TestClient(app)
    stored = client.get("/api/v1/dev/samples/c2_phishing_000001/js-analysis")
    assert stored.status_code == 200 and stored.headers["x-js-source"] == "stored"
    batch = json.loads((tmp_path / "js" / "c2_phishing_000001.json").read_text("utf-8"))
    assert stored.json()["features"] == batch["features"]
    (tmp_path / "v0.1" / "c2_phishing_000001.json").unlink()
    fresh = client.get("/api/v1/dev/samples/c2_phishing_000001/js-analysis")
    assert fresh.headers["x-js-source"] == "on-the-fly"
    assert fresh.json()["features"] == batch["features"]
    assert client.get("/api/v1/dev/samples/c2_phishing_999999/js-analysis").status_code == 404
    production = TestClient(create_app("production"))
    assert production.get("/api/v1/dev/samples/c2_phishing_000001/js-analysis").status_code == 404
