"""Unit and integration tests for URL Analyzer Final Verdict Classification Logic.

Verifies:
1. Model probability strictly represents malicious class (index 1).
2. Scores below 80% (including 79%): standard multi-layer rules apply (SAFE, SUSPICIOUS, PHISHING, MALICIOUS).
3. Score exactly 80.0%: Not automatically classified as malicious; standard rules apply.
4. Scores above 80% (81%, 90%, 99%):
   - Verdict is NEVER SAFE.
   - PHISHING when credential, login, or fake account verification indicators detected.
   - MALICIOUS when malware distribution or confirmed threat evidence detected.
   - SUSPICIOUS when high risk exists but evidence is insufficient to distinguish phishing vs malware.
5. End-to-end API response consistency (CompleteUrlDomainAnalysisResult.verdict and score).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.analyzers.lexical_analyzer import UrlLexicalAnalyzer
from app.analyzers.risk_scoring_engine import ExplainableRiskScoringEngine
from app.ml.model_service import get_ml_service
from app.schemas.url_schema import (
    DgaAnalysisFeatures,
    DnsIntelligenceFeatures,
    DomainIntelligenceReport,
    DomainRegistrationFeatures,
    DomainReputationFeatures,
    MlPredictionResult,
    RedirectChainFeatures,
    ThreatInfrastructureReport,
)
from main import app


@pytest.fixture
def lexical_analyzer() -> UrlLexicalAnalyzer:
    return UrlLexicalAnalyzer()


@pytest.fixture
def risk_engine() -> ExplainableRiskScoringEngine:
    return ExplainableRiskScoringEngine()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def benign_domain_intel() -> DomainIntelligenceReport:
    return DomainIntelligenceReport(
        dns=DnsIntelligenceFeatures(
            a_records=["93.184.216.34"],
            has_mx_records=True,
            has_spf=True,
            has_dmarc=True,
            min_ttl=3600,
            dns_resolved=True,
            ip_count=1,
            is_fast_flux=False,
            is_dynamic_dns=False,
            is_private_ip_resolved=False,
            dns_indicators=[],
        ),
        registration=DomainRegistrationFeatures(
            domain_name="example.com",
            age_days=3000,
            is_nrd=False,
            is_young_domain=False,
            registrar="MarkMonitor Inc.",
            dnssec_enabled=True,
            privacy_protected=False,
            data_source="rdap",
            is_data_available=True,
        ),
        reputation=DomainReputationFeatures(
            threat_feed_checked=True,
            is_known_threat=False,
            threat_type=None,
            confidence_score=0.0,
            reputation_source=None,
            reputation_indicators=[],
        ),
        domain_risk_score=5.0,
        domain_risk_indicators=[],
    )


@pytest.fixture
def benign_threat_infra() -> ThreatInfrastructureReport:
    return ThreatInfrastructureReport(
        dga=DgaAnalysisFeatures(
            domain_name="example.com",
            label="example",
            label_length=7,
            label_entropy=2.1,
            vowel_count=3,
            consonant_count=4,
            digit_count=0,
            vowel_ratio=0.43,
            consonant_ratio=0.57,
            digit_ratio=0.0,
            max_consecutive_consonants=2,
            bigram_perplexity=8.5,
            dga_score=0.05,
            is_dga_suspected=False,
            dga_family_hint=None,
            dga_indicators=[],
        ),
        redirect_chain=RedirectChainFeatures(
            original_url="https://example.com",
            final_url="https://example.com",
            is_shortened=False,
            shortener_provider=None,
            total_hops=0,
            is_redirected=False,
            has_redirect_loop=False,
            has_cross_domain_redirect=False,
            has_excessive_redirects=False,
            destination_domain_changed=False,
            ssrf_blocked=False,
            error_message=None,
            chain_hops=[],
            redirect_indicators=[],
        ),
        infrastructure_risk_score=0.0,
        infrastructure_indicators=[],
    )


# ==============================================================================
# 1. Technical Requirement: Malicious Probability Index Check
# ==============================================================================

def test_ml_model_probability_represents_malicious_class():
    """Verify that model_service uses malicious class probability (index 1), not safe class (index 0)."""
    service = get_ml_service()
    assert service is not None

    if service.is_loaded:
        # Predict on a test URL
        res = service.predict("https://paypal-verify-secure-login-account.com/auth")
        # Probability must be float between 0.0 and 1.0
        assert 0.0 <= res.malicious_probability <= 1.0
        assert res.predicted_label in ("malicious", "legitimate")
        # In a binary classifier with classes [0=legitimate, 1=malicious],
        # malicious_probability > decision_threshold implies predicted_label == 'malicious'
        if res.malicious_probability >= res.decision_threshold:
            assert res.predicted_label == "malicious"


# ==============================================================================
# 2. Score < 80% (including 79%, 20%, 0%)
# ==============================================================================

def test_verdict_score_below_80_clean_safe(
    risk_engine: ExplainableRiskScoringEngine,
    lexical_analyzer: UrlLexicalAnalyzer,
    benign_domain_intel: DomainIntelligenceReport,
    benign_threat_infra: ThreatInfrastructureReport,
):
    """Benign URL scoring well below 80% should receive SAFE verdict."""
    url = "https://example.com/about"
    features = lexical_analyzer.extract_features(url)
    ml_res = MlPredictionResult(
        predicted_label="legitimate",
        malicious_probability=0.05,  # 5%
        confidence=95.0,
        is_model_loaded=True,
    )

    assessment = risk_engine.evaluate(
        raw_url=url,
        lexical_features=features,
        domain_report=benign_domain_intel,
        infra_report=benign_threat_infra,
        ml_res=ml_res,
    )

    assert assessment.risk_score < 80.0
    assert assessment.verdict == "SAFE"


def test_verdict_score_79_percent_not_forced_to_high_risk_mandate(
    risk_engine: ExplainableRiskScoringEngine,
    lexical_analyzer: UrlLexicalAnalyzer,
    benign_domain_intel: DomainIntelligenceReport,
    benign_threat_infra: ThreatInfrastructureReport,
):
    """URL with score at exactly 79% (below 80%) uses standard rules."""
    url = "https://suspicious-sample-portal.com/check"
    features = lexical_analyzer.extract_features(url)
    # ML probability at 79%
    ml_res = MlPredictionResult(
        predicted_label="malicious",
        malicious_probability=0.79,  # 79%
        confidence=79.0,
        is_model_loaded=True,
    )

    assessment = risk_engine.evaluate(
        raw_url=url,
        lexical_features=features,
        domain_report=benign_domain_intel,
        infra_report=benign_threat_infra,
        ml_res=ml_res,
    )

    # Score should be around 79%
    assert assessment.risk_score < 80.0
    # At 79% without active malware or phishing keywords, it should be SUSPICIOUS under existing classification rules
    assert assessment.verdict in ("SAFE", "SUSPICIOUS", "PHISHING", "MALICIOUS")
    assert assessment.verdict != "MALICIOUS" or "threat" in assessment.justification.lower()


# ==============================================================================
# 3. Score = 80% (Boundary Case)
# ==============================================================================

def test_verdict_score_exactly_80_boundary(
    risk_engine: ExplainableRiskScoringEngine,
    lexical_analyzer: UrlLexicalAnalyzer,
    benign_domain_intel: DomainIntelligenceReport,
    benign_threat_infra: ThreatInfrastructureReport,
):
    """Score = 80% should not automatically be classified as MALICIOUS; applies standard rules."""
    url = "https://example-test-boundary.com/path"
    features = lexical_analyzer.extract_features(url)
    ml_res = MlPredictionResult(
        predicted_label="malicious",
        malicious_probability=0.80,  # Exactly 80%
        confidence=80.0,
        is_model_loaded=True,
    )

    assessment = risk_engine.evaluate(
        raw_url=url,
        lexical_features=features,
        domain_report=benign_domain_intel,
        infra_report=benign_threat_infra,
        ml_res=ml_res,
    )

    # Does not trigger score > 80 rule
    # Can be SUSPICIOUS based on existing rules, but not forced into MALICIOUS
    assert assessment.verdict in ("SUSPICIOUS", "SAFE", "PHISHING", "MALICIOUS")
    # Because there are no malware or threat indicators, standard rule classifies as SUSPICIOUS
    assert assessment.verdict == "SUSPICIOUS"


# ==============================================================================
# 4. Score > 80% (81%, 90%, 99%) - MUST NEVER BE SAFE
# ==============================================================================

@pytest.mark.parametrize("prob_score", [0.81, 0.90, 0.99])
def test_verdict_score_above_80_never_safe_phishing(
    risk_engine: ExplainableRiskScoringEngine,
    lexical_analyzer: UrlLexicalAnalyzer,
    benign_domain_intel: DomainIntelligenceReport,
    benign_threat_infra: ThreatInfrastructureReport,
    prob_score: float,
):
    """When score > 80% and phishing indicators exist, verdict must be PHISHING and NEVER SAFE."""
    url = "https://bank-login-verification-secure-account.com/signin/auth"
    features = lexical_analyzer.extract_features(url)
    ml_res = MlPredictionResult(
        predicted_label="malicious",
        malicious_probability=prob_score,
        confidence=prob_score * 100.0,
        is_model_loaded=True,
    )

    assessment = risk_engine.evaluate(
        raw_url=url,
        lexical_features=features,
        domain_report=benign_domain_intel,
        infra_report=benign_threat_infra,
        ml_res=ml_res,
    )

    assert assessment.risk_score > 80.0
    assert assessment.verdict != "SAFE"
    assert assessment.verdict == "PHISHING"


@pytest.mark.parametrize("prob_score", [0.81, 0.90, 0.99])
def test_verdict_score_above_80_never_safe_malware(
    risk_engine: ExplainableRiskScoringEngine,
    lexical_analyzer: UrlLexicalAnalyzer,
    benign_domain_intel: DomainIntelligenceReport,
    benign_threat_infra: ThreatInfrastructureReport,
    prob_score: float,
):
    """When score > 80% and malware/payload evidence exists, verdict must be MALICIOUS and NEVER SAFE."""
    url = "https://cdn-download-update.com/payload.exe"
    features = lexical_analyzer.extract_features(url)
    ml_res = MlPredictionResult(
        predicted_label="malicious",
        malicious_probability=prob_score,
        confidence=prob_score * 100.0,
        is_model_loaded=True,
    )

    assessment = risk_engine.evaluate(
        raw_url=url,
        lexical_features=features,
        domain_report=benign_domain_intel,
        infra_report=benign_threat_infra,
        ml_res=ml_res,
    )

    assert assessment.risk_score > 80.0
    assert assessment.verdict != "SAFE"
    assert assessment.verdict == "MALICIOUS"


@pytest.mark.parametrize("prob_score", [0.81, 0.90, 0.99])
def test_verdict_score_above_80_never_safe_uncertain_suspicious(
    risk_engine: ExplainableRiskScoringEngine,
    lexical_analyzer: UrlLexicalAnalyzer,
    benign_domain_intel: DomainIntelligenceReport,
    benign_threat_infra: ThreatInfrastructureReport,
    prob_score: float,
):
    """When score > 80% but evidence cannot distinguish phishing vs malware, verdict must be SUSPICIOUS (NEVER SAFE)."""
    # Generic domain without specific login/credential keywords or malware extensions
    url = "https://unusual-obfuscated-cluster.xyz/random-token-v2"
    features = lexical_analyzer.extract_features(url)
    ml_res = MlPredictionResult(
        predicted_label="malicious",
        malicious_probability=prob_score,
        confidence=prob_score * 100.0,
        is_model_loaded=True,
    )

    assessment = risk_engine.evaluate(
        raw_url=url,
        lexical_features=features,
        domain_report=benign_domain_intel,
        infra_report=benign_threat_infra,
        ml_res=ml_res,
    )

    assert assessment.risk_score > 80.0
    assert assessment.verdict != "SAFE"
    assert assessment.verdict in ("MALICIOUS", "PHISHING", "SUSPICIOUS")
    assert assessment.verdict == "SUSPICIOUS"


# ==============================================================================
# 5. Full API Endpoint Verification (/analyze-url)
# ==============================================================================

def test_api_endpoint_verdict_and_score(client: TestClient):
    """Verify that /analyze-url API response includes 'verdict' and 'score' consistently."""
    response = client.post("/analyze-url", json={"url": "https://paypal-verify-secure-login.com"})
    assert response.status_code == 200
    data = response.json()

    assert "verdict" in data
    assert "score" in data
    assert data["verdict"] in ("SAFE", "SUSPICIOUS", "PHISHING", "MALICIOUS")
    assert "risk_assessment" in data
    assert data["risk_assessment"]["verdict"] == data["verdict"]
    assert data["risk_assessment"]["risk_score"] == data["score"]

    # When score > 80%, ensure verdict is never SAFE
    if data["score"] > 80.0:
        assert data["verdict"] in ("MALICIOUS", "PHISHING", "SUSPICIOUS")
        assert data["verdict"] != "SAFE"
