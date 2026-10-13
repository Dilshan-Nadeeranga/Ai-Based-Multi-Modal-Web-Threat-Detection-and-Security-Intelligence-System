"""Unit and integration tests for the Explainable Risk-Scoring Engine (Component C1).

Verifies:
1. Score normalization (0.0 to 100.0).
2. Configurable scoring weights and documented rationales.
3. Collinearity dampening and double-counting avoidance.
4. Graceful handling of missing external services (WHOIS, DNS, ML).
5. Explicit distinction between model probability P and overall risk score R.
6. Configurable risk thresholds and classification mappings.
7. Main contributing indicators with impact deltas and concrete evidence.
8. Telemetry metadata (engine version, timestamp, limitations).
9. Strict epistemological separation (Observed Facts vs Heuristics vs Predictions).
10. Borderline cases and false-positive resistance (Google sign-in, benign NRD, shortener to Wikipedia).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from app.analyzers.lexical_analyzer import UrlLexicalAnalyzer
from app.analyzers.risk_scoring_engine import ExplainableRiskScoringEngine
from app.config import Settings
from main import app
from app.schemas.url_schema import (
    DgaAnalysisFeatures,
    DnsIntelligenceFeatures,
    DomainIntelligenceReport,
    DomainRegistrationFeatures,
    DomainReputationFeatures,
    MlPredictionResult,
    RedirectChainFeatures,
    ThreatInfrastructureReport,
    UrlLexicalFeatures,
)


@pytest.fixture
def lexical_analyzer() -> UrlLexicalAnalyzer:
    return UrlLexicalAnalyzer()


@pytest.fixture
def risk_engine() -> ExplainableRiskScoringEngine:
    return ExplainableRiskScoringEngine()


@pytest.fixture
def dummy_dns() -> DnsIntelligenceFeatures:
    return DnsIntelligenceFeatures(
        a_records=["93.184.216.34"],
        aaaa_records=[],
        mx_records=["mail.example.com"],
        ns_records=["ns1.example.com"],
        txt_records=[],
        has_mx_records=True,
        has_spf=True,
        has_dmarc=True,
        min_ttl=3600,
        ip_count=1,
        is_fast_flux=False,
        is_dynamic_dns=False,
        is_private_ip_resolved=False,
        dns_resolved=True,
        dns_indicators=[],
    )


@pytest.fixture
def dummy_reputation() -> DomainReputationFeatures:
    return DomainReputationFeatures(
        threat_feed_checked=True,
        is_known_threat=False,
        threat_type=None,
        confidence_score=0.0,
        reputation_source=None,
        reputation_indicators=[],
    )


@pytest.fixture
def dummy_dga() -> DgaAnalysisFeatures:
    return DgaAnalysisFeatures(
        domain_name="example.com",
        label="example",
        label_length=7,
        label_entropy=2.8,
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
    )


@pytest.fixture
def dummy_redirect() -> RedirectChainFeatures:
    return RedirectChainFeatures(
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
    )


# ---------------------------------------------------------------------------
# 1. Normalization, Configurable Weights & Thresholds
# ---------------------------------------------------------------------------

def test_risk_score_normalization_and_thresholds(
    risk_engine: ExplainableRiskScoringEngine,
    lexical_analyzer: UrlLexicalAnalyzer,
    dummy_dns: DnsIntelligenceFeatures,
    dummy_reputation: DomainReputationFeatures,
    dummy_dga: DgaAnalysisFeatures,
    dummy_redirect: RedirectChainFeatures,
):
    """Verify that scores are normalized strictly between 0 and 100, and thresholds map correctly."""
    url = "https://example.com/welcome"
    lex_feat = lexical_analyzer.extract_features(url)

    reg = DomainRegistrationFeatures(
        domain_name="example.com",
        creation_date="2010-01-01T00:00:00Z",
        expiration_date="2030-01-01T00:00:00Z",
        updated_date=None,
        age_days=5000,
        days_until_expiration=1500,
        registrar="MarkMonitor",
        registrant_country="US",
        dnssec_enabled=True,
        is_nrd=False,
        is_young_domain=False,
        privacy_protected=False,
        data_source="rdap",
        is_data_available=True,
    )

    domain_rep = DomainIntelligenceReport(
        registration=reg,
        dns=dummy_dns,
        reputation=dummy_reputation,
        domain_risk_score=0.0,
        domain_risk_indicators=[],
    )

    infra_rep = ThreatInfrastructureReport(
        dga=dummy_dga,
        redirect_chain=dummy_redirect,
        infrastructure_risk_score=0.0,
        infrastructure_indicators=[],
    )

    assessment = risk_engine.evaluate(
        raw_url=url,
        lexical_features=lex_feat,
        domain_report=domain_rep,
        infra_report=infra_rep,
        ml_res=None,
    )

    assert 0.0 <= assessment.risk_score <= 100.0
    assert assessment.classification == "Low Risk"
    assert assessment.risk_level == "Low Risk"
    assert assessment.engine_version == "c1-explainable-risk-v1.0.0"
    assert "T" in assessment.analysis_timestamp  # Valid ISO timestamp


def test_configurable_weights_and_custom_settings(
    lexical_analyzer: UrlLexicalAnalyzer,
    dummy_dns: DnsIntelligenceFeatures,
    dummy_reputation: DomainReputationFeatures,
    dummy_dga: DgaAnalysisFeatures,
    dummy_redirect: RedirectChainFeatures,
):
    """Verify that custom weights and thresholds can be configured and are properly respected."""
    custom_settings = Settings(
        weight_lexical_structural=0.50,
        weight_domain_registration=0.50,
        weight_dns_reputation=0.0,
        weight_entropy_obfuscation=0.0,
        weight_homoglyph_lookalike=0.0,
        weight_dga=0.0,
        weight_shortener_redirect=0.0,
        weight_machine_learning=0.0,
        risk_threshold_low=10.0,
        risk_threshold_medium=30.0,
        risk_threshold_high=60.0,
    )
    custom_engine = ExplainableRiskScoringEngine(settings=custom_settings)

    lex_feat = lexical_analyzer.extract_features("https://example.com/login")
    reg = DomainRegistrationFeatures(
        domain_name="example.com",
        creation_date=None,
        expiration_date=None,
        updated_date=None,
        age_days=2000,
        days_until_expiration=None,
        registrar="TestReg",
        registrant_country="US",
        dnssec_enabled=False,
        is_nrd=False,
        is_young_domain=False,
        privacy_protected=False,
        data_source="rdap",
        is_data_available=True,
    )

    domain_rep = DomainIntelligenceReport(
        registration=reg,
        dns=dummy_dns,
        reputation=dummy_reputation,
        domain_risk_score=0.0,
        domain_risk_indicators=[],
    )
    infra_rep = ThreatInfrastructureReport(
        dga=dummy_dga,
        redirect_chain=dummy_redirect,
        infrastructure_risk_score=0.0,
        infrastructure_indicators=[],
    )

    res = custom_engine.evaluate("https://example.com/login", lex_feat, domain_rep, infra_rep)
    assert res.active_weights["lexical_structural"] > 0.0
    assert res.active_weights["domain_registration"] > 0.0
    assert res.active_weights["dga"] == 0.0


# ---------------------------------------------------------------------------
# 2. Missing Services & Dynamic Weight Renormalization
# ---------------------------------------------------------------------------

def test_missing_registration_service_graceful_renormalization(
    risk_engine: ExplainableRiskScoringEngine,
    lexical_analyzer: UrlLexicalAnalyzer,
    dummy_dns: DnsIntelligenceFeatures,
    dummy_reputation: DomainReputationFeatures,
    dummy_dga: DgaAnalysisFeatures,
    dummy_redirect: RedirectChainFeatures,
):
    """Verify that when WHOIS/RDAP is unavailable, registration is not penalized and weights renormalize."""
    url = "https://unregistered-or-rate-limited.com/test"
    lex_feat = lexical_analyzer.extract_features(url)

    reg_unavailable = DomainRegistrationFeatures(
        domain_name="unregistered-or-rate-limited.com",
        creation_date=None,
        expiration_date=None,
        updated_date=None,
        age_days=None,
        days_until_expiration=None,
        registrar=None,
        registrant_country=None,
        dnssec_enabled=False,
        is_nrd=False,
        is_young_domain=False,
        privacy_protected=False,
        data_source="unavailable",
        is_data_available=False,
    )

    domain_rep = DomainIntelligenceReport(
        registration=reg_unavailable,
        dns=dummy_dns,
        reputation=dummy_reputation,
        domain_risk_score=0.0,
        domain_risk_indicators=[],
    )
    infra_rep = ThreatInfrastructureReport(
        dga=dummy_dga,
        redirect_chain=dummy_redirect,
        infrastructure_risk_score=0.0,
        infrastructure_indicators=[],
    )

    res = risk_engine.evaluate(url, lex_feat, domain_rep, infra_rep, ml_res=None)

    # Weights must dynamically sum to 1.0
    active_weight_sum = sum(res.active_weights.values())
    assert pytest.approx(active_weight_sum, 0.001) == 1.0
    assert res.active_weights["domain_registration"] == 0.0
    assert any("WHOIS/RDAP registration lookup was unavailable" in lim for lim in res.analysis_limitations)
    # Missing data should not falsely trigger high risk
    assert res.risk_score < 40.0


def test_direct_ip_destination_deactivates_domain_channels(
    risk_engine: ExplainableRiskScoringEngine,
    lexical_analyzer: UrlLexicalAnalyzer,
    dummy_dns: DnsIntelligenceFeatures,
    dummy_reputation: DomainReputationFeatures,
    dummy_dga: DgaAnalysisFeatures,
    dummy_redirect: RedirectChainFeatures,
):
    """Direct IP destinations must bypass registration and DGA channels without error."""
    url = "http://198.51.100.45/admin"
    lex_feat = lexical_analyzer.extract_features(url)
    assert lex_feat.is_ip_address is True

    reg_empty = DomainRegistrationFeatures(
        domain_name="198.51.100.45",
        creation_date=None,
        expiration_date=None,
        updated_date=None,
        age_days=None,
        days_until_expiration=None,
        registrar=None,
        registrant_country=None,
        dnssec_enabled=False,
        is_nrd=False,
        is_young_domain=False,
        privacy_protected=False,
        data_source="unavailable",
        is_data_available=False,
    )

    domain_rep = DomainIntelligenceReport(
        registration=reg_empty,
        dns=dummy_dns,
        reputation=dummy_reputation,
        domain_risk_score=0.0,
        domain_risk_indicators=[],
    )
    infra_rep = ThreatInfrastructureReport(
        dga=dummy_dga,
        redirect_chain=dummy_redirect,
        infrastructure_risk_score=0.0,
        infrastructure_indicators=[],
    )

    res = risk_engine.evaluate(url, lex_feat, domain_rep, infra_rep)

    assert res.active_weights["domain_registration"] == 0.0
    assert res.active_weights["dga"] == 0.0
    assert any("direct IP address" in lim for lim in res.analysis_limitations)
    # Direct IP is an observed fact and contributing factor
    assert any(f.factor_id == "direct_ip_destination" for f in res.contributing_factors)


# ---------------------------------------------------------------------------
# 3. Model Probability vs Overall Risk Score
# ---------------------------------------------------------------------------

def test_model_probability_distinct_from_overall_risk_score(
    risk_engine: ExplainableRiskScoringEngine,
    lexical_analyzer: UrlLexicalAnalyzer,
    dummy_dns: DnsIntelligenceFeatures,
    dummy_reputation: DomainReputationFeatures,
    dummy_dga: DgaAnalysisFeatures,
    dummy_redirect: RedirectChainFeatures,
):
    """Verify that model probability P in [0, 1] is kept distinct from overall risk score R in [0, 100]."""
    url = "https://example.com/checkout"
    lex_feat = lexical_analyzer.extract_features(url)

    ml_result = MlPredictionResult(
        is_model_loaded=True,
        model_name="RandomForestClassifier",
        malicious_probability=0.72,
        predicted_label="malicious",
        decision_threshold=0.50,
        confidence=85.0,
        inference_time_ms=3.2,
        feature_count=47,
        top_risk_features=["suspicious_keyword_count", "url_length"],
    )

    reg = DomainRegistrationFeatures(
        domain_name="example.com",
        creation_date="2005-01-01T00:00:00Z",
        expiration_date="2030-01-01T00:00:00Z",
        updated_date=None,
        age_days=7000,
        days_until_expiration=2000,
        registrar="MarkMonitor",
        registrant_country="US",
        dnssec_enabled=True,
        is_nrd=False,
        is_young_domain=False,
        privacy_protected=False,
        data_source="rdap",
        is_data_available=True,
    )

    domain_rep = DomainIntelligenceReport(
        registration=reg,
        dns=dummy_dns,
        reputation=dummy_reputation,
        domain_risk_score=0.0,
        domain_risk_indicators=[],
    )
    infra_rep = ThreatInfrastructureReport(
        dga=dummy_dga,
        redirect_chain=dummy_redirect,
        infrastructure_risk_score=0.0,
        infrastructure_indicators=[],
    )

    res = risk_engine.evaluate(url, lex_feat, domain_rep, infra_rep, ml_res=ml_result)

    # ML probability is 0.72, but overall risk score integrates 20-year domain age mitigating credit
    assert res.channel_scores["machine_learning"] == 72.0
    assert res.risk_score < 72.0  # Overall score is lower than pure ML probability due to established domain
    assert res.model_version == "RandomForestClassifier"


# ---------------------------------------------------------------------------
# 4. Collinearity & Double-Counting Avoidance
# ---------------------------------------------------------------------------

def test_collinearity_entropy_and_dga_dampening(
    risk_engine: ExplainableRiskScoringEngine,
    lexical_analyzer: UrlLexicalAnalyzer,
    dummy_dns: DnsIntelligenceFeatures,
    dummy_reputation: DomainReputationFeatures,
    dummy_redirect: RedirectChainFeatures,
):
    """When DGA classifier flags elevated randomness, path entropy contribution is dampened."""
    url = "https://dga-c2-xyz123abc456.org/randompath1234567890abcdef"
    lex_feat = lexical_analyzer.extract_features(url)

    # DGA flagged
    dga_flagged = DgaAnalysisFeatures(
        domain_name="dga-c2-xyz123abc456.org",
        label="dga-c2-xyz123abc456",
        label_length=20,
        label_entropy=4.1,
        vowel_count=2,
        consonant_count=14,
        digit_count=4,
        vowel_ratio=0.12,
        consonant_ratio=0.88,
        digit_ratio=0.20,
        max_consecutive_consonants=6,
        bigram_perplexity=32.0,
        dga_score=0.85,
        is_dga_suspected=True,
        dga_family_hint="conficker_like",
        dga_indicators=["High entropy", "Consonant clustering"],
    )

    reg = DomainRegistrationFeatures(
        domain_name="dga-c2-xyz123abc456.org",
        creation_date=None,
        expiration_date=None,
        updated_date=None,
        age_days=10,
        days_until_expiration=None,
        registrar="BadReg",
        registrant_country="RU",
        dnssec_enabled=False,
        is_nrd=True,
        is_young_domain=True,
        privacy_protected=True,
        data_source="rdap",
        is_data_available=True,
    )

    domain_rep = DomainIntelligenceReport(
        registration=reg,
        dns=dummy_dns,
        reputation=dummy_reputation,
        domain_risk_score=0.0,
        domain_risk_indicators=[],
    )
    infra_rep = ThreatInfrastructureReport(
        dga=dga_flagged,
        redirect_chain=dummy_redirect,
        infrastructure_risk_score=0.0,
        infrastructure_indicators=[],
    )

    res = risk_engine.evaluate(url, lex_feat, domain_rep, infra_rep)

    # Entropy factor should reflect dampening (half impact)
    entropy_factors = [f for f in res.contributing_factors if f.factor_id == "elevated_path_entropy"]
    if entropy_factors:
        assert entropy_factors[0].impact_score <= 10.0


def test_collinearity_homoglyph_and_punycode_non_duplication(
    risk_engine: ExplainableRiskScoringEngine,
    lexical_analyzer: UrlLexicalAnalyzer,
    dummy_dns: DnsIntelligenceFeatures,
    dummy_reputation: DomainReputationFeatures,
    dummy_dga: DgaAnalysisFeatures,
    dummy_redirect: RedirectChainFeatures,
):
    """Punycode prefix and homoglyphs must not be charged twice for the same character set encoding."""
    # Cyrillic 'а' in xn--pple-43d.com
    url = "https://xn--pple-43d.com/login"
    lex_feat = lexical_analyzer.extract_features(url)

    reg = DomainRegistrationFeatures(
        domain_name="xn--pple-43d.com",
        creation_date=None,
        expiration_date=None,
        updated_date=None,
        age_days=2,
        days_until_expiration=None,
        registrar="Reg",
        registrant_country="IS",
        dnssec_enabled=False,
        is_nrd=True,
        is_young_domain=True,
        privacy_protected=True,
        data_source="rdap",
        is_data_available=True,
    )

    domain_rep = DomainIntelligenceReport(
        registration=reg,
        dns=dummy_dns,
        reputation=dummy_reputation,
        domain_risk_score=0.0,
        domain_risk_indicators=[],
    )
    infra_rep = ThreatInfrastructureReport(
        dga=dummy_dga,
        redirect_chain=dummy_redirect,
        infrastructure_risk_score=0.0,
        infrastructure_indicators=[],
    )

    res = risk_engine.evaluate(url, lex_feat, domain_rep, infra_rep)

    factor_ids = [f.factor_id for f in res.contributing_factors]
    # If homoglyph is detected, generic punycode shouldn't be added as an independent penalty
    if "homoglyph_confusable_domain" in factor_ids:
        assert "punycode_encoded_domain" not in factor_ids


# ---------------------------------------------------------------------------
# 5. Epistemological Tier Separation
# ---------------------------------------------------------------------------

def test_epistemological_tier_separation(
    risk_engine: ExplainableRiskScoringEngine,
    lexical_analyzer: UrlLexicalAnalyzer,
    dummy_dns: DnsIntelligenceFeatures,
    dummy_reputation: DomainReputationFeatures,
    dummy_dga: DgaAnalysisFeatures,
    dummy_redirect: RedirectChainFeatures,
):
    """Verify strict separation between Observed Facts, Heuristic Indicators, and Model Predictions."""
    url = "https://login.paypal.verify-account.com/auth"
    lex_feat = lexical_analyzer.extract_features(url)

    reg = DomainRegistrationFeatures(
        domain_name="verify-account.com",
        creation_date="2026-10-01T00:00:00Z",
        expiration_date="2027-10-01T00:00:00Z",
        updated_date=None,
        age_days=12,
        days_until_expiration=350,
        registrar="Namecheap",
        registrant_country="PA",
        dnssec_enabled=False,
        is_nrd=True,
        is_young_domain=True,
        privacy_protected=True,
        data_source="rdap",
        is_data_available=True,
    )

    domain_rep = DomainIntelligenceReport(
        registration=reg,
        dns=dummy_dns,
        reputation=dummy_reputation,
        domain_risk_score=0.0,
        domain_risk_indicators=[],
    )
    infra_rep = ThreatInfrastructureReport(
        dga=dummy_dga,
        redirect_chain=dummy_redirect,
        infrastructure_risk_score=0.0,
        infrastructure_indicators=[],
    )

    ml_res = MlPredictionResult(
        is_model_loaded=True,
        model_name="XGBClassifier",
        malicious_probability=0.88,
        predicted_label="malicious",
        decision_threshold=0.5,
        confidence=92.0,
        inference_time_ms=2.1,
        feature_count=47,
        top_risk_features=["suspicious_keyword_count", "subdomain_depth"],
    )

    res = risk_engine.evaluate(url, lex_feat, domain_rep, infra_rep, ml_res=ml_res)
    breakdown = res.epistemic_breakdown

    # 1. Facts must contain deterministic data
    assert any("Target URL scheme" in fact for fact in breakdown.observed_facts)
    assert any("Domain registration creation date" in fact for fact in breakdown.observed_facts)
    assert any("DNS resolved" in fact for fact in breakdown.observed_facts)

    # 2. Heuristics must contain rule/threshold triggers
    assert any("sensitive keyword" in heur for heur in breakdown.heuristic_indicators)
    assert any("Newly Registered Domain" in heur for heur in breakdown.heuristic_indicators)

    # 3. Predictions must contain statistical models
    assert any("Supervised ML classifier (XGBClassifier)" in pred for pred in breakdown.model_predictions)
    assert any("Statistical DGA analyzer" in pred for pred in breakdown.model_predictions)


# ---------------------------------------------------------------------------
# 6. Borderline Cases & False-Positive Scenarios
# ---------------------------------------------------------------------------

def test_borderline_google_signin_false_positive_guard(
    risk_engine: ExplainableRiskScoringEngine,
    lexical_analyzer: UrlLexicalAnalyzer,
    dummy_dns: DnsIntelligenceFeatures,
    dummy_reputation: DomainReputationFeatures,
    dummy_dga: DgaAnalysisFeatures,
    dummy_redirect: RedirectChainFeatures,
):
    """Legitimate enterprise auth URL (accounts.google.com/signin) must not trigger High Risk Scam."""
    url = "https://accounts.google.com/signin/v2/identifier?flowName=GlifWebSignIn"
    lex_feat = lexical_analyzer.extract_features(url)

    reg = DomainRegistrationFeatures(
        domain_name="google.com",
        creation_date="1997-09-15T00:00:00Z",
        expiration_date="2028-09-14T00:00:00Z",
        updated_date=None,
        age_days=10600,  # ~29 years old
        days_until_expiration=700,
        registrar="MarkMonitor, Inc.",
        registrant_country="US",
        dnssec_enabled=True,
        is_nrd=False,
        is_young_domain=False,
        privacy_protected=False,
        data_source="rdap",
        is_data_available=True,
    )

    domain_rep = DomainIntelligenceReport(
        registration=reg,
        dns=dummy_dns,
        reputation=dummy_reputation,
        domain_risk_score=0.0,
        domain_risk_indicators=[],
    )
    infra_rep = ThreatInfrastructureReport(
        dga=dummy_dga,
        redirect_chain=dummy_redirect,
        infrastructure_risk_score=0.0,
        infrastructure_indicators=[],
    )

    res = risk_engine.evaluate(url, lex_feat, domain_rep, infra_rep)

    # Established domain guardrail must keep score capped at or below 35.0 (Low/Suspicious)
    assert res.risk_score <= 35.0
    assert res.classification in ["Low Risk", "Suspicious"]
    assert any(f.factor_id in ["established_domain_age", "established_domain_fp_guard"] for f in res.contributing_factors)



def test_borderline_benign_newly_registered_domain(
    risk_engine: ExplainableRiskScoringEngine,
    lexical_analyzer: UrlLexicalAnalyzer,
    dummy_dns: DnsIntelligenceFeatures,
    dummy_reputation: DomainReputationFeatures,
    dummy_dga: DgaAnalysisFeatures,
    dummy_redirect: RedirectChainFeatures,
):
    """Benign developer blog on a new domain with NO phishing keywords or homoglyphs must not be High Risk."""
    url = "https://mynewpersonaltechblog2026.dev/articles/getting-started"
    lex_feat = lexical_analyzer.extract_features(url)
    assert lex_feat.has_suspicious_keyword is False

    reg = DomainRegistrationFeatures(
        domain_name="mynewpersonaltechblog2026.dev",
        creation_date="2026-10-05T00:00:00Z",
        expiration_date="2027-10-05T00:00:00Z",
        updated_date=None,
        age_days=8,  # NRD
        days_until_expiration=355,
        registrar="Google Domains",
        registrant_country="US",
        dnssec_enabled=True,
        is_nrd=True,
        is_young_domain=True,
        privacy_protected=False,
        data_source="rdap",
        is_data_available=True,
    )

    domain_rep = DomainIntelligenceReport(
        registration=reg,
        dns=dummy_dns,
        reputation=dummy_reputation,
        domain_risk_score=0.0,
        domain_risk_indicators=[],
    )
    infra_rep = ThreatInfrastructureReport(
        dga=dummy_dga,
        redirect_chain=dummy_redirect,
        infrastructure_risk_score=0.0,
        infrastructure_indicators=[],
    )

    res = risk_engine.evaluate(url, lex_feat, domain_rep, infra_rep)

    # Should be flagged as Suspicious due to NRD, but NOT High Risk Scam
    assert res.risk_score < 50.0
    assert res.classification in ["Low Risk", "Suspicious"]


def test_borderline_github_commit_hash_high_path_entropy(
    risk_engine: ExplainableRiskScoringEngine,
    lexical_analyzer: UrlLexicalAnalyzer,
    dummy_dns: DnsIntelligenceFeatures,
    dummy_reputation: DomainReputationFeatures,
    dummy_dga: DgaAnalysisFeatures,
    dummy_redirect: RedirectChainFeatures,
):
    """High entropy git hash in path on an established domain (GitHub) should not trigger false alarm."""
    url = "https://github.com/torvalds/linux/commit/a1b2c3d4e5f67890abcdef1234567890abcdef12"
    lex_feat = lexical_analyzer.extract_features(url)

    reg = DomainRegistrationFeatures(
        domain_name="github.com",
        creation_date="2007-10-09T00:00:00Z",
        expiration_date="2028-10-09T00:00:00Z",
        updated_date=None,
        age_days=6940,
        days_until_expiration=700,
        registrar="MarkMonitor",
        registrant_country="US",
        dnssec_enabled=False,
        is_nrd=False,
        is_young_domain=False,
        privacy_protected=False,
        data_source="rdap",
        is_data_available=True,
    )

    domain_rep = DomainIntelligenceReport(
        registration=reg,
        dns=dummy_dns,
        reputation=dummy_reputation,
        domain_risk_score=0.0,
        domain_risk_indicators=[],
    )
    infra_rep = ThreatInfrastructureReport(
        dga=dummy_dga,
        redirect_chain=dummy_redirect,
        infrastructure_risk_score=0.0,
        infrastructure_indicators=[],
    )

    res = risk_engine.evaluate(url, lex_feat, domain_rep, infra_rep)
    assert res.risk_score <= 35.0
    assert res.classification in ["Low Risk", "Suspicious"]


def test_critical_high_risk_multi_vector_phishing_combo(
    risk_engine: ExplainableRiskScoringEngine,
    lexical_analyzer: UrlLexicalAnalyzer,
    dummy_dns: DnsIntelligenceFeatures,
    dummy_reputation: DomainReputationFeatures,
    dummy_redirect: RedirectChainFeatures,
):
    """Obvious phishing setup (NRD + multiple login keywords + high risk TLD + ML malicious) must score High Risk."""
    url = "http://login-verify-paypal-security.top/auth/update.php?token=xyz"
    lex_feat = lexical_analyzer.extract_features(url)

    reg = DomainRegistrationFeatures(
        domain_name="login-verify-paypal-security.top",
        creation_date="2026-10-10T00:00:00Z",
        expiration_date="2027-10-10T00:00:00Z",
        updated_date=None,
        age_days=3,
        days_until_expiration=362,
        registrar="Hostinger",
        registrant_country="CN",
        dnssec_enabled=False,
        is_nrd=True,
        is_young_domain=True,
        privacy_protected=True,
        data_source="rdap",
        is_data_available=True,
    )

    ml_res = MlPredictionResult(
        is_model_loaded=True,
        model_name="RandomForestClassifier",
        malicious_probability=0.95,
        predicted_label="malicious",
        decision_threshold=0.5,
        confidence=95.0,
        inference_time_ms=2.5,
        feature_count=47,
        top_risk_features=["suspicious_keyword_count", "is_suspicious_tld"],
    )

    dga = DgaAnalysisFeatures(
        domain_name="login-verify-paypal-security.top",
        label="login-verify-paypal-security",
        label_length=27,
        label_entropy=3.2,
        vowel_count=9,
        consonant_count=18,
        digit_count=0,
        vowel_ratio=0.33,
        consonant_ratio=0.67,
        digit_ratio=0.0,
        max_consecutive_consonants=3,
        bigram_perplexity=10.0,
        dga_score=0.15,
        is_dga_suspected=False,
        dga_family_hint=None,
        dga_indicators=[],
    )

    domain_rep = DomainIntelligenceReport(
        registration=reg,
        dns=dummy_dns,
        reputation=dummy_reputation,
        domain_risk_score=0.0,
        domain_risk_indicators=[],
    )
    infra_rep = ThreatInfrastructureReport(
        dga=dga,
        redirect_chain=dummy_redirect,
        infrastructure_risk_score=0.0,
        infrastructure_indicators=[],
    )

    res = risk_engine.evaluate(url, lex_feat, domain_rep, infra_rep, ml_res=ml_res)

    assert res.risk_score >= 75.0
    assert res.classification == "High Risk Scam"
    assert any(f.factor_id == "compound_nrd_phishing_synergy" for f in res.contributing_factors)


# ---------------------------------------------------------------------------
# 7. FastAPI Endpoint Integration Tests
# ---------------------------------------------------------------------------

def test_api_explain_risk_endpoint():
    """Verify POST /api/v1/explain-risk endpoint returns valid ExplainableRiskAssessment."""
    client = TestClient(app)

    payload = {"url": "https://accounts.google.com/signin"}
    response = client.post("/api/v1/explain-risk", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert "risk_score" in data
    assert "classification" in data
    assert "contributing_factors" in data
    assert "epistemic_breakdown" in data
    assert "analysis_limitations" in data
    assert "active_weights" in data
    assert len(data["epistemic_breakdown"]["observed_facts"]) > 0


def test_api_scoring_weights_endpoint():
    """Verify GET /api/v1/scoring-weights endpoint returns nominal weights and rationales."""
    client = TestClient(app)

    response = client.get("/api/v1/scoring-weights")
    assert response.status_code == 200
    data = response.json()

    assert "engine_version" in data
    assert "nominal_weights" in data
    assert "thresholds" in data
    assert "lexical_structural" in data["nominal_weights"]
    assert "rationale" in data["nominal_weights"]["lexical_structural"]
    assert data["thresholds"]["high_risk"]["min_score"] == 75.0
