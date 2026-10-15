"""Automated test suite specifically verifying False Positive and False Negative reduction.

Tests cover:
1. Known legitimate URLs from Tranco Top 1M / authoritative sources.
2. Confirmed malicious URLs from URLhaus and PhishTank.
3. Legitimate URLs containing security-sensitive keywords without triggering false positives.
4. Legitimate URLs carrying high-entropy marketing/tracking tokens without triggering false positives.
5. URL shorteners, raw IP destinations, and non-standard network ports.
6. Encoded characters, long URLs, and unusual subdomains.
7. Graceful handling of missing domain telemetry, nulls, and malformed inputs.
8. Feature extraction parity between training-time and inference-time services.
9. Classification threshold calibration and safe confusion-matrix calculations (no zero division).
"""

from __future__ import annotations

import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.analyzers.lexical_analyzer import UrlLexicalAnalyzer
from app.ml.feature_extractor import FEATURE_NAMES, MlFeatureExtractor
from app.ml.model_service import MlInferenceService, get_ml_service
from app.ml.pipeline import MlTrainingPipeline
from main import app

client = TestClient(app)


# =============================================================================
# 1. Known Legitimate URLs
# =============================================================================

@pytest.mark.parametrize(
    "legitimate_url",
    [
        "https://www.google.com/search?q=cybersecurity+research",
        "https://en.wikipedia.org/wiki/Domain_Name_System",
        "https://github.com/torvalds/linux/commits/master",
        "https://www.amazon.com/gp/help/customer/display.html",
        "https://docs.python.org/3/library/urllib.parse.html",
        "https://www.cloudflare.com/learning/security/threats/",
        "https://stackoverflow.com/questions/tagged/python",
    ],
)
def test_known_legitimate_urls(legitimate_url: str):
    """Ensure recognized legitimate URLs are classified as legitimate with low probability."""
    svc = get_ml_service()
    res = svc.predict(legitimate_url)
    assert res.is_model_loaded is True
    assert res.predicted_label == "legitimate", f"False positive for {legitimate_url} (prob: {res.malicious_probability})"
    assert res.malicious_probability < res.decision_threshold
    assert res.risk_category in ("low", "suspicious_warning")


# =============================================================================
# 2. Confirmed Malicious URLs
# =============================================================================

@pytest.mark.parametrize(
    "malicious_url",
    [
        "http://203.196.41.11:45206/i",
        "http://123.14.145.195:46530/bin.sh",
        "http://paypal-verification-update.secure-login.xyz/auth/login.php",
        "http://chase-online-account-alert.top/verify.html",
        "http://appleid-security-lockout.click/login/session.php",
    ],
)
def test_confirmed_malicious_urls(malicious_url: str):
    """Ensure verified attack infrastructure URLs are flagged as malicious."""
    svc = get_ml_service()
    res = svc.predict(malicious_url)
    assert res.is_model_loaded is True
    assert res.predicted_label == "malicious", f"False negative for {malicious_url} (prob: {res.malicious_probability})"
    assert res.malicious_probability >= res.decision_threshold


# =============================================================================
# 3. Legitimate URLs Containing Suspicious Keywords (False Positive Prevention)
# =============================================================================

@pytest.mark.parametrize(
    "keyword_url",
    [
        "https://www.paypal-community.com/t5/Security/bd-p/Security",
        "https://support.apple.com/en-us/HT204144",
        "https://github.com/login",
        "https://www.bankofamerica.com/security-center/overview/",
        "https://docs.microsoft.com/en-us/security/",
    ],
)
def test_legitimate_urls_with_suspicious_keywords(keyword_url: str):
    """Ensure authentic brand domains containing security/login keywords are not falsely classified as malicious."""
    svc = get_ml_service()
    res = svc.predict(keyword_url)
    assert res.is_model_loaded is True
    assert res.predicted_label == "legitimate", f"False positive triggered by keywords in {keyword_url} (prob: {res.malicious_probability})"


# =============================================================================
# 4. High-Entropy Marketing Tracking Parameters (False Positive Prevention)
# =============================================================================

@pytest.mark.parametrize(
    "tracking_url",
    [
        "https://incarnage.com/?srsltid=AU7gw4Xh3ZyZaUEd7vknNJwSALGGys4-rUHXNgX9HwyRGK2QXX7UpLyN",
        "https://www.nike.com/t/air-max-90-mens-shoes?utm_source=google&utm_medium=cpc&utm_campaign=brand_sale",
        "https://store.steampowered.com/app/1091500/Cyberpunk_2077/?gclid=Cj0KCQjwlZixBhCoARIsADSpUTdY8xLq",
    ],
)
def test_tracking_parameters_entropy_mitigation(tracking_url: str):
    """Ensure high-entropy tracking hashes are mitigated by base_url_entropy and has_tracking_param."""
    extractor = MlFeatureExtractor()
    feat = extractor.extract_dict(tracking_url)

    assert feat["has_tracking_param"] == 1.0
    assert feat["base_url_entropy"] < feat["url_entropy"]

    # Verify end-to-end API assessment keeps the overall verdict as Low Risk
    response = client.post("/api/v1/analyze-url", json={"url": tracking_url})
    assert response.status_code == 200
    data = response.json()
    assert data["risk_assessment"]["risk_level"] in ("Low Risk", "Suspicious")


# =============================================================================
# 5. URL Shorteners, IP Addresses, and Network Ports
# =============================================================================

def test_shortened_and_ip_indicators():
    """Verify shortener and IP-address indicators are accurately extracted."""
    extractor = MlFeatureExtractor()

    # Shorteners
    short_bitly = extractor.extract_dict("https://bit.ly/3xyz123")
    short_tiny = extractor.extract_dict("https://tinyurl.com/sample456")
    assert short_bitly["is_shortened_url"] == 1.0
    assert short_tiny["is_shortened_url"] == 1.0

    # Non-shortener
    regular = extractor.extract_dict("https://www.example.com/test")
    assert regular["is_shortened_url"] == 0.0

    # IP address hosts
    ip_url = extractor.extract_dict("http://192.168.1.1:8080/setup")
    assert ip_url["is_ip_address"] == 1.0
    assert ip_url["is_private_ip"] == 1.0
    assert ip_url["is_standard_port"] == 0.0  # port 8080 is non-standard

    standard_port = extractor.extract_dict("https://www.google.com:443/")
    assert standard_port["is_standard_port"] == 1.0


# =============================================================================
# 6. Encoded Characters, Deep Subdomains, and Long Paths
# =============================================================================

def test_encoded_and_deep_subdomains():
    """Verify handling of percent-encoded and deeply nested subdomain structures."""
    extractor = MlFeatureExtractor()

    # Encoded characters
    enc_url = "http://victim-portal.com/login?token=%20admin%2520root"
    feat_enc = extractor.extract_dict(enc_url)
    assert feat_enc["is_encoded"] == 1.0
    assert feat_enc["is_double_encoded"] == 1.0

    # Deep subdomains
    deep_url = "http://secure.account.verify.client.portal.phish.com/auth"
    feat_deep = extractor.extract_dict(deep_url)
    assert feat_deep["num_subdomains"] >= 4
    assert feat_deep["path_to_url_ratio"] > 0.0


# =============================================================================
# 7. Missing Domain Telemetry and Malformed Inputs
# =============================================================================

@pytest.mark.parametrize(
    "malformed_url",
    [
        "",
        "   ",
        "http://",
        "invalid://:::",
        "ftp://",
    ],
)
def test_malformed_and_empty_inputs_graceful_handling(malformed_url: str):
    """Ensure malformed or empty inputs do not raise unhandled exceptions."""
    svc = get_ml_service()
    res = svc.predict(malformed_url)
    assert res.predicted_label == "legitimate"
    assert res.malicious_probability >= 0.0

    response = client.post("/api/v1/analyze-url", json={"url": malformed_url})
    # Returns handled 200 with fallback, 400 bad request, or 422 validation
    assert response.status_code in (200, 400, 422)


def test_missing_domain_telemetry_imputation():
    """Ensure missing domain data does not unfairly penalize a URL."""
    svc = get_ml_service()
    url = "https://www.example.com/clean/test"

    # Missing domain telemetry (None passed)
    res_missing = svc.predict(url, domain_data=None)
    assert res_missing.predicted_label == "legitimate"
    assert res_missing.malicious_probability < res_missing.decision_threshold


# =============================================================================
# 8. Feature Parity Between Training and Inference Pipeline
# =============================================================================

def test_feature_parity_training_and_inference():
    """Verify training-time and inference-time feature extraction extract identical 57 features."""
    extractor = MlFeatureExtractor()
    url = "https://sub.testdomain.com:8443/auth/action.php?user=admin&token=xyz#anchor"

    feat_dict = extractor.extract_dict(url)
    feat_vec = extractor.extract_vector(url)

    assert len(FEATURE_NAMES) == 57
    assert len(feat_dict) == 57
    assert feat_vec.shape == (57,)

    for idx, name in enumerate(FEATURE_NAMES):
        assert name in feat_dict
        assert feat_vec[idx] == pytest.approx(feat_dict[name], rel=1e-5)


# =============================================================================
# 9. Threshold Calibration & Confusion Matrix Math (Zero-Division Safe)
# =============================================================================

def test_threshold_calibration_and_zero_division_safety():
    """Verify threshold evaluation correctly calculates FPR and FNR and handles zero division."""
    pipeline = MlTrainingPipeline()

    # Synthetic predictions and labels
    y_true = np.array([0, 0, 0, 1, 1, 1, 0, 1])
    y_probs = np.array([0.1, 0.2, 0.3, 0.7, 0.8, 0.9, 0.15, 0.85])

    opt_thresh, grid, best = pipeline._calibrate_decision_threshold(
        y_true=y_true,
        y_probs=y_probs,
        max_fpr=0.05,
        min_thresh=0.20,
        max_thresh=0.80,
        steps=31,
    )

    assert 0.20 <= opt_thresh <= 0.80
    assert len(grid) == 31
    assert "fpr" in best
    assert "fnr" in best
    assert best["fpr"] <= 0.05

    # Test edge case with all-zero predictions (zero division safe)
    all_zero_true = np.array([0, 0, 0, 0])
    all_zero_probs = np.array([0.0, 0.0, 0.0, 0.0])
    thresh, grid_zero, best_zero = pipeline._calibrate_decision_threshold(
        y_true=all_zero_true,
        y_probs=all_zero_probs,
        max_fpr=0.05,
    )
    assert 0.0 <= best_zero["fpr"] <= 1.0
    assert 0.0 <= best_zero["fnr"] <= 1.0
