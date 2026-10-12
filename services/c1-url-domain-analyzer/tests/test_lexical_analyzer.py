"""Unit tests for Layer 1 URL Lexical Feature Extraction Engine."""

from __future__ import annotations

import pytest
from app.analyzers.lexical_analyzer import (
    UrlLexicalAnalyzer,
    calculate_shannon_entropy,
    detect_homoglyphs_and_unicode,
    parse_ip_address,
)


@pytest.fixture
def analyzer() -> UrlLexicalAnalyzer:
    return UrlLexicalAnalyzer()


def test_calculate_shannon_entropy():
    # Identical chars -> 0 entropy
    assert calculate_shannon_entropy("aaaaa") == 0.0
    # High entropy random string -> > 3.5 bits/char
    high_ent = calculate_shannon_entropy("aB9#xZ1$qL7&")
    assert high_ent > 3.0
    # Empty string -> 0.0
    assert calculate_shannon_entropy("") == 0.0


def test_standard_legitimate_url(analyzer: UrlLexicalAnalyzer):
    url = "https://www.google.com/search?q=cybersecurity"
    result = analyzer.analyze(url)

    assert result.status == "success"
    assert result.risk_level == "Low Risk"
    assert result.score < 25.0

    feat = result.features
    assert feat.hostname == "www.google.com"
    assert feat.registered_domain == "google.com"
    assert feat.subdomain == "www"
    assert feat.tld == "com"
    assert feat.is_ip_address is False
    assert feat.has_at_symbol is False
    assert feat.has_homoglyphs is False
    assert feat.num_dots >= 2
    assert feat.url_length == len(url)


def test_ip_address_urls(analyzer: UrlLexicalAnalyzer):
    # Standard IPv4
    res_v4 = analyzer.analyze("http://192.168.1.1/admin/login")
    assert res_v4.features.is_ip_address is True
    assert res_v4.features.ip_type == "ipv4"
    assert res_v4.features.is_private_ip is True

    # Hexadecimal IP
    res_hex = analyzer.analyze("http://0xC0A80101/index.html")
    assert res_hex.features.is_ip_address is True
    assert res_hex.features.ip_type == "hex_ip"
    assert res_hex.features.has_hex_obfuscation is True

    # Octal IP
    res_oct = analyzer.analyze("http://0300.0250.0001.0001/")
    assert res_oct.features.is_ip_address is True
    assert res_oct.features.ip_type == "octal_ip"


def test_homoglyph_and_punycode_urls(analyzer: UrlLexicalAnalyzer):
    # Cyrillic lookalike 'а' (U+0430) and 'р' (U+0440)
    cyrillic_url = "http://\u0440a\u0443\u0440al.com/verify"
    res_homo = analyzer.analyze(cyrillic_url)
    assert res_homo.features.has_homoglyphs is True
    assert len(res_homo.features.homoglyph_details) > 0

    # Punycode prefix xn--
    puny_url = "http://xn--e1afmkfd.xn--p1ai/path"
    res_puny = analyzer.analyze(puny_url)
    assert res_puny.features.is_punycode is True


def test_obfuscation_and_delimiters(analyzer: UrlLexicalAnalyzer):
    # @ symbol in authority
    at_url = "http://legit.com@phishing-server.com/login"
    res_at = analyzer.analyze(at_url)
    assert res_at.features.has_at_symbol is True

    # Double percent encoding
    double_enc_url = "https://example.com/search?q=%2520login%2520page"
    res_enc = analyzer.analyze(double_enc_url)
    assert res_enc.features.is_encoded is True
    assert res_enc.features.is_double_encoded is True


def test_suspicious_phishing_combo(analyzer: UrlLexicalAnalyzer):
    url = "http://login.paypal.verify-account.update.secure-bank.top/auth/login.php?user=123"
    result = analyzer.analyze(url)

    assert result.risk_level in ("Medium Risk", "High Risk Scam")
    assert result.score >= 50.0
    feat = result.features

    assert feat.is_suspicious_tld is True
    assert feat.has_suspicious_keyword is True
    assert len(feat.suspicious_keywords_found) >= 3
    assert feat.num_subdomains >= 3


def test_single_keyword_no_false_positive(analyzer: UrlLexicalAnalyzer):
    # A single keyword on a clean domain should NOT produce High Risk Scam
    url = "https://security.google.com/"
    result = analyzer.analyze(url)

    assert result.risk_level in ("Low Risk", "Suspicious")
    assert result.score < 50.0


def test_empty_and_malformed_input(analyzer: UrlLexicalAnalyzer):
    res_empty = analyzer.analyze("")
    assert res_empty.status == "invalid_input"
    assert res_empty.score == 0.0

    res_none = analyzer.analyze(None)  # type: ignore
    assert res_none.status == "invalid_input"
