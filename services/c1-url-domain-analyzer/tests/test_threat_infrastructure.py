"""Unit tests for Threat-Infrastructure Analysis Layer.

Tests DGA statistical analysis, URL shortener detection, SSRF & DNS-rebinding security prevention,
and controlled HTTP redirect-chain resolution using mocked responses.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.analyzers.dga_analyzer import DgaAnalyzer
from app.analyzers.redirect_analyzer import (
    ControlledRedirectResolver,
    RedirectFeatureExtractor,
    ShortenerDetector,
)
from app.analyzers.threat_infrastructure import ThreatInfrastructureAnalyzer
from app.schemas.url_schema import RedirectHop
from app.utils.ssrf_validator import SsrfValidator, is_ip_blocked


@pytest.fixture
def dga_analyzer() -> DgaAnalyzer:
    return DgaAnalyzer()


@pytest.fixture
def shortener_detector() -> ShortenerDetector:
    return ShortenerDetector()


@pytest.fixture
def ssrf_validator() -> SsrfValidator:
    return SsrfValidator()


@pytest.fixture
def redirect_resolver() -> ControlledRedirectResolver:
    return ControlledRedirectResolver()


@pytest.fixture
def threat_infra_analyzer() -> ThreatInfrastructureAnalyzer:
    return ThreatInfrastructureAnalyzer()


# ---------------------------------------------------------------------------
# 1. DGA (Domain Generation Algorithm) Statistical Analysis Tests
# ---------------------------------------------------------------------------

def test_dga_legitimate_domains(dga_analyzer: DgaAnalyzer):
    """Verify that legitimate natural language domains are not flagged as DGA."""
    benign_domains = ["google.com", "wikipedia.org", "microsoft.com", "bankofamerica.com"]
    for dom in benign_domains:
        res = dga_analyzer.analyze(dom)
        assert res.is_dga_suspected is False
        assert res.dga_score < 0.60
        assert res.vowel_ratio >= 0.15


def test_dga_algorithmic_domains(dga_analyzer: DgaAnalyzer):
    """Verify that pseudo-random, high-entropy DGA labels are detected."""
    # 1. Random high-entropy consonant clustering
    res1 = dga_analyzer.analyze("brtklpqzxwv.org")
    assert res1.is_dga_suspected is True
    assert res1.max_consecutive_consonants >= 6
    assert res1.dga_score >= 0.60

    # 2. Hexadecimal hash DGA (e.g. 16-character md5/hash style label)
    res2 = dga_analyzer.analyze("d3d5f8a9c2e1f4b7.info")
    assert res2.is_dga_suspected is True
    assert res2.dga_family_hint == "hex_hash_dga"

    # 3. Interleaved high-entropy random string
    res3 = dga_analyzer.analyze("xjfkf893nkajs.biz")
    assert res3.is_dga_suspected is True
    assert res3.label_entropy >= 3.0


def test_dga_empty_input(dga_analyzer: DgaAnalyzer):
    res = dga_analyzer.analyze("")
    assert res.is_dga_suspected is False
    assert res.label_length == 0


# ---------------------------------------------------------------------------
# 2. URL Shortener Recognition Tests
# ---------------------------------------------------------------------------

def test_shortener_recognition(shortener_detector: ShortenerDetector):
    """Verify recognition of known URL shortener providers."""
    short_urls = [
        ("https://bit.ly/3xY7kL", True, "Bit"),
        ("http://tinyurl.com/abc1234", True, "Tinyurl"),
        ("https://rebrand.ly/special-deal", True, "Rebrand"),
        ("https://t.co/9xK2mN", True, "T"),
        ("https://is.gd/short", True, "Is"),
        ("https://cutt.ly/token", True, "Cutt"),
    ]

    for url, expected_bool, expected_provider in short_urls:
        is_short, provider = shortener_detector.detect(url)
        assert is_short is expected_bool
        if expected_provider:
            assert expected_provider in (provider or "")

    # Non-shortener check
    is_short, provider = shortener_detector.detect("https://www.google.com/search?q=test")
    assert is_short is False
    assert provider is None


# ---------------------------------------------------------------------------
# 3. SSRF & DNS-Rebinding Security Prevention Tests
# ---------------------------------------------------------------------------

def test_ssrf_ip_blocking():
    """Verify that private, loopback, link-local, and cloud metadata IPs are blocked."""
    # Loopback
    assert is_ip_blocked("127.0.0.1")[0] is True
    assert is_ip_blocked("::1")[0] is True

    # RFC-1918 Private
    assert is_ip_blocked("10.0.0.1")[0] is True
    assert is_ip_blocked("172.16.5.5")[0] is True
    assert is_ip_blocked("192.168.1.1")[0] is True

    # Cloud Metadata
    assert is_ip_blocked("169.254.169.254")[0] is True
    assert is_ip_blocked("100.100.100.200")[0] is True

    # Link-local & Reserved
    assert is_ip_blocked("169.254.1.1")[0] is True
    assert is_ip_blocked("0.0.0.0")[0] is True

    # Safe Public IPs
    assert is_ip_blocked("8.8.8.8")[0] is False
    assert is_ip_blocked("93.184.216.34")[0] is False


def test_ssrf_validator_urls(ssrf_validator: SsrfValidator):
    """Verify URL validation against scheme abuse and cloud metadata hostnames."""
    # Disallowed schemes
    assert ssrf_validator.validate_url("file:///etc/passwd")[0] is False
    assert ssrf_validator.validate_url("gopher://127.0.0.1:6379")[0] is False
    assert ssrf_validator.validate_url("ftp://internal.repo")[0] is False

    # Prohibited metadata hostnames
    assert ssrf_validator.validate_url("http://metadata.google.internal/computeMetadata")[0] is False

    # Direct private IP URL
    assert ssrf_validator.validate_url("http://192.168.1.1/router-login")[0] is False


# ---------------------------------------------------------------------------
# 4. Decoupled Redirect Feature Extractor Tests (Offline Unit Testing)
# ---------------------------------------------------------------------------

def test_redirect_feature_extractor():
    """Test pure offline feature derivation from simulated hop structures."""
    extractor = RedirectFeatureExtractor()

    simulated_hops = [
        RedirectHop(
            hop_number=0,
            url="https://bit.ly/promo",
            domain="bit.ly",
            status_code=301,
            resolved_ip="67.199.248.11",
            is_cross_domain=False,
            location_header="https://intermediate.link/track",
        ),
        RedirectHop(
            hop_number=1,
            url="https://intermediate.link/track",
            domain="intermediate.link",
            status_code=302,
            resolved_ip="198.51.100.2",
            is_cross_domain=True,
            location_header="https://final-destination.com/landing",
        ),
        RedirectHop(
            hop_number=2,
            url="https://final-destination.com/landing",
            domain="final-destination.com",
            status_code=200,
            resolved_ip="203.0.113.5",
            is_cross_domain=True,
            location_header=None,
        ),
    ]

    features = extractor.extract_features(
        original_url="https://bit.ly/promo",
        chain_hops=simulated_hops,
        is_shortened=True,
        shortener_provider="Bitly",
    )

    assert features.total_hops == 2
    assert features.is_redirected is True
    assert features.has_cross_domain_redirect is True
    assert features.destination_domain_changed is True
    assert features.final_url == "https://final-destination.com/landing"
    assert any("URL shortener detected" in ind for ind in features.redirect_indicators)
    assert any("Cross-domain redirect" in ind for ind in features.redirect_indicators)


# ---------------------------------------------------------------------------
# 5. Controlled Redirect Resolver Tests with Mocked HTTP
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_redirect_resolver_shortener_resolution_mock(redirect_resolver: ControlledRedirectResolver):
    """Test resolution of shortened URL with mocked HTTP responses."""
    mock_resp_head1 = MagicMock()
    mock_resp_head1.status_code = 301
    mock_resp_head1.headers = {"location": "https://destination-store.com/item"}

    mock_resp_head2 = MagicMock()
    mock_resp_head2.status_code = 200
    mock_resp_head2.headers = {}

    with patch.object(redirect_resolver.ssrf_validator, "validate_url", return_value=(True, "Safe", ["93.184.216.34"])), \
         patch("httpx.AsyncClient.head", side_effect=[mock_resp_head1, mock_resp_head2]):

        result = await redirect_resolver.resolve("https://bit.ly/test321")

        assert result.is_shortened is True
        assert result.total_hops == 1
        assert result.is_redirected is True
        assert result.final_url == "https://destination-store.com/item"
        assert result.destination_domain_changed is True


@pytest.mark.asyncio
async def test_redirect_resolver_loop_detection_mock(redirect_resolver: ControlledRedirectResolver):
    """Test safe termination when a cyclic redirect loop is encountered."""
    mock_loop_a = MagicMock()
    mock_loop_a.status_code = 302
    mock_loop_a.headers = {"location": "https://loop-site.com/b"}

    mock_loop_b = MagicMock()
    mock_loop_b.status_code = 302
    mock_loop_b.headers = {"location": "https://loop-site.com/a"}

    with patch.object(redirect_resolver.ssrf_validator, "validate_url", return_value=(True, "Safe", ["93.184.216.34"])), \
         patch("httpx.AsyncClient.head", side_effect=[mock_loop_a, mock_loop_b]):

        result = await redirect_resolver.resolve("https://loop-site.com/a")

        assert result.has_redirect_loop is True
        assert any("Cyclic redirect loop" in ind for ind in result.redirect_indicators)


@pytest.mark.asyncio
async def test_redirect_resolver_ssrf_hop_blocking_mock(redirect_resolver: ControlledRedirectResolver):
    """Verify that an HTTP redirect targeting a private/cloud IP is blocked before connection."""
    mock_initial = MagicMock()
    mock_initial.status_code = 302
    mock_initial.headers = {"location": "http://169.254.169.254/latest/meta-data/"}

    def mock_validate(target_url):
        if "169.254.169.254" in target_url:
            return False, "Prohibited cloud metadata address", ["169.254.169.254"]
        return True, "Safe", ["93.184.216.34"]

    with patch.object(redirect_resolver.ssrf_validator, "validate_url", side_effect=mock_validate), \
         patch("httpx.AsyncClient.head", return_value=mock_initial):

        result = await redirect_resolver.resolve("https://legit-looking-shortener.com/redir")

        assert result.ssrf_blocked is True
        assert any("SSRF Security Violation" in ind for ind in result.redirect_indicators)


# ---------------------------------------------------------------------------
# 6. Integrated Threat Infrastructure Analyzer Tests
# ---------------------------------------------------------------------------

from app.schemas.url_schema import RedirectChainFeatures, RedirectHop


@pytest.mark.asyncio
async def test_threat_infrastructure_integrated(threat_infra_analyzer: ThreatInfrastructureAnalyzer):
    """Test consolidated threat infrastructure analysis on an algorithmic shortener URL."""
    mock_redirect = RedirectChainFeatures(
        original_url="https://bit.ly/suspicious",
        final_url="https://xjfkf893nkajs.biz/landing",
        is_shortened=True,
        shortener_provider="Bitly",
        total_hops=1,
        is_redirected=True,
        has_redirect_loop=False,
        has_cross_domain_redirect=True,
        has_excessive_redirects=False,
        destination_domain_changed=True,
        ssrf_blocked=False,
        error_message=None,
        chain_hops=[
            RedirectHop(
                hop_number=0,
                url="https://bit.ly/suspicious",
                domain="bit.ly",
                status_code=301,
                resolved_ip="67.199.248.11",
                is_cross_domain=False,
                location_header="https://xjfkf893nkajs.biz/landing",
            ),
            RedirectHop(
                hop_number=1,
                url="https://xjfkf893nkajs.biz/landing",
                domain="xjfkf893nkajs.biz",
                status_code=200,
                resolved_ip="198.51.100.10",
                is_cross_domain=True,
                location_header=None,
            ),
        ],
        redirect_indicators=["Cross-domain redirect from bit.ly to xjfkf893nkajs.biz."],
    )

    with patch.object(threat_infra_analyzer.redirect_resolver, "resolve", AsyncMock(return_value=mock_redirect)):
        report = await threat_infra_analyzer.analyze("https://bit.ly/suspicious", "xjfkf893nkajs.biz")

        assert report.dga.is_dga_suspected is True
        assert report.redirect_chain.is_shortened is True
        assert report.infrastructure_risk_score >= 35.0
        assert len(report.infrastructure_indicators) >= 2
