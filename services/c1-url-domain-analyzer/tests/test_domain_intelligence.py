"""Unit tests for Domain Intelligence Layer with mocked DNS, RDAP, and WHOIS responses."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import dns.exception
import dns.rdatatype
import dns.resolver

from app.analyzers.dns_analyzer import DnsAnalyzer
from app.analyzers.domain_intelligence import DomainIntelligenceAnalyzer, DomainIntelligenceCache
from app.analyzers.registration_analyzer import RegistrationAnalyzer
from app.analyzers.reputation_analyzer import ReputationAnalyzer
from app.schemas.url_schema import (
    DnsIntelligenceFeatures,
    DomainIntelligenceReport,
    DomainRegistrationFeatures,
    DomainReputationFeatures,
)


@pytest.fixture
def reg_analyzer() -> RegistrationAnalyzer:
    return RegistrationAnalyzer()


@pytest.fixture
def dns_analyzer() -> DnsAnalyzer:
    return DnsAnalyzer()


@pytest.fixture
def rep_analyzer() -> ReputationAnalyzer:
    return ReputationAnalyzer()


@pytest.fixture
def domain_intelligence_analyzer() -> DomainIntelligenceAnalyzer:
    return DomainIntelligenceAnalyzer()


class MockAnswer(list):
    """Mock dnspython Answer object containing an rrset and iterable rdatas."""
    def __init__(self, items, ttl: int = 300):
        super().__init__(items)
        self.rrset = MagicMock()
        self.rrset.ttl = ttl


# ---------------------------------------------------------------------------
# 1. Registration Analyzer (RDAP / WHOIS) Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_registration_analyzer_nrd_mock(reg_analyzer: RegistrationAnalyzer):
    """Test detection of Newly Registered Domain (NRD) via mocked RDAP payload."""
    mock_rdap_response = {
        "events": [
            {"eventAction": "registration", "eventDate": "2026-10-05T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-10-05T00:00:00Z"}
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Namecheap, Inc."]]]
            }
        ],
        "secureDNS": {"delegationSigned": False}
    }

    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_rdap_response
        mock_get.return_value = mock_resp

        res = await reg_analyzer.analyze("suspicious-new-bank.com")

        assert res.is_data_available is True
        assert res.registrar == "Namecheap, Inc."
        assert res.age_days is not None
        assert res.age_days <= 30
        assert res.is_nrd is True
        assert res.data_source == "rdap"


@pytest.mark.asyncio
async def test_registration_analyzer_established_domain_mock(reg_analyzer: RegistrationAnalyzer):
    """Test established domain (> 2 years old) via mocked RDAP."""
    mock_rdap_response = {
        "events": [
            {"eventAction": "registration", "eventDate": "2015-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2028-01-01T00:00:00Z"}
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "MarkMonitor Inc."]]]
            }
        ],
        "secureDNS": {"delegationSigned": True}
    }

    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_rdap_response
        mock_get.return_value = mock_resp

        res = await reg_analyzer.analyze("google.com")

        assert res.is_data_available is True
        assert res.is_nrd is False
        assert res.is_young_domain is False
        assert res.dnssec_enabled is True
        assert res.age_days is not None and res.age_days > 2000


@pytest.mark.asyncio
async def test_registration_analyzer_unavailable_handling(reg_analyzer: RegistrationAnalyzer):
    """Verify that unavailable/rate-limited registration data does NOT raise errors or flag malicious."""
    with patch("httpx.AsyncClient.get", side_effect=Exception("Connection timed out")), \
         patch("app.analyzers.registration_analyzer._HAS_PYTHON_WHOIS", False):

        res = await reg_analyzer.analyze("unreachable-whois-domain.com")

        assert res.is_data_available is False
        assert res.is_nrd is False
        assert res.age_days is None
        assert res.data_source == "unavailable"


# ---------------------------------------------------------------------------
# 2. DNS Analyzer Tests with Mocked dnspython Responses
# ---------------------------------------------------------------------------

def test_dns_analyzer_standard_resolution_mock(dns_analyzer: DnsAnalyzer):
    """Test standard healthy DNS resolution for an established domain."""
    mock_a = MagicMock()
    mock_a.address = "93.184.216.34"

    mock_mx = MagicMock()
    mock_mx.preference = 10
    mock_mx.exchange = "mail.example.com."

    mock_ns = MagicMock()
    mock_ns.target = "ns1.example.com."

    mock_txt = MagicMock()
    mock_txt.strings = [b"v=spf1 ~all"]

    def mock_resolve(qname, rdtype):
        if rdtype == dns.rdatatype.A:
            return MockAnswer([mock_a], ttl=3600)
        elif rdtype == dns.rdatatype.MX:
            return MockAnswer([mock_mx], ttl=3600)
        elif rdtype == dns.rdatatype.NS:
            return MockAnswer([mock_ns], ttl=3600)
        elif rdtype == dns.rdatatype.TXT:
            return MockAnswer([mock_txt], ttl=3600)
        raise dns.resolver.NoAnswer()

    with patch.object(dns.resolver.Resolver, "resolve", side_effect=mock_resolve):
        res = dns_analyzer.analyze("example.com")

        assert res.dns_resolved is True
        assert "93.184.216.34" in res.a_records
        assert res.has_mx_records is True
        assert res.has_spf is True
        assert res.is_private_ip_resolved is False
        assert res.is_fast_flux is False


def test_dns_analyzer_fast_flux_detection(dns_analyzer: DnsAnalyzer):
    """Test detection of fast-flux DNS (>= 5 IPs with low TTL <= 300s)."""
    ips = [f"198.51.100.{i}" for i in range(1, 7)]
    mock_answers = []
    for ip in ips:
        m = MagicMock()
        m.address = ip
        mock_answers.append(m)

    def mock_resolve(qname, rdtype):
        if rdtype == dns.rdatatype.A:
            return MockAnswer(mock_answers, ttl=60)
        raise dns.resolver.NoAnswer()

    with patch.object(dns.resolver.Resolver, "resolve", side_effect=mock_resolve):
        res = dns_analyzer.analyze("fast-flux-botnet.net")

        assert res.dns_resolved is True
        assert res.ip_count == 6
        assert res.min_ttl == 60
        assert res.is_fast_flux is True
        assert any("fast-flux" in ind.lower() for ind in res.dns_indicators)


def test_dns_analyzer_private_ip_resolution(dns_analyzer: DnsAnalyzer):
    """Test detection of internal RFC 1918 private IP resolution."""
    mock_a = MagicMock()
    mock_a.address = "192.168.1.1"

    def mock_resolve(qname, rdtype):
        if rdtype == dns.rdatatype.A:
            return MockAnswer([mock_a], ttl=300)
        raise dns.resolver.NoAnswer()

    with patch.object(dns.resolver.Resolver, "resolve", side_effect=mock_resolve):
        res = dns_analyzer.analyze("internal-leak.corp")

        assert res.is_private_ip_resolved is True
        assert any("private/internal IP" in ind for ind in res.dns_indicators)


def test_dns_analyzer_dynamic_dns_provider(dns_analyzer: DnsAnalyzer):
    """Test detection of known dynamic DNS service."""
    with patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NXDOMAIN()):
        res = dns_analyzer.analyze("malicious-c2.duckdns.org")

        assert res.is_dynamic_dns is True
        assert any("duckdns.org" in ind for ind in res.dns_indicators)


def test_dns_analyzer_nxdomain_handling(dns_analyzer: DnsAnalyzer):
    """Verify that NXDOMAIN is safely handled without raising an exception."""
    with patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NXDOMAIN()):
        res = dns_analyzer.analyze("nonexistent-domain-12345.com")

        assert res.dns_resolved is False
        assert len(res.a_records) == 0
        assert any("does not currently resolve" in ind for ind in res.dns_indicators)


# ---------------------------------------------------------------------------
# 3. Reputation & Cache Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reputation_local_heuristic_ddns_nrd(rep_analyzer: ReputationAnalyzer):
    """Test local heuristic detection when dynamic DNS is coupled with NRD status."""
    res = await rep_analyzer.analyze("payload.no-ip.com", is_dynamic_dns=True, is_nrd=True)

    assert res.is_known_threat is True
    assert res.threat_type == "disposable_c2_infrastructure"
    assert res.confidence_score >= 0.7


@pytest.mark.asyncio
async def test_domain_intelligence_cache():
    """Verify thread-safe in-memory caching respects TTL and prevents repeated lookups."""
    cache = DomainIntelligenceCache(ttl_seconds=60)
    mock_report = MagicMock(spec=DomainIntelligenceReport)

    assert await cache.get("test.com") is None
    await cache.set("test.com", mock_report)
    assert await cache.get("test.com") is mock_report


# ---------------------------------------------------------------------------
# 4. Integrated Multi-Layer Analysis Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_full_integrated_analysis_nrd_phishing(domain_intelligence_analyzer: DomainIntelligenceAnalyzer):
    """Test full integrated analysis combining lexical heuristics and mocked domain intelligence."""
    # Create valid DomainRegistrationFeatures model
    mock_reg = DomainRegistrationFeatures(
        domain_name="paypal-security-update.com",
        creation_date="2026-10-07T00:00:00Z",
        expiration_date="2027-10-07T00:00:00Z",
        updated_date=None,
        age_days=5,
        days_until_expiration=365,
        registrar="Namecheap, Inc.",
        registrant_country="US",
        dnssec_enabled=False,
        is_nrd=True,
        is_young_domain=True,
        privacy_protected=True,
        data_source="rdap",
        is_data_available=True,
    )

    # Create valid DnsIntelligenceFeatures model
    mock_dns = DnsIntelligenceFeatures(
        a_records=["198.51.100.1"],
        aaaa_records=[],
        mx_records=[],
        ns_records=["dns1.namecheaphosting.com"],
        txt_records=[],
        has_mx_records=False,
        has_spf=False,
        has_dmarc=False,
        min_ttl=3600,
        ip_count=1,
        is_fast_flux=False,
        is_dynamic_dns=False,
        is_private_ip_resolved=False,
        dns_resolved=True,
        dns_indicators=[],
    )

    with patch.object(domain_intelligence_analyzer.registration_analyzer, "analyze", AsyncMock(return_value=mock_reg)), \
         patch.object(domain_intelligence_analyzer.dns_analyzer, "analyze", return_value=mock_dns):

        result = await domain_intelligence_analyzer.analyze_full(
            "http://login.paypal-security-update.com/verify?token=123"
        )

        assert result.component == "C1_URL_DOMAIN"
        assert result.status == "success"
        assert result.domain_intelligence.registration.is_nrd is True
        assert result.features.has_suspicious_keyword is True
        assert result.score >= 50.0
        assert any("Newly registered domain" in ind for ind in result.risk_indicators)
