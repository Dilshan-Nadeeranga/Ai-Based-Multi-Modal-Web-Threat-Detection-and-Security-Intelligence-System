"""DNS Infrastructure & Configuration Intelligence Analyzer.

Performs non-blocking DNS queries for A, AAAA, MX, NS, and TXT records using dnspython.
Identifies unusual or suspicious DNS configurations such as fast-flux hosting patterns,
private IP resolutions, dynamic DNS provider usage, and missing mail exchanger hygiene.

Crucially: Missing DNS records are NOT interpreted as proof of malicious activity.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, List, Optional, Tuple

import dns.exception
import dns.rdatatype
import dns.resolver

from app.config import get_settings
from app.schemas.url_schema import DnsIntelligenceFeatures

logger = logging.getLogger(__name__)


class DnsAnalyzer:
    """DNS analyzer for querying resource records and evaluating infrastructure indicators."""

    def __init__(self) -> None:
        self.settings = get_settings()

    def _get_resolver(self) -> dns.resolver.Resolver:
        """Create and configure a dnspython resolver instance."""
        resolver = dns.resolver.Resolver()
        resolver.lifetime = self.settings.dns_timeout_seconds
        resolver.timeout = self.settings.dns_timeout_seconds
        if self.settings.custom_dns_servers:
            try:
                resolver.nameservers = self.settings.custom_dns_servers
            except Exception as exc:
                logger.debug("Failed to set custom nameservers: %s; using system default", exc)
        return resolver

    def analyze(self, domain_name: str) -> DnsIntelligenceFeatures:
        """Query DNS for domain records and extract infrastructure features.

        Safely handles timeouts, NXDOMAIN, and resolution failures without
        treating absence of records as proof of malicious activity.
        """
        clean_domain = domain_name.strip().lower().strip(".")
        if not clean_domain:
            return self._empty_features()

        resolver = self._get_resolver()

        a_records: List[str] = []
        aaaa_records: List[str] = []
        mx_records: List[str] = []
        ns_records: List[str] = []
        txt_records: List[str] = []
        ttls: List[int] = []
        dns_indicators: List[str] = []

        # 1. Query A records (IPv4)
        try:
            answers_a = resolver.resolve(clean_domain, dns.rdatatype.A)
            for rdata in answers_a:
                a_records.append(rdata.address)
            if answers_a.rrset and answers_a.rrset.ttl is not None:
                ttls.append(int(answers_a.rrset.ttl))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        except Exception as exc:
            logger.debug("Error querying A records for %s: %s", clean_domain, exc)

        # 2. Query AAAA records (IPv6)
        try:
            answers_aaaa = resolver.resolve(clean_domain, dns.rdatatype.AAAA)
            for rdata in answers_aaaa:
                aaaa_records.append(rdata.address)
            if answers_aaaa.rrset and answers_aaaa.rrset.ttl is not None:
                ttls.append(int(answers_aaaa.rrset.ttl))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        except Exception as exc:
            logger.debug("Error querying AAAA records for %s: %s", clean_domain, exc)

        # 3. Query MX records (Mail Exchanger)
        try:
            answers_mx = resolver.resolve(clean_domain, dns.rdatatype.MX)
            for rdata in answers_mx:
                mx_records.append(f"{rdata.preference} {str(rdata.exchange).rstrip('.')}")
            if answers_mx.rrset and answers_mx.rrset.ttl is not None:
                ttls.append(int(answers_mx.rrset.ttl))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        except Exception as exc:
            logger.debug("Error querying MX records for %s: %s", clean_domain, exc)

        # 4. Query NS records (Name Servers)
        try:
            answers_ns = resolver.resolve(clean_domain, dns.rdatatype.NS)
            for rdata in answers_ns:
                ns_records.append(str(rdata.target).rstrip('.'))
            if answers_ns.rrset and answers_ns.rrset.ttl is not None:
                ttls.append(int(answers_ns.rrset.ttl))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        except Exception as exc:
            logger.debug("Error querying NS records for %s: %s", clean_domain, exc)

        # 5. Query TXT records (SPF, verification, etc.)
        try:
            answers_txt = resolver.resolve(clean_domain, dns.rdatatype.TXT)
            for rdata in answers_txt:
                txt_str = b"".join(rdata.strings).decode("utf-8", errors="replace")
                txt_records.append(txt_str)
            if answers_txt.rrset and answers_txt.rrset.ttl is not None:
                ttls.append(int(answers_txt.rrset.ttl))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        except Exception as exc:
            logger.debug("Error querying TXT records for %s: %s", clean_domain, exc)

        # 6. Query DMARC record (_dmarc.<domain>)
        has_dmarc = False
        try:
            answers_dmarc = resolver.resolve(f"_dmarc.{clean_domain}", dns.rdatatype.TXT)
            for rdata in answers_dmarc:
                dmarc_str = b"".join(rdata.strings).decode("utf-8", errors="replace")
                if "v=DMARC1" in dmarc_str.upper():
                    has_dmarc = True
                    break
        except Exception:
            pass

        # Evaluate derived metrics
        has_mx_records = len(mx_records) > 0
        has_spf = any("v=spf1" in t.lower() for t in txt_records)
        min_ttl = min(ttls) if ttls else None
        ip_count = len(a_records)
        dns_resolved = bool(a_records or aaaa_records or ns_records or mx_records)

        # Private IP resolution detection (RFC 1918 / Loopback / CGNAT / Link-Local)
        is_private_ip_resolved = False
        for ip in a_records:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                    is_private_ip_resolved = True
                    dns_indicators.append(f"Domain resolves to private/internal IP address: {ip}")
            except ValueError:
                continue

        # Fast-flux hosting pattern: Multiple IP addresses rotating with unusually short TTL (<= 300s)
        is_fast_flux = False
        if ip_count >= 5 and min_ttl is not None and min_ttl <= 300:
            is_fast_flux = True
            dns_indicators.append(
                f"Potential fast-flux DNS network: {ip_count} IPs with low TTL ({min_ttl}s)."
            )

        # Dynamic DNS provider detection
        is_dynamic_dns = False
        for ddns_host in self.settings.dynamic_dns_domains:
            if clean_domain == ddns_host or clean_domain.endswith(f".{ddns_host}"):
                is_dynamic_dns = True
                dns_indicators.append(f"Domain hosted under dynamic DNS provider: {ddns_host}")
                break

        if not dns_resolved:
            dns_indicators.append("Domain does not currently resolve in DNS (NXDOMAIN or inactive).")

        return DnsIntelligenceFeatures(
            a_records=a_records,
            aaaa_records=aaaa_records,
            mx_records=mx_records,
            ns_records=ns_records,
            txt_records=txt_records,
            has_mx_records=has_mx_records,
            has_spf=has_spf,
            has_dmarc=has_dmarc,
            min_ttl=min_ttl,
            ip_count=ip_count,
            is_fast_flux=is_fast_flux,
            is_dynamic_dns=is_dynamic_dns,
            is_private_ip_resolved=is_private_ip_resolved,
            dns_resolved=dns_resolved,
            dns_indicators=dns_indicators,
        )

    def _empty_features(self) -> DnsIntelligenceFeatures:
        """Return zeroed features model when domain name is empty."""
        return DnsIntelligenceFeatures(
            a_records=[],
            aaaa_records=[],
            mx_records=[],
            ns_records=[],
            txt_records=[],
            has_mx_records=False,
            has_spf=False,
            has_dmarc=False,
            min_ttl=None,
            ip_count=0,
            is_fast_flux=False,
            is_dynamic_dns=False,
            is_private_ip_resolved=False,
            dns_resolved=False,
            dns_indicators=["Empty domain provided."],
        )
