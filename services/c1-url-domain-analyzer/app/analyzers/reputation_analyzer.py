"""Domain Reputation & Malware Infrastructure Analyzer.

Performs evidence-based identification of potential malware-distribution infrastructure,
bulletproof hosting patterns, and dynamic DNS abuse.
Supports optional external threat-intelligence feeds (e.g., VirusTotal, ThreatFox)
when configured via environment variables, with full offline/local heuristic fallback.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

from app.config import get_settings
from app.schemas.url_schema import DomainReputationFeatures

logger = logging.getLogger(__name__)


class ReputationAnalyzer:
    """Analyzer for evaluating domain reputation and threat intelligence indicators."""

    def __init__(self) -> None:
        self.settings = get_settings()

    async def analyze(
        self,
        domain_name: str,
        is_dynamic_dns: bool = False,
        is_nrd: bool = False,
    ) -> DomainReputationFeatures:
        """Evaluate reputation for the specified domain.

        Checks external threat intelligence APIs if credentials are configured in environment variables,
        otherwise performs local heuristic threat indicator evaluation.
        """
        clean_domain = domain_name.strip().lower().strip(".")
        if not clean_domain:
            return self._empty_features()

        # 1. Check external threat intelligence if API keys are configured
        if self.settings.virustotal_api_key:
            vt_result = await self._check_virustotal(clean_domain)
            if vt_result.threat_feed_checked:
                return vt_result

        if self.settings.threatfox_api_key:
            tf_result = await self._check_threatfox(clean_domain)
            if tf_result.threat_feed_checked:
                return tf_result

        # 2. Local heuristic & infrastructure indicator evaluation
        return self._local_heuristic_check(clean_domain, is_dynamic_dns=is_dynamic_dns, is_nrd=is_nrd)

    def _local_heuristic_check(
        self,
        domain: str,
        is_dynamic_dns: bool,
        is_nrd: bool,
    ) -> DomainReputationFeatures:
        """Evaluate reputation based on local threat heuristics and infrastructure patterns."""
        indicators: List[str] = []
        is_threat = False
        threat_type: Optional[str] = None
        confidence = 0.0

        # Pattern 1: Dynamic DNS provider combined with newly registered domain
        if is_dynamic_dns and is_nrd:
            is_threat = True
            threat_type = "disposable_c2_infrastructure"
            confidence = 0.75
            indicators.append("Dynamic DNS domain combined with newly registered status (frequent C2/malware delivery pattern).")
        elif is_dynamic_dns:
            indicators.append("Hosted on dynamic DNS provider commonly leveraged for ephemeral C2 infrastructure.")
            confidence = 0.35

        # Pattern 2: Suspicious TLD check
        tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
        if tld in self.settings.suspicious_tlds:
            indicators.append(f"Domain registered under high-abuse TLD (.{tld}).")
            confidence = max(confidence, 0.40)

        return DomainReputationFeatures(
            threat_feed_checked=False,
            is_known_threat=is_threat,
            threat_type=threat_type,
            confidence_score=round(confidence, 2),
            reputation_source="local_heuristic",
            reputation_indicators=indicators,
        )

    async def _check_virustotal(self, domain: str) -> DomainReputationFeatures:
        """Query VirusTotal v3 domain report if API key is provided."""
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": self.settings.virustotal_api_key}

        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                res = await client.get(url, headers=headers)
                if res.status_code == 200:
                    data = res.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)

                    indicators: List[str] = []
                    is_known = malicious >= 3
                    if is_known:
                        indicators.append(f"VirusTotal detected {malicious} security vendors flagging domain as malicious.")
                    elif suspicious > 0 or malicious > 0:
                        indicators.append(f"VirusTotal flagged {malicious} malicious / {suspicious} suspicious vendor verdicts.")

                    total_verdicts = sum(stats.values()) or 1
                    conf = round((malicious * 1.0 + suspicious * 0.5) / total_verdicts, 2)

                    return DomainReputationFeatures(
                        threat_feed_checked=True,
                        is_known_threat=is_known,
                        threat_type="malware_distribution" if is_known else None,
                        confidence_score=min(1.0, conf),
                        reputation_source="virustotal",
                        reputation_indicators=indicators,
                    )
        except Exception as exc:
            logger.debug("VirusTotal query failed for %s: %s", domain, exc)

        return DomainReputationFeatures(
            threat_feed_checked=False,
            is_known_threat=False,
            threat_type=None,
            confidence_score=0.0,
            reputation_source="virustotal_unavailable",
            reputation_indicators=[],
        )

    async def _check_threatfox(self, domain: str) -> DomainReputationFeatures:
        """Query ThreatFox API if API key is provided."""
        url = "https://threatfox-api.abuse.ch/api/v1/"
        headers = {"API-KEY": self.settings.threatfox_api_key}
        payload = {"query": "search_ioc", "search_term": domain}

        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                res = await client.post(url, json=payload, headers=headers)
                if res.status_code == 200:
                    data = res.json()
                    status = data.get("query_status", "")
                    if status == "ok" and data.get("data"):
                        ioc_records = data.get("data", [])
                        threat_type = ioc_records[0].get("threat_type_desc", "malware")
                        return DomainReputationFeatures(
                            threat_feed_checked=True,
                            is_known_threat=True,
                            threat_type=threat_type,
                            confidence_score=0.90,
                            reputation_source="threatfox",
                            reputation_indicators=[f"ThreatFox confirmed IOC match: {threat_type}."],
                        )
        except Exception as exc:
            logger.debug("ThreatFox query failed for %s: %s", domain, exc)

        return DomainReputationFeatures(
            threat_feed_checked=False,
            is_known_threat=False,
            threat_type=None,
            confidence_score=0.0,
            reputation_source="threatfox_unavailable",
            reputation_indicators=[],
        )

    def _empty_features(self) -> DomainReputationFeatures:
        """Return zeroed features model for empty domain input."""
        return DomainReputationFeatures(
            threat_feed_checked=False,
            is_known_threat=False,
            threat_type=None,
            confidence_score=0.0,
            reputation_source="none",
            reputation_indicators=[],
        )
