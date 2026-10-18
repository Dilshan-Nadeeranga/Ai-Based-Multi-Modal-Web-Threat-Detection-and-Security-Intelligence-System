"""Domain Intelligence Orchestrator & Multi-Layer Integration Engine.

Coordinates domain registration (RDAP/WHOIS), DNS configuration, and threat reputation analyzers.
Caches results to respect external service rate limits and calculates an evidence-based domain risk score.

Integrates seamlessly with Layer 1 URL lexical features to produce the comprehensive
Multi-Layer URL and Domain Intelligence Framework assessment.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Dict, List, Optional, Tuple

from app.analyzers.dns_analyzer import DnsAnalyzer
from app.analyzers.lexical_analyzer import UrlLexicalAnalyzer
from app.analyzers.registration_analyzer import RegistrationAnalyzer
from app.analyzers.reputation_analyzer import ReputationAnalyzer
from app.analyzers.risk_scoring_engine import ExplainableRiskScoringEngine
from app.analyzers.threat_infrastructure import ThreatInfrastructureAnalyzer
from app.config import get_settings
from app.schemas.url_schema import (
    CompleteUrlDomainAnalysisResult,
    DnsIntelligenceFeatures,
    DomainIntelligenceReport,
    DomainRegistrationFeatures,
    DomainReputationFeatures,
    ExplainableRiskAssessment,
    MlPredictionResult,
    ThreatInfrastructureReport,
    UrlLexicalFeatures,
)
from app.ml.model_service import get_ml_service

logger = logging.getLogger(__name__)


class DomainIntelligenceCache:
    """Thread-safe in-memory TTL cache for domain intelligence results."""

    def __init__(self, ttl_seconds: int = 3600) -> None:
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Tuple[float, DomainIntelligenceReport]] = {}
        self._lock = asyncio.Lock()

    async def get(self, domain: str) -> Optional[DomainIntelligenceReport]:
        """Retrieve cached domain report if not expired."""
        async with self._lock:
            entry = self._cache.get(domain)
            if entry:
                timestamp, report = entry
                if time.time() - timestamp < self.ttl_seconds:
                    return report
                del self._cache[domain]
            return None

    async def set(self, domain: str, report: DomainIntelligenceReport) -> None:
        """Store domain report with current timestamp."""
        async with self._lock:
            self._cache[domain] = (time.time(), report)


class DomainIntelligenceAnalyzer:
    """Orchestrator for Domain Intelligence Layer integrated with URL Lexical Analysis."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.lexical_analyzer = UrlLexicalAnalyzer()
        self.registration_analyzer = RegistrationAnalyzer()
        self.dns_analyzer = DnsAnalyzer()
        self.reputation_analyzer = ReputationAnalyzer()
        self.threat_infra_analyzer = ThreatInfrastructureAnalyzer()
        self.ml_service = get_ml_service()
        self.risk_scoring_engine = ExplainableRiskScoringEngine(self.settings)
        self.cache = DomainIntelligenceCache(ttl_seconds=self.settings.cache_ttl_seconds)


    async def analyze_domain(self, domain_name: str) -> DomainIntelligenceReport:
        """Run registration, DNS, and reputation intelligence on domain with caching."""
        clean_domain = domain_name.strip().lower().strip(".")
        if not clean_domain:
            return self._empty_domain_report("")

        # 1. Check in-memory cache
        cached = await self.cache.get(clean_domain)
        if cached:
            logger.debug("Returning cached domain intelligence for %s", clean_domain)
            return cached

        # 2. Run Registration & DNS checks concurrently
        # DNS query is run in worker thread to prevent blocking the async event loop
        loop = asyncio.get_running_loop()
        reg_task = asyncio.create_task(self.registration_analyzer.analyze(clean_domain))
        dns_task = loop.run_in_executor(None, self.dns_analyzer.analyze, clean_domain)

        registration_res, dns_res = await asyncio.gather(reg_task, dns_task)

        # 3. Run Reputation check with DNS and registration context
        reputation_res = await self.reputation_analyzer.analyze(
            clean_domain,
            is_dynamic_dns=dns_res.is_dynamic_dns,
            is_nrd=registration_res.is_nrd,
        )

        # 4. Compute evidence-based Domain Risk Score
        domain_score, indicators = self._compute_domain_risk_score(
            registration=registration_res,
            dns=dns_res,
            reputation=reputation_res,
        )

        report = DomainIntelligenceReport(
            registration=registration_res,
            dns=dns_res,
            reputation=reputation_res,
            domain_risk_score=domain_score,
            domain_risk_indicators=indicators,
        )

        # 5. Store in cache
        await self.cache.set(clean_domain, report)
        return report

    async def analyze_full(self, raw_url: str) -> CompleteUrlDomainAnalysisResult:
        """Execute full multi-layer analysis combining Lexical URL Analysis and Domain Intelligence."""
        # Layer 1: Extract lexical features
        lexical_features = self.lexical_analyzer.extract_features(raw_url)

        if not lexical_features.original_url:
            empty_domain_report = self._empty_domain_report("")
            return CompleteUrlDomainAnalysisResult(
                component="C1_URL_DOMAIN",
                layer="Multi_Layer_URL_and_Domain_Intelligence",
                status="invalid_input",
                url=raw_url or "",
                score=0.0,
                risk_level="Low Risk",
                verdict="SAFE",
                features=lexical_features,
                domain_intelligence=empty_domain_report,
                risk_indicators=["Empty or invalid URL provided."],
                explanation="Input URL was empty or contained only whitespace.",
            )

        # Layer 2: Determine target domain for domain intelligence
        target_domain = lexical_features.registered_domain or lexical_features.hostname

        # Skip DNS/RDAP for raw IP addresses (IPs are analyzed via IP features in Layer 1)
        if lexical_features.is_ip_address:
            domain_report = self._empty_domain_report(target_domain)
        else:
            domain_report = await self.analyze_domain(target_domain)

        # Layer 1 lexical evaluation
        lexical_result = self.lexical_analyzer.analyze(raw_url)

        # Layer 3: Threat-Infrastructure Analysis (DGA & Redirect Chains)
        infra_report = await self.threat_infra_analyzer.analyze(raw_url, target_domain)

        # Layer 4: Machine Learning Classifier Inference
        ml_res = self.ml_service.predict(raw_url, lexical_features)

        # Explainable Multi-Channel Risk Scoring Engine Evaluation
        risk_assessment = self.risk_scoring_engine.evaluate(
            raw_url=raw_url,
            lexical_features=lexical_features,
            domain_report=domain_report,
            infra_report=infra_report,
            ml_res=ml_res,
        )

        # Build unified human-readable indicators combining factors and observations
        unified_indicators: List[str] = []
        for factor in risk_assessment.contributing_factors:
            if factor.impact_score != 0:
                unified_indicators.append(f"{factor.title}: {factor.evidence}")

        # Also preserve direct domain observations for backwards compatibility
        if domain_report.registration.is_nrd and domain_report.registration.age_days is not None:
            nrd_str = f"Newly registered domain (Age: {domain_report.registration.age_days} days, threshold <= {self.settings.nrd_threshold_days} days)."
            if nrd_str not in unified_indicators:
                unified_indicators.append(nrd_str)

        for rep_ind in domain_report.domain_risk_indicators + infra_report.infrastructure_indicators:
            if rep_ind not in unified_indicators:
                unified_indicators.append(rep_ind)

        # Top contributing factors narrative explanation
        top_risks = [f.title for f in risk_assessment.contributing_factors if f.impact_score > 0][:3]
        if not top_risks:
            explanation = (
                f"Explainable multi-layer intelligence evaluated 8 channels and determined a normalized risk score "
                f"of {risk_assessment.risk_score}/100 ({risk_assessment.risk_level}). No critical scam indicators observed."
            )
        else:
            explanation = (
                f"Explainable risk engine assigned {risk_assessment.risk_score}/100 ({risk_assessment.risk_level}) "
                f"based on {len(risk_assessment.contributing_factors)} factor(s), primarily driven by: "
                f"{', '.join(top_risks)}."
            )

        return CompleteUrlDomainAnalysisResult(
            component="C1_URL_DOMAIN",
            layer="Multi_Layer_URL_and_Domain_Intelligence",
            status="success",
            url=lexical_features.original_url,
            score=risk_assessment.risk_score,
            risk_level=risk_assessment.risk_level,
            verdict=risk_assessment.verdict,
            features=lexical_features,
            domain_intelligence=domain_report,
            threat_infrastructure=infra_report,
            ml_prediction=ml_res,
            risk_assessment=risk_assessment,
            risk_indicators=unified_indicators,
            explanation=explanation,
        )


    def _compute_domain_risk_score(
        self,
        registration: DomainRegistrationFeatures,
        dns: DnsIntelligenceFeatures,
        reputation: DomainReputationFeatures,
    ) -> Tuple[float, List[str]]:
        """Compute domain risk score strictly from evidence without penalizing missing data."""
        indicators: List[str] = []
        raw_score = 0.0

        # 1. Registration Age (NRD & Young Domain)
        if registration.is_nrd and registration.age_days is not None:
            raw_score += 25.0
            indicators.append(
                f"Newly registered domain (Age: {registration.age_days} days, threshold <= {self.settings.nrd_threshold_days} days)."
            )
        elif registration.is_young_domain and registration.age_days is not None:
            raw_score += 12.0
            indicators.append(
                f"Young domain registration (Age: {registration.age_days} days, threshold <= {self.settings.nrd_warning_threshold_days} days)."
            )

        # Mitigating factor: Domain established for over 2 years
        if registration.age_days is not None and registration.age_days >= 730:
            raw_score -= 10.0

        # Mitigating factor: DNSSEC signed
        if registration.dnssec_enabled:
            raw_score -= 5.0

        # 2. DNS Infrastructure Anomalies
        if dns.is_fast_flux:
            raw_score += 30.0
            indicators.append("Fast-flux DNS behavior detected (rapid IP turnover with short TTL).")

        if dns.is_private_ip_resolved:
            raw_score += 25.0
            indicators.append("Domain resolves to internal/private RFC-1918 address space.")

        if dns.is_dynamic_dns:
            raw_score += 15.0
            indicators.append("Hosted on dynamic DNS service commonly associated with volatile infrastructure.")

        # 3. Reputation & Threat Feed Hits
        if reputation.is_known_threat:
            raw_score += 40.0
            indicators.append(
                f"Known threat intelligence match ({reputation.reputation_source or 'threat_feed'}): {reputation.threat_type or 'malicious'}."
            )

        for rep_ind in reputation.reputation_indicators:
            if rep_ind not in indicators:
                indicators.append(rep_ind)

        # Bound score between 0.0 and 100.0
        final_score = round(min(max(raw_score, 0.0), 100.0), 1)
        return final_score, indicators

    def _combine_multi_layer_scores(
        self,
        lexical_score: float,
        lexical_indicators: List[str],
        domain_score: float,
        domain_indicators: List[str],
        infra_score: float,
        infra_indicators: List[str],
        lexical_features: UrlLexicalFeatures,
        domain_report: DomainIntelligenceReport,
        infra_report: ThreatInfrastructureReport,
        ml_res: Optional[MlPredictionResult] = None,
    ) -> Tuple[float, List[str], str]:
        """Combine Layer 1 lexical, Layer 2 domain intelligence, Layer 3 infrastructure, and Layer 4 ML scores."""
        unified_indicators: List[str] = []

        for ind in lexical_indicators + domain_indicators + infra_indicators:
            if ind not in unified_indicators:
                unified_indicators.append(ind)

        # Incorporate ML classification indicator if model active
        ml_score = 0.0
        has_ml = ml_res is not None and ml_res.is_model_loaded
        if has_ml:
            ml_score = ml_res.malicious_probability * 100.0
            if ml_res.predicted_label == "malicious":
                unified_indicators.append(
                    f"Machine Learning Classifier ({ml_res.model_name}) classified URL as malicious "
                    f"(probability: {ml_res.malicious_probability:.2f}, confidence: {ml_res.confidence}%)."
                )

        # Weighted composite score
        if domain_report.registration.is_data_available or domain_report.dns.dns_resolved:
            # Active domain intelligence available
            if has_ml:
                combined = (lexical_score * 0.30) + (domain_score * 0.30) + (infra_score * 0.15) + (ml_score * 0.25)
            else:
                combined = (lexical_score * 0.40) + (domain_score * 0.40) + (infra_score * 0.20)

            # High-confidence correlation booster:
            # If domain is newly registered AND contains credential/login keywords
            if domain_report.registration.is_nrd and lexical_features.has_suspicious_keyword:
                correlation_boost = 30.0 if lexical_features.suspicious_keyword_count >= 3 else 15.0
                combined += correlation_boost
                unified_indicators.append(
                    "High-risk correlation: Newly registered domain combined with security/login keywords."
                )
        else:
            # Domain registration data unavailable, combine lexical, infrastructure, and ML
            if has_ml:
                combined = (lexical_score * 0.45) + (infra_score * 0.25) + (ml_score * 0.30)
            else:
                combined = (lexical_score * 0.65) + (infra_score * 0.35)

        # Critical threat triggers (SSRF violation or DGA + Phishing)
        if infra_report.redirect_chain.ssrf_blocked:
            combined = max(combined, 85.0)

        final_score = round(min(max(combined, 0.0), 100.0), 1)

        total_indicators = len(unified_indicators)
        if total_indicators == 0:
            explanation = "No suspicious lexical, domain intelligence, or threat infrastructure risk indicators observed."
        else:
            explanation = (
                f"Multi-layer analysis identified {total_indicators} risk factor(s) across lexical "
                f"heuristics (sub-score: {lexical_score}), domain intelligence (sub-score: {domain_score}), "
                f"and threat infrastructure (sub-score: {infra_score}). Consolidated risk rating: {final_score}/100."
            )

        return final_score, unified_indicators, explanation

    def _empty_domain_report(self, domain: str) -> DomainIntelligenceReport:
        """Create zeroed empty domain report model."""
        return DomainIntelligenceReport(
            registration=DomainRegistrationFeatures(
                domain_name=domain,
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
            ),
            dns=DnsIntelligenceFeatures(
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
                dns_indicators=[],
            ),
            reputation=DomainReputationFeatures(
                threat_feed_checked=False,
                is_known_threat=False,
                threat_type=None,
                confidence_score=0.0,
                reputation_source="none",
                reputation_indicators=[],
            ),
            domain_risk_score=0.0,
            domain_risk_indicators=[],
        )
