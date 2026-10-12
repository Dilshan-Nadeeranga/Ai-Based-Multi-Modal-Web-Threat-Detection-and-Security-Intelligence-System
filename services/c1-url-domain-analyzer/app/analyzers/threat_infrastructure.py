"""Threat-Infrastructure Analysis Orchestrator.

Combines DGA statistical analysis, URL shortener resolution, and controlled HTTP
redirect-chain tracking to identify evasive and procedurally generated attack infrastructure.

Strictly adheres to passive non-rendering inspection, SSRF prevention, and hop bounds.
"""

from __future__ import annotations

import logging
from typing import List, Tuple

from app.analyzers.dga_analyzer import DgaAnalyzer
from app.analyzers.redirect_analyzer import ControlledRedirectResolver
from app.config import get_settings
from app.schemas.url_schema import (
    DgaAnalysisFeatures,
    RedirectChainFeatures,
    ThreatInfrastructureReport,
)

logger = logging.getLogger(__name__)


class ThreatInfrastructureAnalyzer:
    """Orchestrator for analyzing DGA domain patterns and controlled redirect chains."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.dga_analyzer = DgaAnalyzer()
        self.redirect_resolver = ControlledRedirectResolver()

    async def analyze(self, url: str, domain_name: str) -> ThreatInfrastructureReport:
        """Execute DGA statistical analysis and controlled redirect-chain resolution."""
        # 1. Run DGA statistical analysis on domain label
        dga_features = self.dga_analyzer.analyze(domain_name)

        # 2. Run controlled redirect resolution
        redirect_features = await self.redirect_resolver.resolve(url)

        # 3. Compute consolidated infrastructure risk sub-score
        infra_score, infra_indicators = self._compute_infrastructure_risk(
            dga_features=dga_features,
            redirect_features=redirect_features,
        )

        return ThreatInfrastructureReport(
            dga=dga_features,
            redirect_chain=redirect_features,
            infrastructure_risk_score=infra_score,
            infrastructure_indicators=infra_indicators,
        )

    def _compute_infrastructure_risk(
        self,
        dga_features: DgaAnalysisFeatures,
        redirect_features: RedirectChainFeatures,
    ) -> Tuple[float, List[str]]:
        """Calculate evidence-based infrastructure risk score from DGA and redirect metrics."""
        indicators: List[str] = []
        raw_score = 0.0

        # DGA Observations
        if dga_features.is_dga_suspected:
            raw_score += 35.0
            indicators.append(
                f"Procedurally generated DGA characteristics identified (Score: {dga_features.dga_score}, Family hint: {dga_features.dga_family_hint or 'algorithmic'})."
            )

        for dga_ind in dga_features.dga_indicators:
            if "Suspicious algorithmic" not in dga_ind and dga_ind not in indicators:
                indicators.append(dga_ind)

        # Redirect Chain Observations
        if redirect_features.ssrf_blocked:
            raw_score += 35.0
            indicators.append("Prohibited SSRF destination blocked during redirect resolution.")

        if redirect_features.has_redirect_loop:
            raw_score += 15.0
            indicators.append("Cyclic redirect loop observed in resolution chain.")

        if redirect_features.has_excessive_redirects:
            raw_score += 15.0
            indicators.append(
                f"Excessive redirection hops ({redirect_features.total_hops} hops observed)."
            )

        if redirect_features.destination_domain_changed:
            if redirect_features.is_shortened:
                raw_score += 10.0
                indicators.append(
                    f"Shortened URL expands to external domain ({redirect_features.shortener_provider} -> {redirect_features.final_url})."
                )
            else:
                raw_score += 15.0
                indicators.append("Chain transitions across multiple distinct domain boundaries.")

        for r_ind in redirect_features.redirect_indicators:
            if r_ind not in indicators:
                indicators.append(r_ind)

        final_score = round(min(100.0, max(0.0, raw_score)), 1)
        return final_score, indicators
