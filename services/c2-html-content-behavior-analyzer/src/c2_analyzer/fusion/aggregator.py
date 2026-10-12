"""Build the unified response and flag missing modalities.

Part 9: Preliminary tri-modal output (fusion + FastAPI).
"""

from __future__ import annotations

from typing import Any

from c2_analyzer.schemas.analysis import AnalysisResponse


def aggregate(modality_results: dict[str, dict[str, Any] | None]) -> AnalysisResponse:
    """Combine per-modality outputs into verdict, risk_score and findings."""
    raise NotImplementedError
