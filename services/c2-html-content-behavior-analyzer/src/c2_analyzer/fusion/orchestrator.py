"""Run preprocess -> dom -> content -> js -> behavior for one page.

Part 9: Preliminary tri-modal output (fusion + FastAPI).
"""

from __future__ import annotations

from c2_analyzer.schemas.analysis import AnalysisRequest, AnalysisResponse


class Orchestrator:
    """Holds loaded models and runs the full pipeline."""

    def __init__(self) -> None:
        # TODO: load DOM baseline + XLM-R checkpoints if available.
        pass

    def analyze(self, request: AnalysisRequest) -> AnalysisResponse:
        """Analyze one page; a failing modality is reported as missing, not fatal."""
        raise NotImplementedError
