"""Behavioral intent vector + JSON output.

Part 8: Behavioral intent mapping (sources -> sinks).
"""

from __future__ import annotations

from c2_analyzer.schemas.behavior import BehaviorResult, SourceSinkFlow
from c2_analyzer.schemas.js import JsAnalysisResult


def build_behavior_result(
    analysis: JsAnalysisResult, flows: list[SourceSinkFlow]
) -> BehaviorResult:
    """Combine findings, flows and patterns into a BehaviorResult."""
    raise NotImplementedError
