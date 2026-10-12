"""Behavioral intent vector + JSON output.

Part 8: Behavioral intent mapping (sources -> sinks).
"""

from __future__ import annotations

from c2_analyzer.schemas.behavior import BehaviorResult, JsFindings, SourceSinkFlow


def build_behavior_result(findings: JsFindings, flows: list[SourceSinkFlow]) -> BehaviorResult:
    """Combine findings, flows and patterns into a BehaviorResult."""
    raise NotImplementedError
