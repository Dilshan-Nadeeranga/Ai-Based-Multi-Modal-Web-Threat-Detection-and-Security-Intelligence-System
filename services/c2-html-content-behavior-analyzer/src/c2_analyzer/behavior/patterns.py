"""Behavior patterns: credential exfiltration, forced redirect, clipboard, download, obfuscation.

Part 8: Behavioral intent mapping (sources -> sinks).
"""

from __future__ import annotations

from c2_analyzer.schemas.behavior import SourceSinkFlow
from c2_analyzer.schemas.js import JsAnalysisResult


def match_patterns(flows: list[SourceSinkFlow], analysis: JsAnalysisResult) -> list[str]:
    """Return names of matched behavioral patterns."""
    raise NotImplementedError
