"""Behavior patterns: credential exfiltration, forced redirect, clipboard, download, obfuscation.

Part 8: Behavioral intent mapping (sources -> sinks).
"""

from __future__ import annotations

from c2_analyzer.schemas.behavior import JsFindings, SourceSinkFlow


def match_patterns(flows: list[SourceSinkFlow], findings: JsFindings) -> list[str]:
    """Return names of matched behavioral patterns."""
    raise NotImplementedError
