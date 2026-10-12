"""Intra-script source-to-sink relationships (lightweight taint tracking).

Part 8: Behavioral intent mapping (sources -> sinks).
"""

from __future__ import annotations

from typing import Any

from c2_analyzer.schemas.behavior import SourceSinkFlow


def find_flows(ast: Any) -> list[SourceSinkFlow]:
    """Track variables from sources to sinks within a script."""
    raise NotImplementedError
