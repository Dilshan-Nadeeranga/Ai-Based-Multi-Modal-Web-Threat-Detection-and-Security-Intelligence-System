"""Load and match sources/sinks (configs/sources_sinks.yaml).

Part 8: Behavioral intent mapping (sources -> sinks).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def load_sources_sinks(path: Path | None = None) -> dict[str, Any]:
    """Return source and sink definitions."""
    raise NotImplementedError


def classify_node(node: Any) -> tuple[str | None, str | None]:
    """Return (source_id, sink_id) that an AST node represents, if any."""
    raise NotImplementedError
