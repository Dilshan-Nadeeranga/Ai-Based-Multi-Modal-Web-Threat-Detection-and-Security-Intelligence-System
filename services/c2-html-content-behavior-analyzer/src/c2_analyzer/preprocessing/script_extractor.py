"""Extract inline JS bodies and external JS references.

Part 2: HTML preprocessing pipeline.
"""

from __future__ import annotations

from typing import Any

from c2_analyzer.schemas.parsed_page import ScriptInfo


def extract_scripts(soup: Any) -> list[ScriptInfo]:
    """Return inline and external scripts in document order."""
    raise NotImplementedError
