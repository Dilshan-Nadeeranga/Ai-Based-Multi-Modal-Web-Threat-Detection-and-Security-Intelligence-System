"""Extract forms and their inputs.

Part 2: HTML preprocessing pipeline.
"""

from __future__ import annotations

from typing import Any

from c2_analyzer.schemas.parsed_page import FormInfo


def extract_forms(soup: Any) -> list[FormInfo]:
    """Return one FormInfo per <form>."""
    raise NotImplementedError
