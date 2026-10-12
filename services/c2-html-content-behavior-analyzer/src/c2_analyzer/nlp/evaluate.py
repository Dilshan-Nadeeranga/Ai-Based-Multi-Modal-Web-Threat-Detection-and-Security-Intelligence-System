"""Per-language and macro metrics for XLM-R.

Part 6: XLM-R content classification.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def evaluate(checkpoint: Path, test_data: Any) -> dict[str, Any]:
    """Macro F1 overall plus per-language (en/si/ta) breakdown."""
    raise NotImplementedError
