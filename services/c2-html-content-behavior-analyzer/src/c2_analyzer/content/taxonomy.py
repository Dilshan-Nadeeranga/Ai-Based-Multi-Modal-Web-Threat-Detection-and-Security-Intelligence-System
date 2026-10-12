"""Social-engineering intent taxonomy (loads configs/intent_taxonomy.yaml).

Part 5: Multilingual scam content analyzer.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def load_taxonomy(path: Path | None = None) -> dict[str, Any]:
    """Return intents with descriptions and cue phrases."""
    raise NotImplementedError


def intent_names() -> list[str]:
    """Ordered list of intent ids."""
    raise NotImplementedError
