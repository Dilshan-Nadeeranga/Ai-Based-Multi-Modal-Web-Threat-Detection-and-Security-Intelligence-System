"""Fine-tune XLM-R (designed to also run on Colab).

Part 6: XLM-R content classification.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def train(config: dict[str, Any], output_dir: Path) -> Path:
    """Fine-tune and save the best checkpoint; return its path."""
    raise NotImplementedError
