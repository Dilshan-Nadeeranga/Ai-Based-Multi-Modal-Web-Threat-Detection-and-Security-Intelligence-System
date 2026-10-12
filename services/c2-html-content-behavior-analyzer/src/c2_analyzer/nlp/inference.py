"""Load a fine-tuned checkpoint and predict.

Part 6: XLM-R content classification.
"""

from __future__ import annotations

from pathlib import Path


class ContentClassifier:
    """Wrapper around a fine-tuned XLM-R checkpoint."""

    def __init__(self, checkpoint: Path, device: str = "cpu") -> None:
        # TODO: load tokenizer + model lazily.
        raise NotImplementedError

    def predict(self, text: str) -> dict[str, float]:
        """Return class -> probability."""
        raise NotImplementedError
