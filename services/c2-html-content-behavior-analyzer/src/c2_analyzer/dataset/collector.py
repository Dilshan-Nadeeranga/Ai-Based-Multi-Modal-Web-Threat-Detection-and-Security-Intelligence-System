"""Collect raw HTML samples into data/raw/<label>/.

Part 1: Multilingual dataset preparation.
"""

from __future__ import annotations

from pathlib import Path


def save_sample(html: str, label: str, source: str, source_url: str | None = None) -> Path:
    """Store one HTML sample under its label folder and return its path."""
    raise NotImplementedError
