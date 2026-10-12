"""Manual/automatic label verification helpers.

Part 1: Multilingual dataset preparation.
"""

from __future__ import annotations

from pathlib import Path


def mark_verified(sample_id: str, verified_by: str, notes: str | None = None) -> None:
    """Record that a sample's label has been verified."""
    raise NotImplementedError


def unverified_samples(metadata_path: Path) -> list[str]:
    """Return sample_ids still awaiting verification."""
    raise NotImplementedError
