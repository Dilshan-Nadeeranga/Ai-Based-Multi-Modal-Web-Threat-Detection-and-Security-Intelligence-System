"""Export DOM features to CSV / JSON.

Part 3: DOM structural analysis.
"""

from __future__ import annotations

from pathlib import Path


def export_csv(rows: list[dict], path: Path) -> None:
    """Write feature rows (sample_id, label, features...) to CSV."""
    raise NotImplementedError


def export_json(rows: list[dict], path: Path) -> None:
    """Write feature rows to JSON."""
    raise NotImplementedError
