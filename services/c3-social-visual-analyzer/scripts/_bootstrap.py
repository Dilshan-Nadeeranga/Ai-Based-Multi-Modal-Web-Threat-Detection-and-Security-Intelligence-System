"""Shared setup for the command-line scripts (path, UTF-8 output, logging)."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

SERVICE_ROOT = Path(__file__).resolve().parent.parent
if str(SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVICE_ROOT))

from app.config import Settings  # noqa: E402


def setup(verbose: bool = False) -> None:
    """Make Sinhala/Tamil text printable on Windows consoles and enable logging."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(levelname)s [%(name)s] %(message)s",
    )


def load_settings(data_dir: str | None = None, **overrides: object) -> Settings:
    """Settings from env/.env, optionally pointed at another data directory."""
    if data_dir:
        overrides["data_dir"] = Path(data_dir).expanduser().resolve()
    return Settings(**overrides)
