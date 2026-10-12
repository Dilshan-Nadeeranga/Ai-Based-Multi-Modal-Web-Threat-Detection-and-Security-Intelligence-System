"""Logging setup.

Shared (used across Parts 1-9).
"""

from __future__ import annotations

import logging


def get_logger(name: str, level: str | None = None) -> logging.Logger:
    """Return a configured logger for ``name``."""
    # TODO: configure format/handlers once, honour Settings.log_level.
    raise NotImplementedError
