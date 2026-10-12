"""FastAPI dependency providers.

Part 9: Preliminary tri-modal output (fusion + FastAPI).
"""

from __future__ import annotations

from c2_analyzer.config import Settings, get_settings
from c2_analyzer.fusion.orchestrator import Orchestrator


def settings_dependency() -> Settings:
    """Inject application settings."""
    return get_settings()


def get_orchestrator() -> Orchestrator:
    """Return the shared, lazily-initialised Orchestrator."""
    # TODO (Part 9): cache a single Orchestrator instance.
    raise NotImplementedError
