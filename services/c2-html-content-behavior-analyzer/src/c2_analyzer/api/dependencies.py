"""FastAPI dependency providers.

Part 9: Preliminary tri-modal output (fusion + FastAPI).
"""

from __future__ import annotations

from functools import lru_cache

from c2_analyzer.api.dev_data import DevDataset
from c2_analyzer.config import Settings, get_settings
from c2_analyzer.fusion.orchestrator import Orchestrator
from c2_analyzer.nlp.inference import TextModelRegistry


def settings_dependency() -> Settings:
    """Inject application settings."""
    return get_settings()


@lru_cache
def get_dev_dataset() -> DevDataset:
    """The shared DevDataset (one instance, so its summary cache survives requests).

    Tests replace it with ``app.dependency_overrides[get_dev_dataset]``.
    """
    return DevDataset.from_settings()


@lru_cache
def get_text_models() -> TextModelRegistry:
    """The shared Part 6A text models (loaded lazily on the first prediction).

    Tests replace it with ``app.dependency_overrides[get_text_models]``.
    """
    return TextModelRegistry()


def get_orchestrator() -> Orchestrator:
    """Return the shared, lazily-initialised Orchestrator."""
    # TODO (Part 9): cache a single Orchestrator instance.
    raise NotImplementedError
