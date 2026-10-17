"""FastAPI dependency providers.

Part 9: Preliminary tri-modal output (fusion + FastAPI).
"""

from __future__ import annotations

import threading
import time
from functools import lru_cache

from c2_analyzer.api.dev_data import DevDataset
from c2_analyzer.api.guards import RateLimiter, ResultCache
from c2_analyzer.config import Settings, get_settings
from c2_analyzer.fusion.live_fetch import analyze_config
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


class AnalysisEngine:
    """The ONE Orchestrator of the process (Part 9 B-1), loaded once.

    ``start()`` (API start-up) loads every model in a background thread, so ``/health``
    answers at once and ``/ready`` reports "loading" until the models are in memory;
    the first ``/analyze`` before that simply waits for the load to finish.
    """

    def __init__(self, factory=Orchestrator.load) -> None:
        self._factory = factory
        self._orchestrator: Orchestrator | None = None
        self._error: str | None = None
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self.started_at: float | None = None

    def _load(self) -> None:
        with self._lock:
            if self._orchestrator is not None:
                return
            try:
                self._orchestrator = self._factory()
                self._error = None
            except Exception as error:  # noqa: BLE001 - reported by /ready, retried later
                self._error = f"{type(error).__name__}: {error}"

    def start(self) -> None:
        """Begin loading in the background (idempotent)."""
        if self._orchestrator is not None or (self._thread and self._thread.is_alive()):
            return
        self.started_at = time.perf_counter()
        self._thread = threading.Thread(target=self._load, name="c2-model-load", daemon=True)
        self._thread.start()

    @property
    def loading(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    @property
    def error(self) -> str | None:
        return self._error

    def peek(self) -> Orchestrator | None:
        """The orchestrator if loaded (never blocks)."""
        return self._orchestrator

    def get(self) -> Orchestrator:
        """The orchestrator, loading it now if needed (raises RuntimeError if that fails)."""
        if self._orchestrator is None:
            self._load()  # waits for a background load holding the lock
        if self._orchestrator is None:
            raise RuntimeError(self._error or "models not loaded")
        return self._orchestrator


@lru_cache
def get_engine() -> AnalysisEngine:
    """The shared analysis engine. Tests replace it with ``dependency_overrides``."""
    return AnalysisEngine()


@lru_cache
def get_result_cache() -> ResultCache:
    config = analyze_config()["cache"]
    return ResultCache(config["ttl_seconds"], config["max_entries"])


@lru_cache
def get_rate_limiter() -> RateLimiter:
    config = analyze_config()["rate_limit"]
    return RateLimiter(config["requests"], config["per_seconds"])


def get_orchestrator() -> Orchestrator:
    """Return the shared Orchestrator (loaded on first use)."""
    return get_engine().get()
