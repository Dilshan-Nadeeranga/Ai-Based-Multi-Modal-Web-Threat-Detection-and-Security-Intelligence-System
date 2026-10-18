"""Settings of the ingestion pipeline (configs/ingest.yaml), validated once.

Part 9: Batch B-2 - automatic ThreatRadar ingestion.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from c2_analyzer.config import load_yaml_config
from c2_analyzer.schemas.ingest import MAX_INGEST_URLS


@dataclass(frozen=True)
class IngestConfig:
    max_urls_per_call: int = MAX_INGEST_URLS
    max_queue_depth: int = 10_000
    dedupe_ttl_hours: float = 24.0
    skip_allow_listed: bool = True
    concurrency: int = 2
    jobs_per_second: float = 1.0
    max_attempts: int = 3
    backoff_seconds: float = 30.0
    backoff_max_seconds: float = 900.0
    job_time_budget_seconds: float = 45.0
    idle_poll_seconds: float = 2.0
    suspicious_min_risk: int = 70
    default_limit: int = 50
    max_limit: int = 200
    sse_heartbeat_seconds: float = 15.0
    top_n: int = 10

    def __post_init__(self) -> None:
        if not 1 <= self.max_urls_per_call <= MAX_INGEST_URLS:
            raise ValueError(f"ingest.max_urls_per_call must be 1..{MAX_INGEST_URLS}")
        if self.concurrency < 1 or self.jobs_per_second <= 0 or self.max_attempts < 1:
            raise ValueError("worker: concurrency >= 1, jobs_per_second > 0, max_attempts >= 1")
        if not 0 <= self.suspicious_min_risk <= 100:
            raise ValueError("review.suspicious_min_risk must be 0..100")

    @classmethod
    def from_dict(cls, data: dict) -> IngestConfig:
        ingest, worker = data.get("ingest") or {}, data.get("worker") or {}
        review, read = data.get("review") or {}, data.get("read_api") or {}
        return cls(**{**ingest, **worker, **review, **read})

    def backoff(self, attempt: int) -> float:
        """Seconds to wait after failed attempt ``attempt`` (1-based): exponential, capped."""
        return min(self.backoff_seconds * 2 ** max(attempt - 1, 0), self.backoff_max_seconds)


@lru_cache
def ingest_config() -> IngestConfig:
    return IngestConfig.from_dict(load_yaml_config("ingest"))
