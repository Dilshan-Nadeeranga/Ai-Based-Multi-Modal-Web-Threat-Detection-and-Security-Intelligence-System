"""Centralized configuration for the c1-url-domain-analyzer service."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

SERVICE_ROOT: Path = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Runtime configuration settings for C1 URL and Domain Analyzer."""

    model_config = SettingsConfigDict(
        env_file=SERVICE_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    service_name: str = "c1-url-domain-analyzer"
    log_level: str = "INFO"
    port: int = 8001
    host: str = "0.0.0.0"

    mongodb_uri: str = "mongodb://localhost:27017"
    mongodb_database: str = "url_domain_analyzer"

    # Suspicious TLD list for lexical heuristic scoring
    suspicious_tlds: set[str] = {
        "zip", "mov", "top", "xyz", "work", "gq", "cf", "tk", "ml", "ga",
        "click", "link", "country", "kim", "science", "party", "review",
        "download", "racing", "date", "stream", "men", "win", "bid"
    }

    # High-risk security keywords in URLs
    suspicious_keywords: set[str] = {
        "login", "signin", "verify", "verification", "account", "update",
        "secure", "security", "banking", "bank", "confirm", "confirmation",
        "support", "service", "credential", "auth", "authorize", "token",
        "wallet", "password", "recovery", "checkout", "payment", "billing",
        "paypal", "appleid", "microsoft", "google", "meta", "netflix",
        "amazon", "facebook", "instagram", "chase", "wellsfargo"
    }


@lru_cache
def get_settings() -> Settings:
    """Return process-wide settings singleton."""
    return Settings()
