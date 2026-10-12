"""Application settings (env / .env via pydantic-settings) and YAML config loading.

Shared (used across Parts 1-9).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings. Values come from environment variables or ``.env``."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: str = "development"
    api_host: str = "0.0.0.0"
    api_port: int = 8002
    log_level: str = "INFO"
    model_dir: Path = Path("models")
    data_dir: Path = Path("data")
    config_dir: Path = Path("configs")
    xlmr_model_name: str = "xlm-roberta-base"
    device: str = "cpu"


@lru_cache
def get_settings() -> Settings:
    """Return the cached application settings."""
    return Settings()


def load_yaml_config(name: str, config_dir: Path | None = None) -> dict[str, Any]:
    """Load ``configs/<name>.yaml`` (e.g. ``labels``, ``js_rules``) as a dict."""
    # TODO: read the YAML file with yaml.safe_load and validate required keys.
    raise NotImplementedError
