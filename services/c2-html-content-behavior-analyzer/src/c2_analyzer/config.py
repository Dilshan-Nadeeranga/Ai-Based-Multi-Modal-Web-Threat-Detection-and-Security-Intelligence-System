"""Application settings (env / .env via pydantic-settings) and YAML config loading.

Shared (used across Parts 1-9).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings. Values come from environment variables or ``.env``."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: str = "development"
    api_host: str = "127.0.0.1"  # run_api.py binds 127.0.0.1 unless --host is given
    api_port: int = 8002
    log_level: str = "INFO"
    model_dir: Path = Path("models")
    data_dir: Path = Path("data")
    config_dir: Path = Path("configs")
    xlmr_model_name: str = "xlm-roberta-base"
    device: str = "cpu"
    # Part 9 B-1 (/api/v1/analyze): serve the XLM-R arm (CPU, ~1 GB RAM); false = 3 arms.
    xlmr_enabled: bool = True
    # Comma-separated browser origins allowed to call the API (team frontend). Empty = none.
    cors_origins: str = ""

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    """Return the cached application settings."""
    return Settings()


def project_root() -> Path:
    """Return the service folder (the one containing ``configs/``, ``data/``, ``models/``).

    Relative paths in Settings are resolved against this folder, so scripts work
    no matter which directory they are started from. In a source checkout it is
    three levels above this file (``src/c2_analyzer/config.py``); if the package
    was installed elsewhere (e.g. Docker), fall back to the current directory.
    """
    candidate = Path(__file__).resolve().parents[2]
    if (candidate / "configs").is_dir():
        return candidate
    return Path.cwd()


def resolve_path(path: Path) -> Path:
    """Make a Settings path absolute (relative paths are relative to project_root())."""
    return path if path.is_absolute() else project_root() / path


def load_yaml_config(name: str, config_dir: Path | None = None) -> dict[str, Any]:
    """Load ``configs/<name>.yaml`` (e.g. ``labels``, ``js_rules``) as a dict."""
    directory = config_dir or resolve_path(get_settings().config_dir)
    path = directory / f"{name}.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"Config file not found: {path}")
    with path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML mapping at the top level")
    return data


# The vocabularies below are the single source of truth for allowed values.
# They are cached because they never change while the program runs.


@lru_cache
def get_labels() -> tuple[str, ...]:
    """Threat class names in id order, from ``configs/labels.yaml``."""
    labels = load_yaml_config("labels")["labels"]
    return tuple(item["name"] for item in sorted(labels, key=lambda item: item["id"]))


@lru_cache
def get_languages(include_special: bool = True) -> tuple[str, ...]:
    """Language codes from ``configs/languages.yaml``.

    ``include_special=True`` adds the metadata-only values ``mixed``/``unknown``.
    """
    config = load_yaml_config("languages")
    languages = tuple(config["languages"])
    if include_special:
        languages += tuple(config.get("special_values", []))
    return languages


@lru_cache
def get_sources() -> tuple[str, ...]:
    """Allowed dataset sources, from ``configs/sources.yaml``."""
    return tuple(load_yaml_config("sources")["sources"])


@lru_cache
def get_quality_flags() -> tuple[str, ...]:
    """Allowed page quality flags, from ``configs/quality_rules.yaml``."""
    return tuple(load_yaml_config("quality_rules")["quality_flags"])
