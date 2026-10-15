"""Centralized configuration for the social-visual-analyzer service.

All values can be overridden with environment variables or a ``.env`` file
placed in the service root (see ``.env.example``).
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

SERVICE_ROOT: Path = Path(__file__).resolve().parent.parent

ALLOWED_EXTENSIONS: frozenset[str] = frozenset({".jpg", ".jpeg", ".png", ".webp"})
ALLOWED_FORMATS: frozenset[str] = frozenset({"JPEG", "PNG", "WEBP"})

PIPELINE_VERSION = "phase1-ocr-preprocessing-v1"

_LANGUAGE_SPEC_PATTERN = re.compile(r"^[A-Za-z_]+(\+[A-Za-z_]+)*$")


class Settings(BaseSettings):
    """Runtime settings for Phase 1 (OCR + image preprocessing)."""

    model_config = SettingsConfigDict(
        env_file=SERVICE_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    service_name: str = "social-visual-analyzer"
    log_level: str = "INFO"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    data_dir: Path = Field(default=SERVICE_ROOT / "data")

    max_image_size_mb: float = Field(default=10, gt=0)
    max_image_width: int = Field(default=10000, gt=0)
    max_image_height: int = Field(default=10000, gt=0)

    processed_max_width: int = Field(default=1024, gt=0)
    processed_max_height: int = Field(default=1024, gt=0)
    processed_background_color: tuple[int, int, int] = (255, 255, 255)

    phash_hash_size: int = Field(default=8, ge=4)
    phash_near_duplicate_threshold: int = Field(default=5, ge=0)

    ocr_engine: str = "tesseract"
    ocr_languages: str = "eng+sin+tam"
    ocr_fallback_language: str = "eng"
    tesseract_cmd: str = ""
    ocr_min_word_confidence: float = Field(default=0, ge=0, le=100)
    ocr_low_confidence_warning: float = Field(default=60, ge=0, le=100)
    ocr_psm: int = Field(default=3, ge=0, le=13)
    ocr_oem: int = Field(default=3, ge=0, le=3)
    ocr_timeout_seconds: int = Field(default=60, ge=0)
    ocr_max_side: int = Field(default=3000, gt=0)

    dataset_version: str = Field(default="0.1", pattern=r"^\d+\.\d+(\.\d+)?$")
    dataset_max_images_per_sample: int = Field(default=20, ge=1, le=99)
    dataset_max_urls_per_sample: int = Field(default=50, ge=1)
    dataset_max_text_length: int = Field(default=20000, gt=0)
    dataset_allow_synthetic: bool = False
    dataset_lock_timeout_seconds: float = Field(default=10, gt=0)

    web_capture_enabled: bool = True
    web_capture_timeout_seconds: float = Field(default=30, gt=0, le=300)
    web_capture_settle_seconds: float = Field(default=2, ge=0, le=30)
    web_capture_viewport_width: int = Field(default=1366, ge=320, le=3840)
    web_capture_viewport_height: int = Field(default=768, ge=240, le=2160)
    web_capture_max_height: int = Field(default=12000, ge=240, le=30000)
    web_capture_javascript: bool = True
    web_capture_block_social_media: bool = True
    web_capture_allow_private_hosts: bool = False
    web_capture_user_agent: str = ""
    web_capture_max_title_length: int = Field(default=300, ge=1, le=2000)

    @field_validator("data_dir")
    @classmethod
    def _resolve_data_dir(cls, value: Path) -> Path:
        """Resolve relative data paths against the service root, not the CWD."""
        path = Path(value)
        if not path.is_absolute():
            path = SERVICE_ROOT / path
        return path.resolve()

    @field_validator("ocr_languages", "ocr_fallback_language")
    @classmethod
    def _validate_language_spec(cls, value: str) -> str:
        value = value.strip()
        if not _LANGUAGE_SPEC_PATTERN.fullmatch(value):
            raise ValueError("OCR languages must look like 'eng' or 'eng+sin+tam'")
        return value

    @field_validator("tesseract_cmd")
    @classmethod
    def _strip_tesseract_cmd(cls, value: str) -> str:
        return value.strip().strip('"')

    @property
    def max_image_size_bytes(self) -> int:
        return int(self.max_image_size_mb * 1024 * 1024)

    @property
    def raw_dir(self) -> Path:
        """Original, untransformed evidence. Never overwritten by processing."""
        return self.data_dir / "raw"

    @property
    def raw_images_dir(self) -> Path:
        """Dataset post images named ``SVT_000001_01.jpg``."""
        return self.raw_dir / "images"

    @property
    def raw_posts_dir(self) -> Path:
        """One submitted-post JSON snapshot per dataset sample."""
        return self.raw_dir / "posts"

    @property
    def raw_uploads_dir(self) -> Path:
        """Uploads received by the preprocessing endpoint."""
        return self.raw_dir / "uploads"

    @property
    def processed_dir(self) -> Path:
        return self.data_dir / "processed"

    @property
    def processed_images_dir(self) -> Path:
        """Validated, RGB, resized PNGs produced by the preprocessing pipeline."""
        return self.processed_dir / "images"

    @property
    def rejected_dir(self) -> Path:
        return self.data_dir / "rejected"

    @property
    def webpage_screenshots_dir(self) -> Path:
        """Destination website screenshots named ``SVT_000001_web_01.png``."""
        return self.data_dir / "webpage_screenshots"

    @property
    def webpage_captures_path(self) -> Path:
        """Append-only log of every destination capture attempt (success or failure)."""
        return self.annotations_dir / "webpage_captures.jsonl"

    @property
    def statistics_dir(self) -> Path:
        return self.data_dir / "statistics"

    @property
    def annotations_dir(self) -> Path:
        return self.data_dir / "annotations"

    @property
    def dataset_metadata_path(self) -> Path:
        return self.annotations_dir / "dataset_metadata.jsonl"

    @property
    def labels_path(self) -> Path:
        return self.annotations_dir / "labels.jsonl"

    @property
    def dataset_lock_path(self) -> Path:
        return self.annotations_dir / ".dataset.lock"

    @property
    def dataset_statistics_path(self) -> Path:
        return self.statistics_dir / "dataset_statistics.json"

    @property
    def ocr_results_path(self) -> Path:
        return self.annotations_dir / "ocr_results.jsonl"

    @property
    def image_hashes_path(self) -> Path:
        return self.annotations_dir / "image_hashes.json"

    @property
    def rejected_images_path(self) -> Path:
        return self.annotations_dir / "rejected_images.jsonl"

    def ensure_directories(self) -> None:
        """Create the data directory layout if it does not exist yet."""
        for directory in (
            self.raw_images_dir,
            self.raw_posts_dir,
            self.raw_uploads_dir,
            self.processed_images_dir,
            self.rejected_dir,
            self.webpage_screenshots_dir,
            self.annotations_dir,
            self.statistics_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings instance."""
    return Settings()
