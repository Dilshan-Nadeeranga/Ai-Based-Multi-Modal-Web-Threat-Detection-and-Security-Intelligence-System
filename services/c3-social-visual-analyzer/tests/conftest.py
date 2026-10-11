"""Shared fixtures: isolated data directories, synthetic images, fake OCR."""

from __future__ import annotations

import io
from collections.abc import Callable
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from PIL import Image, ImageDraw

from app.config import Settings
from app.main import create_app
from app.schemas.ocr_schema import OcrResult, OcrWord
from app.services.image_pipeline import ImagePipeline
from app.services.ocr_service import OcrEngine


class FakeOcrEngine(OcrEngine):
    """Deterministic OCR stand-in so unit tests do not need Tesseract."""

    name = "fake"

    def __init__(self, error: Exception | None = None) -> None:
        self.calls: list[tuple[int, int]] = []
        self.error = error

    def is_available(self) -> bool:
        return self.error is None

    def extract(self, image: Image.Image) -> OcrResult:
        self.calls.append(image.size)
        if self.error is not None:
            raise self.error
        words = [OcrWord(text="SAMPLE", confidence=90.0), OcrWord(text="TEXT", confidence=80.0)]
        return OcrResult(
            engine=self.name,
            text="SAMPLE TEXT",
            average_confidence=85.0,
            requested_languages="eng+sin+tam",
            used_languages="eng",
            word_count=len(words),
            words=words,
            warning="Requested OCR languages eng+sin+tam unavailable (missing: sin, tam). Using eng.",
            input_width=image.width,
            input_height=image.height,
        )


def make_pattern_image(
    size: tuple[int, int] = (640, 480),
    variant: int = 0,
    mode: str = "RGB",
) -> Image.Image:
    """Create a structured synthetic image; different variants look different."""
    width, height = size
    image = Image.new("RGB", size, (240, 240, 240))
    draw = ImageDraw.Draw(image)
    if variant == 0:
        draw.rectangle([0, 0, width // 2, height // 3], fill=(20, 60, 200))
        draw.ellipse([width // 2, height // 3, width - 10, height - 10], fill=(220, 30, 30))
        draw.rectangle([width // 10, height // 2, width // 3, height - height // 10], fill=(10, 10, 10))
    else:
        stripe = max(1, width // 8)
        for index in range(0, width, stripe * 2):
            draw.rectangle([index, 0, index + stripe, height], fill=(0, 0, 0))
        draw.rectangle([0, height // 2, width, height // 2 + height // 6], fill=(250, 200, 0))
    return image.convert(mode) if mode != "RGB" else image


def image_bytes(image: Image.Image, image_format: str, **save_kwargs) -> bytes:
    buffer = io.BytesIO()
    image.save(buffer, format=image_format, **save_kwargs)
    return buffer.getvalue()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    test_settings = Settings(_env_file=None, data_dir=tmp_path / "data")
    test_settings.ensure_directories()
    return test_settings


@pytest.fixture
def fake_ocr() -> FakeOcrEngine:
    return FakeOcrEngine()


@pytest.fixture
def pipeline(settings: Settings, fake_ocr: FakeOcrEngine) -> ImagePipeline:
    return ImagePipeline.from_settings(settings, ocr_engine=fake_ocr)


@pytest.fixture
def client(settings: Settings, pipeline: ImagePipeline) -> TestClient:
    return TestClient(create_app(settings=settings, pipeline=pipeline))


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def dataset_settings(tmp_path: Path) -> Settings:
    """Isolated data directory that permits synthetic_test samples."""
    test_settings = Settings(_env_file=None, data_dir=tmp_path / "dataset_data", dataset_allow_synthetic=True)
    test_settings.ensure_directories()
    return test_settings


@pytest.fixture
def dataset_service(dataset_settings: Settings):
    from app.services.dataset_service import DatasetService

    return DatasetService(dataset_settings)


@pytest.fixture
def make_request() -> Callable[..., object]:
    """Build a synthetic NewSampleRequest; keyword arguments override defaults."""
    from app.services.dataset_service import build_request

    def _make(**overrides: object):
        fields: dict[str, object] = {
            "platform": "facebook",
            "post_text": "Example security information",
            "embedded_urls": ["https://example.com"],
            "is_scam": 0,
            "scam_type": "legitimate",
            "label_status": "verified",
            "collection_method": "synthetic_test",
        }
        fields.update(overrides)
        return build_request(**fields)

    return _make


@pytest.fixture
def write_image(tmp_path: Path) -> Callable[..., Path]:
    """Write a synthetic image to ``tmp_path/uploads`` and return its path."""
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir(exist_ok=True)

    def _write(
        name: str,
        image: Image.Image | None = None,
        image_format: str | None = None,
        **save_kwargs,
    ) -> Path:
        image = image if image is not None else make_pattern_image()
        image_format = image_format or {
            ".jpg": "JPEG",
            ".jpeg": "JPEG",
            ".png": "PNG",
            ".webp": "WEBP",
            ".gif": "GIF",
        }[Path(name).suffix.lower()]
        path = upload_dir / name
        path.write_bytes(image_bytes(image, image_format, **save_kwargs))
        return path

    return _write
