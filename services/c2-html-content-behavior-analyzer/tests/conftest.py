"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from c2_analyzer.api.main import app

SAMPLE_PAGES = Path(__file__).parent / "fixtures" / "sample_pages"


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def sample_pages_dir() -> Path:
    return SAMPLE_PAGES


@pytest.fixture
def load_page():
    def _load(name: str) -> str:
        return (SAMPLE_PAGES / name).read_text(encoding="utf-8")

    return _load
