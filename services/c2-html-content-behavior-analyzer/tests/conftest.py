"""Shared pytest fixtures."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

# Part 9 B-2: tests must never write to the real results database (data/c2_results.db)
# nor start the background ingest worker. Set before the app (and Settings) is imported;
# environment variables win over .env.
os.environ["RESULTS_DB"] = str(Path(tempfile.mkdtemp(prefix="c2-tests-")) / "results.db")
os.environ["INGEST_WORKER_ENABLED"] = "false"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from c2_analyzer.api.main import app  # noqa: E402

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
