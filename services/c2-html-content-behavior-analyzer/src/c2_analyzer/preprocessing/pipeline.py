"""Orchestrate Part 2: HTML -> ParsedPage, and batch-save JSON outputs.

Part 2: HTML preprocessing pipeline.
"""

from __future__ import annotations

from pathlib import Path

from c2_analyzer.schemas.parsed_page import ParsedPage


def preprocess(html: str, url: str | None = None) -> ParsedPage:
    """Run load/parse/clean/extract on one document."""
    raise NotImplementedError


def preprocess_directory(input_dir: Path, output_dir: Path) -> int:
    """Preprocess every HTML file; save ParsedPage JSON to ``output_dir``. Returns count."""
    raise NotImplementedError
