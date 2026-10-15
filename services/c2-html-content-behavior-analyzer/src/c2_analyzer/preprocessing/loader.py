"""Load raw HTML from a file, a dataset sample or a string (Task 1).

Part 2: HTML preprocessing pipeline.

Why: the same pipeline must handle
  (a) a sample from a frozen dataset version (training data), and
  (b) a raw HTML string + optional URL (the Part 9 API).
The loader turns all of these into one ``RawHtml`` object, so the pipeline
never needs to know where the page came from.

Safety and limits:
- Only the local file or the given string is read - nothing is downloaded.
- Input above ``max_html_bytes`` (5 MB) is cut and marked as truncated.
- Bytes are decoded with the Part 1 rules (BOM -> <meta charset> -> UTF-8
  with replacement characters), so a broken encoding never crashes.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from c2_analyzer.dataset.fetcher import decode_html
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.preprocessing.settings import PreprocessSettings, default_settings
from c2_analyzer.utils.hashing import sha256_bytes


@dataclass
class RawHtml:
    """Decoded HTML plus everything the pipeline needs to know about its origin."""

    html: str
    size_bytes: int  # before truncation
    sha256: str  # of the original input bytes
    encoding: str
    truncated: bool = False
    sample_id: str | None = None
    page_url: str | None = None  # the page's own address (final URL after redirects)
    dataset_version: str | None = None
    label: str | None = None  # only for dataset samples (used in reports, not in parsing)


def from_bytes(
    data: bytes,
    page_url: str | None = None,
    sample_id: str | None = None,
    dataset_version: str | None = None,
    label: str | None = None,
    settings: PreprocessSettings | None = None,
) -> RawHtml:
    """Decode bytes, cutting them at the size limit first."""
    settings = settings or default_settings()
    truncated = len(data) > settings.max_html_bytes
    html, encoding = decode_html(data[: settings.max_html_bytes])
    return RawHtml(
        html=html,
        size_bytes=len(data),
        sha256=sha256_bytes(data),
        encoding=encoding,
        truncated=truncated,
        sample_id=sample_id,
        page_url=page_url or None,
        dataset_version=dataset_version,
        label=label,
    )


def from_string(
    html: str, page_url: str | None = None, settings: PreprocessSettings | None = None
) -> RawHtml:
    """An HTML string (e.g. from the API). Measured and capped as UTF-8 bytes."""
    settings = settings or default_settings()
    data = html.encode("utf-8", errors="replace")
    truncated = len(data) > settings.max_html_bytes
    text = data[: settings.max_html_bytes].decode("utf-8", errors="ignore") if truncated else html
    return RawHtml(
        html=text,
        size_bytes=len(data),
        sha256=sha256_bytes(data),
        encoding="utf-8",
        truncated=truncated,
        page_url=page_url or None,
    )


def from_file(
    path: Path, page_url: str | None = None, settings: PreprocessSettings | None = None
) -> RawHtml:
    """Any local HTML file (``preprocess_html.py one --file``)."""
    return from_bytes(Path(path).read_bytes(), page_url=page_url, settings=settings)


def from_sample(
    store: MetadataStore,
    sample_id: str,
    dataset_version: str | None = None,
    settings: PreprocessSettings | None = None,
) -> RawHtml:
    """A registered sample: file from data/raw, page URL from metadata.csv.

    The page URL is the final URL after redirects (falls back to the source URL),
    because relative links on the page are relative to where it really loaded.
    """
    record = store.get(sample_id)  # KeyError if unknown
    return from_bytes(
        (store.raw_dir / record.file_path).read_bytes(),
        page_url=record.final_url or record.source_url,
        sample_id=sample_id,
        dataset_version=dataset_version,
        label=record.label,
        settings=settings,
    )
