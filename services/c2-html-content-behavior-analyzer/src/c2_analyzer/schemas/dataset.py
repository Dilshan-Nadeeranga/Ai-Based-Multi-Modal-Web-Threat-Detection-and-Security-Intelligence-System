"""Dataset sample metadata model (mirrors data/metadata/dataset_schema.json).

Part 1: Multilingual dataset preparation.
"""

from __future__ import annotations

from datetime import date

from pydantic import BaseModel


class SampleMetadata(BaseModel):
    """One row of ``data/metadata/metadata.csv``."""

    sample_id: str
    file_path: str
    label: str
    language: str
    source: str
    source_url: str | None = None
    collection_date: date | None = None
    sha256: str
    verified: bool = False
    verified_by: str | None = None
    notes: str | None = None
