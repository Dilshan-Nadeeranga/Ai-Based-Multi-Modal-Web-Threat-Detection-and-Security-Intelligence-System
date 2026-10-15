"""DomResult: the output of Part 3 (DOM security feature vector + evidence).

Part 3: DOM structural analysis.

Why: Part 4 (DOM classifiers) needs a FIXED-ORDER numeric vector, and the
explanation layer (Part 9) and the inspector need to say WHY a value is high.
So one result carries both:

- ``features``: name -> number, in the exact order of configs/dom_features.yaml
  (``feature_set_version`` names that order; the CSV columns follow it);
- ``evidence``: short, human-readable items for the important non-zero
  features, e.g. "Password form submits to external domain submit-form.com".

The feature NAMES are not fields of this model on purpose: the YAML dictionary
is the single source of truth, so adding a feature never needs a schema edit.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["high", "medium", "info"]


class EvidenceItem(BaseModel):
    """Why one feature is non-zero, in words (PII stays masked as Part 2 stored it)."""

    feature: str
    message: str
    severity: Severity = "info"
    value: float
    details: dict[str, Any] = Field(default_factory=dict)


class DomResult(BaseModel):
    """Part 3 output for one page."""

    sample_id: str | None = None
    dataset_version: str | None = None
    feature_set_version: str
    dictionary_hash: str  # sha256 of the dictionary used (skip/redo decision in batch runs)
    source_sha256: str | None = None  # of the HTML the ParsedPage was made from
    tree_source: Literal["html", "parsed_page"] = "html"  # where tree metrics came from
    features: dict[str, float | int]  # ordered as the dictionary
    evidence: list[EvidenceItem] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)  # a failed feature group (its values are 0)
    warnings: list[str] = Field(default_factory=list)
    processing_ms: float = 0.0
