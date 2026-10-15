"""Response models of the developer inspector API (``/api/v1/dev/...``).

Developer tooling (added after Part 2, extended by later parts).

Why: the inspector page shows how the engine sees a page (for debugging,
supervisor demos and progress presentations). These models are the contract
between the dev endpoints and ``api/static/inspector.js``. They only describe
dataset samples and stored Part 2 results - nothing here judges a page.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class VersionInfo(BaseModel):
    """One frozen dataset version (Part 1 manifest) and how much of it Part 2 processed."""

    version: str
    created_at: str | None = None
    notes: str | None = None
    total: int = 0
    processed: int = 0  # samples with a stored ParsedPage JSON
    counts_per_label: dict[str, int] = Field(default_factory=dict)
    counts_per_language: dict[str, int] = Field(default_factory=dict)


class SampleSummary(BaseModel):
    """One row of the inspector's sample list.

    ``label``/``language`` come from the manifest; the other facts come from the
    stored Part 2 JSON only (never re-parsed for the list). A sample without a
    stored JSON has ``processed=False`` and empty facts.
    """

    sample_id: str
    label: str
    language: str
    title: str | None = None
    has_form: bool = False
    has_password: bool = False
    external_form_action: bool = False  # a form whose action is on another site (Part 2 fact)
    processed: bool = False
    misclassified: bool = False  # a test page the best Part 4 baseline got wrong
    behavior_max_severity: str | None = None  # stored Part 8 result (None = none / not run)


class DomFeatureInfo(BaseModel):
    """One Part 3 feature as the inspector shows it."""

    name: str
    group: str
    type: str
    description: str
    needs_page_url: bool = False


class DomDictionaryInfo(BaseModel):
    """The Part 3 feature dictionary + per-label medians (from the version's report)."""

    feature_set_version: str
    groups: list[str]
    features: list[DomFeatureInfo]
    label_medians: dict[str, dict[str, float]] = Field(default_factory=dict)
