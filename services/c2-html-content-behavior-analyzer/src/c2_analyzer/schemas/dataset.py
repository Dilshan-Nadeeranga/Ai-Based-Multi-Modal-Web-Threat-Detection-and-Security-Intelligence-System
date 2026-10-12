"""Pydantic model for the metadata of one dataset sample.

Part 1: Multilingual dataset preparation.

Why this file exists: every HTML page in ``data/raw/`` needs one trustworthy
metadata record (label, language, where it came from, its hash, ...). This
model is the single gatekeeper - a record that passes ``SampleMetadata``
validation is safe to write to ``metadata.csv``. Bad labels, malformed ids or
impossible dates are rejected *before* they can pollute the training data.

It mirrors ``data/metadata/dataset_schema.json``. Allowed labels, languages,
sources and quality flags are read from ``configs/*.yaml`` so they are defined
in one place only.

Relabelling (Batch C): a sample keeps its sample_id forever, even when a
reviewer corrects its label. The old label is stored in ``label_original``, so
an id such as c2_phishing_000003 with label=benign is valid only if
label_original=phishing. Keeping the id is simpler than issuing a new one:
nothing that refers to the sample (is_duplicate_of, candidates.csv, cluster
reports, peer-review sheets) has to be rewritten.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from c2_analyzer.config import get_labels, get_languages, get_quality_flags, get_sources

# c2_<label>_<6 digits>. The label part may itself contain "_" (fake_ecommerce);
# that is fine because the number is always the last 6 digits.
SAMPLE_ID_PATTERN = re.compile(r"^c2_(?P<label>[a-z_]+)_(?P<number>\d{6})$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
CLUSTER_ID_PATTERN = re.compile(r"^cl_\d{6}$")
MAX_SAMPLE_NUMBER = 999_999

# How the HTML was obtained: downloaded as-is (static), downloaded after running
# the page's JavaScript in a browser (rendered), or saved by hand (manual).
FetchMode = Literal["static", "rendered", "manual"]


def make_sample_id(label: str, number: int) -> str:
    """Build a sample id such as ``c2_phishing_000001``."""
    if not 1 <= number <= MAX_SAMPLE_NUMBER:
        raise ValueError(f"sample number must be between 1 and {MAX_SAMPLE_NUMBER}, got {number}")
    return f"c2_{label}_{number:06d}"


def _check_allowed(value: str, allowed: tuple[str, ...], field: str) -> str:
    if value not in allowed:
        raise ValueError(f"unknown {field} {value!r}; allowed: {', '.join(allowed)}")
    return value


class SampleMetadata(BaseModel):
    """One row of ``data/metadata/metadata.csv``."""

    # extra="forbid": a typo such as "lable" is an error, not silently ignored.
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    sample_id: str
    file_path: str  # relative to data/raw/, e.g. "phishing/c2_phishing_000001.html"
    label: str
    language: str
    source: str
    source_url: str
    collection_date: date
    sha256: str
    file_size_bytes: int | None = Field(default=None, ge=0)
    fetch_mode: FetchMode = "manual"
    final_url: str | None = None  # URL after redirects (fetched samples only)
    http_status: int | None = Field(default=None, ge=100, le=599)
    content_type: str | None = None
    verified: bool = False
    verified_by: str | None = None
    verification_date: date | None = None
    is_duplicate_of: str | None = None
    # ---- Batch C: cleaning and verification ----
    cluster_id: str | None = None  # near-duplicate group, e.g. "cl_000123"
    quality_flag: str = "ok"  # see configs/quality_rules.yaml
    excluded: bool = False  # True = keep the file, but never use it for training
    exclusion_reason: str | None = None
    label_original: str | None = None  # label before a reviewer corrected it
    notes: str | None = None

    # ---- single-field checks -------------------------------------------

    @field_validator("label")
    @classmethod
    def _label_is_known(cls, value: str) -> str:
        return _check_allowed(value, get_labels(), "label")

    @field_validator("language")
    @classmethod
    def _language_is_known(cls, value: str) -> str:
        return _check_allowed(value, get_languages(), "language")

    @field_validator("source")
    @classmethod
    def _source_is_known(cls, value: str) -> str:
        return _check_allowed(value, get_sources(), "source")

    @field_validator("quality_flag")
    @classmethod
    def _quality_flag_is_known(cls, value: str) -> str:
        return _check_allowed(value, get_quality_flags(), "quality_flag")

    @field_validator("label_original")
    @classmethod
    def _original_label_is_known(cls, value: str | None) -> str | None:
        return value if value is None else _check_allowed(value, get_labels(), "label_original")

    @field_validator("cluster_id")
    @classmethod
    def _cluster_id_format(cls, value: str | None) -> str | None:
        if value is not None and not CLUSTER_ID_PATTERN.match(value):
            raise ValueError(f"{value!r} is not a valid cluster id; expected cl_<6 digits>")
        return value

    @field_validator("sample_id", "is_duplicate_of")
    @classmethod
    def _sample_id_format(cls, value: str | None) -> str | None:
        if value is None:
            return value
        match = SAMPLE_ID_PATTERN.match(value)
        if not match or match["label"] not in get_labels():
            raise ValueError(
                f"{value!r} is not a valid sample id; expected c2_<label>_<6 digits>, "
                "e.g. c2_phishing_000001"
            )
        return value

    @field_validator("sha256")
    @classmethod
    def _sha256_format(cls, value: str) -> str:
        value = value.lower()  # store hashes in one canonical form
        if not SHA256_PATTERN.match(value):
            raise ValueError("sha256 must be exactly 64 hexadecimal characters")
        return value

    @field_validator("source_url", "final_url")
    @classmethod
    def _url_format(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith(("http://", "https://")):
            raise ValueError("URLs must start with http:// or https://")
        return value

    @field_validator("collection_date", "verification_date")
    @classmethod
    def _not_in_future(cls, value: date | None) -> date | None:
        if value is not None and value > date.today():
            raise ValueError(f"date {value} is in the future")
        return value

    @field_validator("file_path")
    @classmethod
    def _file_path_is_relative(cls, value: str) -> str:
        value = value.replace("\\", "/")  # Windows paths -> one canonical form
        if value.startswith("/") or ":" in value or ".." in value.split("/"):
            raise ValueError("file_path must be relative to data/raw/ (no drive, no '/', no '..')")
        return value

    # ---- checks that compare several fields ----------------------------

    @model_validator(mode="after")
    def _fields_are_consistent(self) -> SampleMetadata:
        # The id was made from the first label; after a relabel that is label_original.
        if self.label_original == self.label:
            raise ValueError("label_original must differ from label (leave it empty instead)")
        id_label = self.label_original or self.label
        if not self.sample_id.startswith(f"c2_{id_label}_"):
            raise ValueError(
                f"sample_id {self.sample_id} does not match label {id_label!r}"
                + (" (label_original)" if self.label_original else "")
            )

        folder, _, file_name = self.file_path.partition("/")
        if folder != self.label or not file_name or "/" in file_name:
            raise ValueError(
                f"file_path must be '{self.label}/<file name>' (inside the label folder), "
                f"got {self.file_path!r}"
            )

        if self.is_duplicate_of == self.sample_id:
            raise ValueError("a sample cannot be a duplicate of itself")

        if self.verified and not self.verified_by:
            raise ValueError("verified=True requires verified_by (who checked the label)")

        if self.verification_date and self.verification_date < self.collection_date:
            raise ValueError("verification_date cannot be before collection_date")

        if self.excluded and not self.exclusion_reason:
            raise ValueError("excluded=True requires exclusion_reason")
        if self.exclusion_reason and not self.excluded:
            raise ValueError("exclusion_reason is only allowed when excluded=True")
        return self
