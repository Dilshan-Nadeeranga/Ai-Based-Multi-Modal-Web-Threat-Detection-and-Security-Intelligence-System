"""CandidateStore: the to-do list of URLs waiting to be fetched (data/metadata/candidates.csv).

Part 1: Multilingual dataset preparation (Batch B, stage 1 of collection).

Why: collection is split in two stages so each can be repeated safely:

    Stage 1  feeds / manual CSV  ->  candidates.csv          (this file)
    Stage 2  candidates.csv      ->  data/raw + metadata.csv (fetcher)

Every candidate has a status, so a fetch run can be stopped (Ctrl+C) and
resumed later, failed URLs can be retried, and the same URL is never queued
twice (URLs are compared in normalized form).
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import date
from pathlib import Path
from typing import Literal

import pandas as pd
from pydantic import BaseModel, ConfigDict, Field, field_validator

from c2_analyzer.config import (
    get_labels,
    get_languages,
    get_sources,
    load_yaml_config,
    resolve_path,
)
from c2_analyzer.utils.io import atomic_write_csv, read_csv_as_strings
from c2_analyzer.utils.url import normalize_url

# pending   - waiting to be fetched
# fetched   - saved to data/raw and registered (sample_id is set)
# failed    - network error / timeout / non-2xx status (can be retried)
# skipped   - fetched but not usable (not HTML, too large) - not retried
# duplicate - content identical to an existing sample (sample_id = that sample)
CandidateStatus = Literal["pending", "fetched", "failed", "skipped", "duplicate"]


def allowed_language_hints() -> tuple[str, ...]:
    """Real languages from configs/languages.yaml plus "unknown"."""
    return (*get_languages(include_special=False), "unknown")


class Candidate(BaseModel):
    """One row of candidates.csv."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    url: str
    suggested_label: str
    language_hint: str = "unknown"
    source: str
    discovered_date: date = Field(default_factory=date.today)
    status: CandidateStatus = "pending"
    attempts: int = Field(default=0, ge=0)
    last_error: str | None = None
    sample_id: str | None = None
    notes: str | None = None  # e.g. URLhaus threat/tags or notes from the manual CSV

    @field_validator("url")
    @classmethod
    def _url_format(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("url must start with http:// or https://")
        return value

    @field_validator("suggested_label")
    @classmethod
    def _label_is_known(cls, value: str) -> str:
        if value not in get_labels():
            raise ValueError(f"unknown label {value!r}; allowed: {', '.join(get_labels())}")
        return value

    @field_validator("language_hint")
    @classmethod
    def _language_is_known(cls, value: str) -> str:
        if value not in allowed_language_hints():
            raise ValueError(
                f"unknown language_hint {value!r}; allowed: {', '.join(allowed_language_hints())}"
            )
        return value

    @field_validator("source")
    @classmethod
    def _source_is_known(cls, value: str) -> str:
        if value not in get_sources():
            raise ValueError(f"unknown source {value!r}; allowed: {', '.join(get_sources())}")
        return value


COLUMNS: list[str] = list(Candidate.model_fields)


def candidate_to_row(candidate: Candidate) -> dict[str, str]:
    """Candidate -> CSV cell strings (None -> "")."""
    return {
        name: "" if value is None else str(value)
        for name, value in candidate.model_dump(mode="json").items()
    }


def row_to_candidate(row: dict[str, str]) -> Candidate:
    """CSV row -> validated Candidate (empty cells use the defaults)."""
    return Candidate.model_validate({key: value for key, value in row.items() if value != ""})


class CandidateStore:
    """Load, query, change and save ``candidates.csv`` (same style as MetadataStore)."""

    def __init__(self, csv_path: Path | None = None) -> None:
        if csv_path is None:
            csv_path = Path(load_yaml_config("config")["collection"]["candidates_csv"])
        self.csv_path = resolve_path(Path(csv_path))
        self._df: pd.DataFrame | None = None
        self._url_index: dict[str, int] | None = None  # normalized url -> row (built lazily)

    @property
    def df(self) -> pd.DataFrame:
        if self._df is None:
            self.load()
        return self._df

    def load(self) -> pd.DataFrame:
        """Read the CSV (creating it with a header row if missing); returns a copy."""
        if not self.csv_path.exists():
            atomic_write_csv(pd.DataFrame(columns=COLUMNS), self.csv_path, COLUMNS)
        df = read_csv_as_strings(self.csv_path)
        if list(df.columns) != COLUMNS:
            raise ValueError(f"{self.csv_path} has columns {list(df.columns)}, expected {COLUMNS}")
        self._df = df
        self._url_index = None
        return df.copy()

    def save(self) -> None:
        """Write to disk atomically (temp file + rename)."""
        atomic_write_csv(self.df, self.csv_path, COLUMNS)

    # ---- adding ------------------------------------------------------------

    def add_many(self, candidates: Iterable[Candidate]) -> tuple[int, int]:
        """Queue new candidates. Returns (added, skipped_as_duplicate_url).

        Two URLs are the same if their normalized forms match (case of host,
        #fragment and trailing "/" are ignored) - also within the new batch.
        """
        seen = {normalize_url(url) for url in self.df["url"]}
        new_rows = []
        duplicates = 0
        for candidate in candidates:
            key = normalize_url(candidate.url)
            if key in seen:
                duplicates += 1
                continue
            seen.add(key)
            new_rows.append(candidate_to_row(candidate))

        if new_rows:
            new = pd.DataFrame(new_rows, columns=COLUMNS)
            self._df = new if self.df.empty else pd.concat([self.df, new], ignore_index=True)
            self._url_index = None
        return len(new_rows), duplicates

    # ---- querying ------------------------------------------------------------

    def _rows(self, status: str, label: str | None) -> pd.DataFrame:
        df = self.df
        mask = df["status"] == status
        if label is not None:
            mask &= df["suggested_label"] == label
        return df[mask]

    def get(self, url: str) -> Candidate:
        """Return the candidate whose normalized URL equals ``url``'s (KeyError if none)."""
        return row_to_candidate(self.df.loc[self._index_of(url)].to_dict())

    def next_pending(self, label: str | None = None, limit: int | None = None) -> list[Candidate]:
        """Candidates still waiting to be fetched, oldest first."""
        rows = self._rows("pending", label)
        if limit is not None:
            rows = rows.head(limit)
        return [row_to_candidate(row) for row in rows.to_dict("records")]

    def retryable(
        self, max_attempts: int, label: str | None = None, limit: int | None = None
    ) -> list[Candidate]:
        """Failed candidates that have been tried fewer than ``max_attempts`` times."""
        rows = self._rows("failed", label)
        rows = rows[rows["attempts"].astype(int) < max_attempts]
        if limit is not None:
            rows = rows.head(limit)
        return [row_to_candidate(row) for row in rows.to_dict("records")]

    def status_counts(self) -> pd.DataFrame:
        """Table: one row per label, one column per status, cell = number of candidates."""
        statuses = list(CandidateStatus.__args__)
        table = pd.crosstab(self.df["suggested_label"], self.df["status"])
        return table.reindex(index=list(get_labels()), columns=statuses, fill_value=0)

    # ---- changing ------------------------------------------------------------

    def mark(
        self,
        url: str,
        status: CandidateStatus,
        error: str | None = None,
        sample_id: str | None = None,
        count_attempt: bool = True,
    ) -> Candidate:
        """Record the outcome of a fetch attempt for ``url`` (validated before saving)."""
        index = self._index_of(url)
        current = row_to_candidate(self.df.loc[index].to_dict())
        updated = Candidate.model_validate(
            {
                **current.model_dump(),
                "status": status,
                "last_error": error,
                "sample_id": sample_id,
                "attempts": current.attempts + (1 if count_attempt else 0),
            }
        )
        row = candidate_to_row(updated)
        self._df.loc[index, COLUMNS] = [row[column] for column in COLUMNS]
        return updated

    def _index_of(self, url: str):
        # Normalizing thousands of URLs on every lookup is slow, so the
        # normalized-url -> row index is built once and reused until rows change.
        if self._url_index is None:
            self._url_index = {}
            for index, row_url in zip(self.df.index, self.df["url"], strict=True):
                self._url_index.setdefault(normalize_url(row_url), index)
        index = self._url_index.get(normalize_url(url))
        if index is None:
            raise KeyError(f"No candidate with url {url!r}")
        return index
