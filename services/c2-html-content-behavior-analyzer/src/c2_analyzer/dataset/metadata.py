"""MetadataStore: the only code that reads and writes data/metadata/metadata.csv.

Part 1: Multilingual dataset preparation.

Why this file exists: metadata.csv is the "index" of the whole dataset - every
later part (splitting, training, evaluation) trusts it. Keeping all reads and
writes in one class means every row is validated by ``SampleMetadata``,
duplicates are blocked in one place, and the file is always written
atomically so a crash can never leave a half-written CSV.

Usage::

    store = MetadataStore()                 # default data/metadata/metadata.csv
    warnings = store.add(record)            # validate + append (in memory)
    store.save()                            # write to disk (atomic)
    problems = store.validate_all()         # health check of the whole dataset
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
from pydantic import ValidationError

from c2_analyzer.config import get_labels, get_settings, resolve_path
from c2_analyzer.schemas.dataset import SAMPLE_ID_PATTERN, SampleMetadata, make_sample_id
from c2_analyzer.utils.hashing import sha256_file
from c2_analyzer.utils.io import atomic_write_csv, read_csv_as_strings

# CSV column order = field order of the pydantic model (one source of truth).
COLUMNS: list[str] = list(SampleMetadata.model_fields)


class DuplicateSampleError(ValueError):
    """Raised when a record's sample_id or sha256 is already in the store.

    ``existing_sample_id`` is the sample that already has this content (for
    sha256 duplicates), so callers can link to it.
    """

    def __init__(self, message: str, existing_sample_id: str | None = None) -> None:
        super().__init__(message)
        self.existing_sample_id = existing_sample_id


def to_cell(value: object) -> str:
    """One value as a CSV cell string (None -> "", bools -> "true"/"false")."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def default_cell(column: str) -> str:
    """CSV cell for an optional field's default value (used when upgrading old files)."""
    return to_cell(SampleMetadata.model_fields[column].get_default(call_default_factory=True))


def record_to_row(record: SampleMetadata) -> dict[str, str]:
    """Convert a record to CSV cell strings."""
    return {name: to_cell(value) for name, value in record.model_dump(mode="json").items()}


def row_to_record(row: dict[str, str]) -> SampleMetadata:
    """Convert a CSV row back to a validated record.

    Empty cells are dropped so optional fields get their defaults and missing
    required fields produce a clear "Field required" error.
    """
    return SampleMetadata.model_validate({key: value for key, value in row.items() if value != ""})


class MetadataStore:
    """Load, query, change and save ``metadata.csv``.

    Changes (add/update) happen in memory; call ``save()`` to write them.
    Internally the CSV is kept as a DataFrame of strings, exactly as on disk.
    """

    def __init__(self, csv_path: Path | None = None, raw_dir: Path | None = None) -> None:
        data_dir = resolve_path(get_settings().data_dir)
        self.csv_path = Path(csv_path) if csv_path else data_dir / "metadata" / "metadata.csv"
        self.raw_dir = Path(raw_dir) if raw_dir else data_dir / "raw"
        self._df: pd.DataFrame | None = None

    @property
    def df(self) -> pd.DataFrame:
        """The in-memory table (loaded from disk on first use)."""
        if self._df is None:
            self.load()
        return self._df

    # ---- reading ---------------------------------------------------------

    def load(self) -> pd.DataFrame:
        """Read the CSV (creating it with only a header row if missing).

        Returns a *copy*, so callers cannot bypass validation by editing it.
        """
        if not self.csv_path.exists():
            atomic_write_csv(pd.DataFrame(columns=COLUMNS), self.csv_path, COLUMNS)
        df = read_csv_as_strings(self.csv_path)

        if list(df.columns) != COLUMNS:
            unknown = [column for column in df.columns if column not in COLUMNS]
            missing = [column for column in COLUMNS if column not in df.columns]
            required_missing = [c for c in missing if SampleMetadata.model_fields[c].is_required()]
            if unknown or required_missing:
                raise ValueError(
                    f"{self.csv_path} has columns {list(df.columns)}, expected {COLUMNS}. "
                    "Fix the header row before continuing."
                )
            # Older file written before new optional fields existed: add them
            # filled with each field's default ("" for None, "ok", "false", ...).
            # They are written to disk on the next save().
            df = df.reindex(columns=COLUMNS)
            for column in missing:
                df[column] = default_cell(column)
        self._df = df
        return df.copy()

    def get(self, sample_id: str) -> SampleMetadata:
        """Return the record for ``sample_id`` (KeyError if it does not exist)."""
        rows = self.df[self.df["sample_id"] == sample_id]
        if rows.empty:
            raise KeyError(f"No sample with sample_id {sample_id!r}")
        return row_to_record(rows.iloc[0].to_dict())

    def filter(
        self,
        label: str | None = None,
        language: str | None = None,
        verified: bool | None = None,
    ) -> pd.DataFrame:
        """Return the rows matching every filter that is not None."""
        df = self.df
        mask = pd.Series(True, index=df.index)
        if label is not None:
            mask &= df["label"] == label
        if language is not None:
            mask &= df["language"] == language
        if verified is not None:
            mask &= df["verified"] == ("true" if verified else "false")
        return df[mask].copy()

    def next_sample_id(self, label: str) -> str:
        """Next free id for ``label``: highest existing number + 1.

        Using the maximum (not the row count) means ids are never reused,
        even if a row is deleted by hand later.
        """
        if label not in get_labels():
            raise ValueError(f"unknown label {label!r}; allowed: {', '.join(get_labels())}")
        numbers = [
            int(match["number"])
            for sample_id in self.df["sample_id"]
            if (match := SAMPLE_ID_PATTERN.match(sample_id)) and match["label"] == label
        ]
        return make_sample_id(label, max(numbers, default=0) + 1)

    # ---- changing --------------------------------------------------------

    def check_can_add(self, record: SampleMetadata) -> None:
        """Raise DuplicateSampleError if the record clashes with an existing row."""
        df = self.df
        if (df["sample_id"] == record.sample_id).any():
            raise DuplicateSampleError(f"sample_id {record.sample_id} already exists")
        same_hash = df.loc[df["sha256"] == record.sha256, "sample_id"]
        if not same_hash.empty:
            raise DuplicateSampleError(
                f"exact duplicate: this file has the same sha256 as {same_hash.iloc[0]} "
                "(identical content is stored only once)",
                existing_sample_id=same_hash.iloc[0],
            )

    def add(self, record: SampleMetadata) -> list[str]:
        """Validate and append a record. Returns warnings (empty list if none).

        Rejects duplicate sample_id or sha256. A repeated source_url is only a
        warning: the page may have changed, so it is not an exact duplicate.
        """
        # Re-validate: pydantic does not re-check fields changed after creation.
        record = SampleMetadata.model_validate(record.model_dump())
        self.check_can_add(record)

        warnings = []
        same_url = self.df.loc[self.df["source_url"] == record.source_url, "sample_id"].tolist()
        if same_url:
            warnings.append(
                f"source_url already used by {', '.join(same_url)}. The page may be a "
                "near-duplicate; if so, set is_duplicate_of after checking."
            )

        row = record_to_row(record)
        self._df.loc[len(self._df)] = [row[column] for column in COLUMNS]
        return warnings

    def update(self, sample_id: str, **fields: object) -> SampleMetadata:
        """Change fields of an existing record, e.g. ``update(id, verified=True, verified_by="X")``.

        The changed record is fully re-validated; on error nothing is changed.
        """
        if "sample_id" in fields:
            raise ValueError("sample_id cannot be changed; register the file again instead")
        current = self.get(sample_id)
        updated = SampleMetadata.model_validate({**current.model_dump(), **fields})

        if updated.sha256 != current.sha256:
            others = self.df[
                (self.df["sha256"] == updated.sha256) & (self.df["sample_id"] != sample_id)
            ]
            if not others.empty:
                raise DuplicateSampleError(
                    f"sha256 already belongs to {others['sample_id'].iloc[0]}"
                )

        index = self.df.index[self.df["sample_id"] == sample_id][0]
        row = record_to_row(updated)
        self._df.loc[index, COLUMNS] = [row[column] for column in COLUMNS]
        return updated

    # ---- checking --------------------------------------------------------

    def validate_all(self) -> list[str]:
        """Check the whole dataset and return a list of human-readable problems.

        Checks: every row is valid, no duplicate ids/hashes, every file exists,
        every file still has the registered sha256, is_duplicate_of points to a
        real sample, and every file in data/raw/ has a metadata row.
        """
        problems: list[str] = []
        df = self.df

        for column in ("sample_id", "sha256"):
            repeated = df.loc[df[column].duplicated(keep=False) & (df[column] != ""), column]
            for value in repeated.unique():
                problems.append(f"duplicate {column} {value} appears in more than one row")

        known_ids = set(df["sample_id"])

        # start=2 because line 1 of the CSV is the header
        for line, row in enumerate(df.to_dict("records"), start=2):
            name = row["sample_id"] or f"line {line}"
            try:
                record = row_to_record(row)
            except ValidationError as error:
                for issue in error.errors():
                    field = ".".join(str(part) for part in issue["loc"]) or "record"
                    problems.append(f"[{name}] invalid {field}: {issue['msg']}")
                continue

            file = self.raw_dir / record.file_path
            if not file.is_file():
                problems.append(f"[{name}] file not found: {file}")
            elif sha256_file(file) != record.sha256:
                problems.append(
                    f"[{name}] sha256 mismatch: {record.file_path} "
                    "was changed after it was registered"
                )

            if record.is_duplicate_of and record.is_duplicate_of not in known_ids:
                problems.append(f"[{name}] is_duplicate_of {record.is_duplicate_of} does not exist")

        for relative in self.unregistered_files():
            problems.append(f"[unregistered] {relative} is in data/raw but has no metadata row")

        return problems

    def unregistered_files(self) -> list[str]:
        """Files in data/raw/ without a metadata row, as ``<label>/<file>`` paths.

        They appear e.g. when a run crashed between copying a page and saving its row.
        """
        if not self.raw_dir.is_dir():
            return []
        registered = {path.replace("\\", "/") for path in self.df["file_path"]}
        orphans = []
        for file in sorted(self.raw_dir.rglob("*")):
            if file.is_file() and file.name != ".gitkeep":
                relative = file.relative_to(self.raw_dir).as_posix()
                if relative not in registered:
                    orphans.append(relative)
        return orphans

    # ---- writing ---------------------------------------------------------

    def save(self) -> None:
        """Write the in-memory table to the CSV (atomically)."""
        atomic_write_csv(self.df, self.csv_path, COLUMNS)
