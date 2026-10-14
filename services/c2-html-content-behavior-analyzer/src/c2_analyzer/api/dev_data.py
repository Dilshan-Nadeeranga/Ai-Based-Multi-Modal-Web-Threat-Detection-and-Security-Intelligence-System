"""Read-only access to frozen dataset versions for the developer inspector.

Developer tooling (added after Part 2; the endpoints exist only when APP_ENV=development).

Why: the inspector must show exactly what the engine produced for a training
sample, so it reads the same files the pipeline uses:

    data/metadata/manifests/dataset_<version>.{csv,json}   Part 1 frozen versions
    data/processed/parsed_html/<version>/<sample_id>.json   Part 2 stored ParsedPage
    data/raw/<label>/<file>.html                            the original page

Rules:
- READ ONLY: nothing here writes to data/ (a page processed on the fly is not
  saved; ``preprocess_html.py run`` stays the only writer).
- Never fetches anything: the page URL is only used to resolve relative links.
- Untrusted input (version, sample id) never reaches a file path unchecked:
  versions must match the manifest pattern, sample ids the id pattern AND be
  listed in that version's manifest, and every raw path must stay inside data/raw.
- The sample list reads the stored JSON once and caches a small summary per
  file (keyed by modification time and size), so it never re-parses HTML and
  a re-run of Part 2 is picked up automatically.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

import pandas as pd

from c2_analyzer.dataset.manifest import list_versions, manifest_paths, manifests_dir
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dataset.page_view import read_html
from c2_analyzer.dataset.safe_preview import sanitize_html
from c2_analyzer.preprocessing.batch import output_dir
from c2_analyzer.preprocessing.loader import from_bytes
from c2_analyzer.preprocessing.pipeline import preprocess
from c2_analyzer.schemas.inspector import SampleSummary, VersionInfo

SAMPLE_ID_PATTERN = re.compile(r"^c2_[a-z_]+_\d{6}$")  # the Part 1 id format


class NotFoundError(LookupError):
    """Unknown version / sample, or its file is missing (the route answers 404)."""


@dataclass(frozen=True)
class _Facts:
    """What the sample list needs from one stored ParsedPage JSON."""

    title: str | None
    has_form: bool
    has_password: bool
    external_form_action: bool


def summarize_parsed(data: dict) -> _Facts:
    """Pick the list facts out of a stored ParsedPage dict (no judgement, just facts)."""
    forms = data.get("forms") or []
    inputs = [field for form in forms for field in form.get("inputs") or []]
    inputs += data.get("inputs_outside_forms") or []
    return _Facts(
        title=data.get("title"),
        has_form=bool(forms),
        has_password=any(field.get("type") == "password" for field in inputs),
        external_form_action=any(form.get("is_external_action") for form in forms),
    )


class DevDataset:
    """Frozen versions, their samples and stored Part 2 results, read from disk."""

    def __init__(
        self,
        manifests: Path,
        parsed_root: Path,
        raw_dir: Path,
        metadata_csv: Path | None = None,
    ) -> None:
        self.manifests = manifests
        self.parsed_root = parsed_root  # data/processed/parsed_html (one folder per version)
        self.raw_dir = raw_dir
        self.metadata_csv = metadata_csv
        self._facts: dict[Path, tuple[int, int, _Facts | None]] = {}
        self._manifests: dict[str, tuple[int, pd.DataFrame]] = {}

    @classmethod
    def from_settings(cls) -> DevDataset:
        """The real project folders (same defaults as the Part 1/2 scripts)."""
        store = MetadataStore()  # only used for its paths; metadata.csv is not loaded here
        return cls(
            manifests=manifests_dir(store),
            parsed_root=output_dir(None).parent,
            raw_dir=store.raw_dir,
            metadata_csv=store.csv_path,
        )

    # ---- versions ---------------------------------------------------------------

    def versions(self) -> list[VersionInfo]:
        """Every frozen version, newest first (that is what the inspector opens)."""
        result = []
        for version in reversed(list_versions(self.manifests)):
            _, json_path = manifest_paths(self.manifests, version)
            info = json.loads(json_path.read_text(encoding="utf-8"))
            folder = self.parsed_root / version
            processed = sum(1 for _ in folder.glob("*.json")) if folder.is_dir() else 0
            result.append(
                VersionInfo(
                    version=version,
                    created_at=info.get("created_at"),
                    notes=info.get("notes"),
                    total=int(info.get("total", 0)),
                    processed=processed,
                    counts_per_label=info.get("counts_per_label") or {},
                    counts_per_language=info.get("counts_per_language") or {},
                )
            )
        return result

    def latest_version(self) -> str:
        versions = list_versions(self.manifests)
        if not versions:
            raise NotFoundError("no frozen dataset version (run dataset_stats.py freeze)")
        return versions[-1]

    def manifest(self, version: str) -> pd.DataFrame:
        """The manifest rows of one version (cached until the CSV changes)."""
        try:
            csv_path, _ = manifest_paths(self.manifests, version)  # rejects odd versions
        except ValueError as error:
            raise NotFoundError(str(error)) from None
        if not csv_path.is_file():
            raise NotFoundError(f"no dataset version {version}")
        stamp = csv_path.stat().st_mtime_ns
        cached = self._manifests.get(version)
        if cached is None or cached[0] != stamp:
            frame = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
            cached = (stamp, frame)
            self._manifests[version] = cached
        return cached[1]

    # ---- samples ----------------------------------------------------------------

    def _stored_facts(self, json_path: Path) -> _Facts | None:
        """Summary of a stored JSON, or None if there is none (or it is unreadable)."""
        try:
            stat = json_path.stat()
        except OSError:
            return None
        cached = self._facts.get(json_path)
        if cached is not None and cached[:2] == (stat.st_mtime_ns, stat.st_size):
            return cached[2]
        try:
            facts = summarize_parsed(json.loads(json_path.read_bytes()))
        except (OSError, ValueError, AttributeError, TypeError):
            facts = None  # damaged file: shown as "not processed"
        self._facts[json_path] = (stat.st_mtime_ns, stat.st_size, facts)
        return facts

    def samples(
        self,
        version: str,
        label: str | None = None,
        language: str | None = None,
        query: str | None = None,
        has_password: bool | None = None,
        external_form_action: bool | None = None,
    ) -> list[SampleSummary]:
        """The (filtered) sample list of one version, in manifest order."""
        rows = self.manifest(version)
        if label:
            rows = rows[rows["label"] == label]
        if language:
            rows = rows[rows["language"] == language]
        needle = (query or "").strip().casefold()
        folder = self.parsed_root / version
        result = []
        for row in rows.to_dict("records"):
            facts = self._stored_facts(folder / f"{row['sample_id']}.json")
            summary = SampleSummary(
                sample_id=row["sample_id"],
                label=row["label"],
                language=row["language"],
                processed=facts is not None,
                **(asdict(facts) if facts is not None else {}),
            )
            if has_password is not None and summary.has_password != has_password:
                continue
            if (
                external_form_action is not None
                and summary.external_form_action != external_form_action
            ):
                continue
            if needle and needle not in f"{summary.sample_id} {summary.title or ''}".casefold():
                continue
            result.append(summary)
        return result

    def _row(self, version: str, sample_id: str) -> dict:
        """The manifest row of a sample (validates the id first)."""
        if not SAMPLE_ID_PATTERN.match(sample_id):
            raise NotFoundError(f"invalid sample id {sample_id!r}")
        rows = self.manifest(version)
        match = rows[rows["sample_id"] == sample_id]
        if match.empty:
            raise NotFoundError(f"{sample_id} is not in dataset {version}")
        return match.iloc[0].to_dict()

    def _raw_file(self, row: dict) -> Path:
        """The original HTML file of a manifest row (must stay inside data/raw)."""
        raw_root = self.raw_dir.resolve()
        path = (raw_root / row["file_path"]).resolve()
        if not path.is_relative_to(raw_root):
            raise NotFoundError(f"{row['sample_id']}: file path outside data/raw")
        if not path.is_file():
            raise NotFoundError(f"{row['sample_id']}: raw file missing ({row['file_path']})")
        return path

    def _page_url(self, sample_id: str) -> str | None:
        """final_url > source_url from metadata.csv (None if the CSV is not there)."""
        if self.metadata_csv is None or not self.metadata_csv.is_file():
            return None  # MetadataStore would create an empty CSV - stay read-only
        try:
            record = MetadataStore(self.metadata_csv, self.raw_dir).get(sample_id)
        except (KeyError, ValueError):
            return None
        return record.final_url or record.source_url

    def parsed(self, version: str, sample_id: str) -> tuple[str, str]:
        """(ParsedPage JSON text, "stored" | "on-the-fly").

        The stored JSON is returned as it is on disk. If Part 2 has not
        processed this sample yet, it is processed now - with the same page URL
        the batch would use - but not saved.
        """
        row = self._row(version, sample_id)
        json_path = self.parsed_root / version / f"{sample_id}.json"
        if self._stored_facts(json_path) is not None:
            return json_path.read_text(encoding="utf-8"), "stored"
        raw = from_bytes(
            self._raw_file(row).read_bytes(),
            page_url=self._page_url(sample_id),
            sample_id=sample_id,
            dataset_version=version,
            label=row["label"],
        )
        return preprocess(raw).model_dump_json(by_alias=True), "on-the-fly"

    def safe_preview(self, sample_id: str, version: str | None = None) -> str:
        """Part 1's sanitized copy of a sample (scripts, URLs and forms removed).

        Without a version, the newest manifest that lists the sample is used.
        """
        versions = [version] if version else list(reversed(list_versions(self.manifests)))
        for candidate in versions:
            try:
                row = self._row(candidate, sample_id)
            except NotFoundError:
                continue
            return sanitize_html(read_html(self._raw_file(row)), sample_id)
        raise NotFoundError(f"{sample_id} is not in any frozen dataset version")
