"""Read-only access to frozen dataset versions for the developer inspector.

Developer tooling (added after Part 2; the endpoints exist only when APP_ENV=development).

Why: the inspector must show exactly what the engine produced for a training
sample, so it reads the same files the pipeline uses:

    data/metadata/manifests/dataset_<version>.{csv,json}   Part 1 frozen versions
    data/processed/parsed_html/<version>/<sample_id>.json   Part 2 stored ParsedPage
    data/raw/<label>/<file>.html                            the original page
    data/processed/dom_features/<version>/<sample_id>.json  Part 3 stored DomResult
    reports/dom_features/<version>_summary.json             Part 3 per-label medians
    data/splits/<version>/split.csv                         shared split (Part 4)
    models/dom_baseline/<version>/*.joblib                  Part 4 trained baselines
    reports/dom_baseline/<version>/misclassified.csv        Part 4 test mistakes
    data/processed/js/<version>/<sample_id>.json            Part 7 stored JsAnalysisResult

Rules:
- READ ONLY: nothing here writes to data/ (a page processed on the fly is not
  saved; ``preprocess_html.py run`` stays the only writer).
- Never fetches anything: the page URL is only used to resolve relative links.
- Saved models are joblib (pickle) files: only the project's own
  models/dom_baseline/<version>/ files are loaded, from a validated version name.
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

import joblib
import pandas as pd

from c2_analyzer.behavior.batch import output_dir as behavior_output_dir
from c2_analyzer.behavior.batch import stored_result as stored_behavior_result
from c2_analyzer.behavior.pipeline import map_behavior
from c2_analyzer.classifiers.dom_baseline.common import MODEL_NAMES, BaselineConfig
from c2_analyzer.classifiers.dom_baseline.predict import predict_features
from c2_analyzer.content.batch import output_dir as content_output_dir
from c2_analyzer.content.batch import stored_result as stored_content_result
from c2_analyzer.content.extractor import extract_content
from c2_analyzer.dataset.manifest import list_versions, manifest_paths, manifests_dir
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dataset.page_view import read_html
from c2_analyzer.dataset.safe_preview import sanitize_html
from c2_analyzer.dataset.splits import split_paths, splits_root
from c2_analyzer.dom.dictionary import dictionary_hash, load_dictionary
from c2_analyzer.dom.exporter import output_dir as dom_output_dir
from c2_analyzer.dom.exporter import reports_dir as dom_reports_dir
from c2_analyzer.dom.pipeline import extract_dom_features
from c2_analyzer.dom.report import label_medians
from c2_analyzer.js_analyzer.batch import output_dir as js_output_dir
from c2_analyzer.js_analyzer.batch import stored_result as stored_js_result
from c2_analyzer.js_analyzer.pipeline import analyze_js
from c2_analyzer.preprocessing.batch import output_dir
from c2_analyzer.preprocessing.loader import from_bytes
from c2_analyzer.preprocessing.pipeline import preprocess
from c2_analyzer.schemas.dom import DomResult
from c2_analyzer.schemas.dom_baseline import DomPrediction
from c2_analyzer.schemas.inspector import (
    DomDictionaryInfo,
    DomFeatureInfo,
    SampleSummary,
    VersionInfo,
)
from c2_analyzer.schemas.js import JsAnalysisResult
from c2_analyzer.schemas.parsed_page import ParsedPage

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
        dom_root: Path | None = None,
        dom_reports: Path | None = None,
        baseline_models: Path | None = None,
        baseline_reports: Path | None = None,
        splits: Path | None = None,
        js_root: Path | None = None,
        behavior_root: Path | None = None,
        content_root: Path | None = None,
    ) -> None:
        self.manifests = manifests
        self.parsed_root = parsed_root  # data/processed/parsed_html (one folder per version)
        self.raw_dir = raw_dir
        self.metadata_csv = metadata_csv
        self.dom_root = dom_root  # data/processed/dom_features (None = never stored)
        self.dom_reports = dom_reports  # reports/dom_features (None = no medians)
        self.baseline_models = baseline_models  # models/dom_baseline (None = no predictions)
        self.baseline_reports = baseline_reports  # reports/dom_baseline (misclassified.csv)
        self.splits = splits  # data/splits (None = split unknown)
        self.js_root = js_root  # data/processed/js (None = never stored)
        self.behavior_root = behavior_root  # data/processed/behavior (None = never stored)
        self.content_root = content_root  # data/processed/text (None = never stored)
        self._bundles: dict[str, tuple[tuple, dict]] = {}
        self._files: dict[Path, tuple[int, object]] = {}
        self._facts: dict[Path, tuple[int, int, _Facts | None]] = {}
        self._manifests: dict[str, tuple[int, pd.DataFrame]] = {}

    @classmethod
    def from_settings(cls) -> DevDataset:
        """The real project folders (same defaults as the Part 1/2 scripts)."""
        store = MetadataStore()  # only used for its paths; metadata.csv is not loaded here
        baseline = BaselineConfig.load()
        return cls(
            manifests=manifests_dir(store),
            parsed_root=output_dir(None).parent,
            raw_dir=store.raw_dir,
            metadata_csv=store.csv_path,
            dom_root=dom_output_dir(None).parent,
            dom_reports=dom_reports_dir(),
            baseline_models=baseline.models_dir,
            baseline_reports=baseline.reports_dir,
            splits=splits_root(),
            js_root=js_output_dir(None).parent,
            behavior_root=behavior_output_dir(None).parent,
            content_root=content_output_dir(None).parent,
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
        misclassified: bool | None = None,
        has_critical_behavior: bool | None = None,
    ) -> list[SampleSummary]:
        """The (filtered) sample list of one version, in manifest order."""
        rows = self.manifest(version)
        wrong = self.misclassified(version)
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
                misclassified=row["sample_id"] in wrong,
                behavior_max_severity=self._behavior_severity(version, row["sample_id"]),
                **(asdict(facts) if facts is not None else {}),
            )
            if has_critical_behavior is not None and (
                (summary.behavior_max_severity == "critical") != has_critical_behavior
            ):
                continue
            if misclassified is not None and summary.misclassified != misclassified:
                continue
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

    def dom_features(self, version: str, sample_id: str) -> tuple[str, str]:
        """(DomResult JSON text, "stored" | "on-the-fly") - Part 3 for one sample.

        The stored result is used when it was made from the same file with the
        current feature dictionary; otherwise the features are computed now from
        the (stored or freshly made) ParsedPage and the raw HTML - not saved.
        """
        row = self._row(version, sample_id)
        if self.dom_root is not None:
            path = self.dom_root / version / f"{sample_id}.json"
            if path.is_file():
                try:
                    stored = DomResult.model_validate_json(path.read_bytes())
                except ValueError:
                    stored = None
                if (
                    stored is not None
                    and stored.dictionary_hash == dictionary_hash()
                    and stored.source_sha256 == row["sha256"]
                ):
                    return path.read_text(encoding="utf-8"), "stored"
        raw = from_bytes(
            self._raw_file(row).read_bytes(),
            page_url=self._page_url(sample_id),
            sample_id=sample_id,
            dataset_version=version,
            label=row["label"],
        )
        text, _ = self.parsed(version, sample_id)
        page = ParsedPage.model_validate_json(text)
        return extract_dom_features(page, raw.html).model_dump_json(), "on-the-fly"

    def js_analysis(self, version: str, sample_id: str) -> tuple[str, str]:
        """(JsAnalysisResult JSON text, "stored" | "on-the-fly") - Part 7 for one sample.

        The stored result is used when it was made from the same file with the
        current rules; otherwise the analysis runs now on the (stored or freshly
        made) ParsedPage - not saved.
        """
        row = self._row(version, sample_id)
        if self.js_root is not None:
            path = self.js_root / version / f"{sample_id}.json"
            if stored_js_result(path, row["sha256"]) is not None:
                return path.read_text(encoding="utf-8"), "stored"
        text, _ = self.parsed(version, sample_id)
        page = ParsedPage.model_validate_json(text)
        return analyze_js(page).model_dump_json(), "on-the-fly"

    def _behavior_severity(self, version: str, sample_id: str) -> str | None:
        """Highest finding severity of the STORED Part 8 result (for the sample list)."""
        if self.behavior_root is None:
            return None

        def load(path: Path) -> str | None:
            try:
                return (json.loads(path.read_bytes()).get("summary") or {}).get("max_severity")
            except (OSError, ValueError, AttributeError):
                return None

        return self._cached_file(self.behavior_root / version / f"{sample_id}.json", load)

    def behavior(self, version: str, sample_id: str) -> tuple[str, str]:
        """(BehaviorResult JSON text, "stored" | "on-the-fly") - Part 8 for one sample.

        The stored result is used when it was made from the same file with the
        current Part 7 + Part 8 rules; otherwise it is computed now from the
        (stored or fresh) ParsedPage and Part 7 result - not saved.
        """
        row = self._row(version, sample_id)
        if self.behavior_root is not None:
            path = self.behavior_root / version / f"{sample_id}.json"
            if stored_behavior_result(path, row["sha256"]) is not None:
                return path.read_text(encoding="utf-8"), "stored"
        page = ParsedPage.model_validate_json(self.parsed(version, sample_id)[0])
        js_result = JsAnalysisResult.model_validate_json(self.js_analysis(version, sample_id)[0])
        return map_behavior(page, js_result).model_dump_json(), "on-the-fly"

    def content(self, version: str, sample_id: str) -> tuple[str, str]:
        """(PageText JSON text, "stored" | "on-the-fly") - Part 5 for one sample.

        The stored result is used when it was made from the same file with the
        current rules (and language backend); otherwise the text is extracted now
        from the (stored or fresh) ParsedPage and the raw HTML - not saved.
        """
        row = self._row(version, sample_id)
        if self.content_root is not None:
            path = self.content_root / version / f"{sample_id}.json"
            if stored_content_result(path, row["sha256"]) is not None:
                return path.read_text(encoding="utf-8"), "stored"
        raw = from_bytes(
            self._raw_file(row).read_bytes(),
            page_url=self._page_url(sample_id),
            sample_id=sample_id,
            dataset_version=version,
            label=row["label"],
        )
        page = ParsedPage.model_validate_json(self.parsed(version, sample_id)[0])
        return extract_content(page, raw.html).model_dump_json(), "on-the-fly"

    def dom_dictionary(self, version: str | None) -> DomDictionaryInfo:
        """The Part 3 feature dictionary + per-label medians of a version (if reported)."""
        dictionary = load_dictionary()
        medians = label_medians(version, self.dom_reports) if version and self.dom_reports else {}
        return DomDictionaryInfo(
            feature_set_version=dictionary.feature_set_version,
            groups=list(dictionary.groups),
            features=[
                DomFeatureInfo(
                    name=spec.name,
                    group=spec.group,
                    type=spec.type,
                    description=spec.description,
                    needs_page_url=spec.needs_page_url,
                )
                for spec in dictionary.features
            ],
            label_medians=medians,
        )

    # ---- Part 4: DOM baseline ---------------------------------------------------

    def _cached_file(self, path: Path, load):
        """load(path), cached until the file changes; None if it does not exist."""
        try:
            stamp = path.stat().st_mtime_ns
        except OSError:
            return None
        cached = self._files.get(path)
        if cached is None or cached[0] != stamp:
            cached = (stamp, load(path))
            self._files[path] = cached
        return cached[1]

    def misclassified(self, version: str) -> set[str]:
        """Test sample ids the BEST baseline model got wrong (empty if not evaluated)."""
        if self.baseline_reports is None:
            return set()
        folder = self.baseline_reports / version
        results = self._cached_file(folder / "results.json", lambda p: json.loads(p.read_bytes()))
        table = self._cached_file(
            folder / "misclassified.csv",
            lambda p: pd.read_csv(p, dtype=str, keep_default_na=False),
        )
        if not results or table is None or table.empty:
            return set()
        best = results.get("best_model")
        return set(table.loc[table["model"] == best, "sample_id"])

    def split_of(self, version: str, sample_id: str) -> str | None:
        """train / val / test / excluded from data/splits/<version>/split.csv (None: no split)."""
        if self.splits is None:
            return None
        csv_path, _, _ = split_paths(version, self.splits)
        table = self._cached_file(
            csv_path, lambda p: pd.read_csv(p, dtype=str, keep_default_na=False)
        )
        if table is None:
            return None
        match = table.loc[table["sample_id"] == sample_id, "split"]
        return None if match.empty else str(match.iloc[0])

    def baseline_bundles(self, version: str) -> tuple[dict, dict]:
        """(trained bundles, model_card) of a version; NotFoundError if none were trained."""
        try:
            manifest_paths(self.manifests, version)  # validates the version name
        except ValueError as error:
            raise NotFoundError(str(error)) from None
        folder = self.baseline_models / version if self.baseline_models else None
        paths = [folder / f"{name}.joblib" for name in MODEL_NAMES] if folder else []
        stamp = tuple(p.stat().st_mtime_ns if p.is_file() else 0 for p in paths)
        if not any(stamp):
            raise NotFoundError(
                f"no DOM baseline trained for {version} - run: python "
                f"scripts/train_dom_baseline.py all --version {version}"
            )
        cached = self._bundles.get(version)
        if cached is None or cached[0] != stamp:
            bundles = {p.stem: joblib.load(p) for p in paths if p.is_file()}
            card_path = folder / "model_card.json"
            card = json.loads(card_path.read_bytes()) if card_path.is_file() else {}
            cached = (stamp, {"bundles": bundles, "card": card})
            self._bundles[version] = cached
        return cached[1]["bundles"], cached[1]["card"]

    def dom_prediction(self, version: str, sample_id: str, top: int = 5) -> DomPrediction:
        """The Part 4 baselines' prediction for a sample (features: stored or on the fly)."""
        row = self._row(version, sample_id)
        bundles, card = self.baseline_bundles(version)
        text, source = self.dom_features(version, sample_id)
        result = DomResult.model_validate_json(text)
        prediction = predict_features(
            result.features,
            bundles,
            version=version,
            dictionary_hash=dictionary_hash(),
            excluded_classes=card.get("excluded_classes", {}),
            top=top,
            sample_id=sample_id,
        )
        split = self.split_of(version, sample_id)
        prediction.true_label = row["label"]
        prediction.split = split
        prediction.misclassified_test = (
            sample_id in self.misclassified(version) if split == "test" else None
        )
        prediction.features_source = source
        return prediction

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
