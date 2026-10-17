"""Scam-text corpus files: paths, row <-> CSV, review decisions, near-duplicate key, freeze.

Part 5: Multilingual scam content analyzer (Batch B, Tasks 11-14).

Why this module exists: the builder, the stats report and the review tool all
read and write the same corpus (``corpus_v1``). Keeping the file format, the
review overlay and the duplicate key in one place means the three can never
disagree about what a row is.

Research integrity (also in the README): the corpus mixes four sources with
different trust levels - page segments and real messages (real text),
synthetic templates and machine translations (augmentation). Every row records
``source_type`` and ``is_synthetic``; augmentation is ALWAYS train; val / test
contain only real text. The stats report shows the synthetic share per split.

Review decisions live in their own file (data/corpus/review/corpus_reviews.csv,
one row per text_id). The corpus is rebuilt from its sources at any time and the
decisions are re-applied, because ``text_id`` is a hash of the source + the
normalized text and therefore stable across rebuilds.

Files with real messages are git-ignored: masking removes emails, phones, NIC
and card numbers, but a name or an address in free text can survive it.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import pandas as pd
import yaml

from c2_analyzer.config import load_yaml_config, project_root, resolve_path
from c2_analyzer.content.taxonomy import load_taxonomy
from c2_analyzer.dataset.manifest import git_commit
from c2_analyzer.schemas.content import CORPUS_SCHEMA_VERSION, CorpusRow
from c2_analyzer.utils.io import atomic_write_csv, atomic_write_text, read_csv_as_strings

CORPUS_NAME = CORPUS_SCHEMA_VERSION  # data/corpus/corpus_v1.csv
COLUMNS = list(CorpusRow.model_fields)
LIST_COLUMNS = ("intents", "cue_intents")
BOOL_COLUMNS = ("is_synthetic", "needs_review", "verified", "excluded")
EXPORT_LANGUAGES = ("en", "si", "ta")  # convenience folders data/corpus/<lang>/
SPLITS = ("train", "val", "test")
REVIEW_COLUMNS = [
    "text_id",
    "intents",
    "primary_intent",
    "language",
    "verified",
    "verified_by",
    "verified_at",
    "excluded",
    "exclusion_reason",
]
ID_PREFIX = {
    "page_segment": "pg",
    "real_message": "rm",
    "synthetic_template": "sy",
    "machine_translation": "mt",
}
NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,40}$")


# ---- paths + rules ---------------------------------------------------------------------


@dataclass(frozen=True)
class CorpusPaths:
    corpus_dir: Path
    real_texts: Path
    synthetic_texts: Path
    mt_dir: Path
    review_dir: Path
    manifests_dir: Path
    reports_dir: Path

    @classmethod
    def from_config(cls) -> CorpusPaths:
        section = load_yaml_config("config").get("corpus", {})
        defaults = cls.under(Path("."))

        def path(key: str) -> Path:
            return resolve_path(Path(section.get(key, getattr(defaults, key))))

        return cls(**{key: path(key) for key in cls.__dataclass_fields__})

    @classmethod
    def under(cls, root: Path) -> CorpusPaths:
        """The default layout below ``root`` (tests use a temporary folder)."""
        corpus = Path(root) / "data" / "corpus"
        return cls(
            corpus_dir=corpus,
            real_texts=corpus / "real_texts.csv",
            synthetic_texts=corpus / "raw_texts_clean.csv",
            mt_dir=corpus / "mt",
            review_dir=corpus / "review",
            manifests_dir=corpus / "manifests",
            reports_dir=Path(root) / "reports" / "content",
        )

    @property
    def corpus_csv(self) -> Path:
        return self.corpus_dir / f"{CORPUS_NAME}.csv"

    @property
    def corpus_jsonl(self) -> Path:
        return self.corpus_dir / f"{CORPUS_NAME}.jsonl"

    @property
    def build_info(self) -> Path:
        return self.corpus_dir / f"{CORPUS_NAME}_build.json"

    @property
    def reviews_csv(self) -> Path:
        return self.review_dir / "corpus_reviews.csv"

    def language_file(self, language: str) -> Path:
        return self.corpus_dir / language / f"{CORPUS_NAME}_{language}.csv"


def rules_path() -> Path:
    return project_root() / "configs" / "corpus.yaml"


@lru_cache(maxsize=1)
def corpus_rules() -> dict[str, Any]:
    """configs/corpus.yaml (cached)."""
    return yaml.safe_load(rules_path().read_text(encoding="utf-8"))


def file_hash(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# ---- the near-duplicate key --------------------------------------------------------------

URL = re.compile(r"(?:https?://|www\.)\S+", re.IGNORECASE)
DIGITS = re.compile(r"\d+")
JOINERS = dict.fromkeys(map(ord, "‌‍"))


def _keep(char: str) -> bool:
    # Letters, combining marks (Sinhala / Tamil vowel signs!) and digits stay; Python's
    # \w does NOT include combining marks, so a [^\w] regex would break those scripts.
    return unicodedata.category(char)[0] in "LMN" or char.isspace()


def dedup_key(text: str) -> str:
    """Normalized text used to find near-identical texts (dedup, grouping, leakage).

    NFC, ZWJ / ZWNJ removed, case-folded, URLs -> "url", every number -> "0"
    (the same SMS with another amount or date is the same message), punctuation
    removed, whitespace collapsed.
    """
    text = unicodedata.normalize("NFC", text).translate(JOINERS).casefold()
    text = DIGITS.sub("0", URL.sub(" url ", text))
    text = "".join(char if _keep(char) else " " for char in text)
    return " ".join(text.split())


def make_text_id(source_type: str, *parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:12]
    return f"{ID_PREFIX[source_type]}_{digest}"


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---- rows <-> files ----------------------------------------------------------------------


def _cell(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ";".join(value)
    return "" if value is None else str(value)


def rows_to_frame(rows: list[CorpusRow]) -> pd.DataFrame:
    """CorpusRow list -> all-string DataFrame (lists ";"-joined, booleans "true"/"false")."""
    records = [{key: _cell(value) for key, value in row.model_dump().items()} for row in rows]
    return pd.DataFrame(records, columns=COLUMNS)


def frame_to_rows(frame: pd.DataFrame) -> list[CorpusRow]:
    """The reverse of rows_to_frame (validates every row)."""
    rows = []
    for record in frame.to_dict("records"):
        data: dict[str, Any] = dict(record)
        for key in LIST_COLUMNS:
            data[key] = [part for part in str(data.get(key, "")).split(";") if part]
        for key in BOOL_COLUMNS:
            data[key] = str(data.get(key, "")).lower() == "true"
        data["dup_count"] = int(data.get("dup_count") or 1)
        rows.append(CorpusRow(**data))
    return rows


def write_corpus(frame: pd.DataFrame, paths: CorpusPaths) -> list[Path]:
    """corpus_v1.csv + .jsonl (all rows) and per-language CSVs (active rows only)."""
    frame = frame.sort_values(["split", "source_type", "text_id"]).reset_index(drop=True)
    atomic_write_csv(frame, paths.corpus_csv, COLUMNS)
    lines = [row.model_dump_json() for row in frame_to_rows(frame)]
    atomic_write_text("\n".join(lines) + ("\n" if lines else ""), paths.corpus_jsonl)
    written = [paths.corpus_csv, paths.corpus_jsonl]
    active = frame[frame["excluded"] != "true"]
    for language in EXPORT_LANGUAGES:
        path = paths.language_file(language)
        atomic_write_csv(active[active["language"] == language], path, COLUMNS)
        written.append(path)
    return written


def read_corpus_file(paths: CorpusPaths) -> pd.DataFrame:
    if not paths.corpus_csv.exists():
        raise FileNotFoundError(
            f"{paths.corpus_csv} not found - run: python scripts/build_text_corpus.py build "
            "--version <dataset version>"
        )
    frame = read_csv_as_strings(paths.corpus_csv)
    missing = set(COLUMNS) - set(frame.columns)
    if missing:
        raise ValueError(f"{paths.corpus_csv} is missing column(s) {sorted(missing)}; rebuild it")
    return frame[COLUMNS]


def load_corpus(paths: CorpusPaths) -> pd.DataFrame:
    """The built corpus with the latest review decisions applied."""
    frame = read_corpus_file(paths)
    frame, _ = apply_reviews(frame, ReviewStore(paths.reviews_csv).frame())
    return frame


def active_rows(frame: pd.DataFrame) -> pd.DataFrame:
    """Rows a model may use: not excluded by the reviewer."""
    return frame[frame["excluded"] != "true"]


# ---- review decisions --------------------------------------------------------------------


class ReviewStore:
    """data/corpus/review/corpus_reviews.csv: the reviewer's latest decision per text_id.

    Written atomically after EVERY decision (a review can stop at any key press).
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._frame: pd.DataFrame | None = None

    def frame(self) -> pd.DataFrame:
        if self._frame is None:
            if self.path.exists():
                frame = read_csv_as_strings(self.path)
                for column in REVIEW_COLUMNS:
                    if column not in frame.columns:
                        frame[column] = ""
                self._frame = frame[REVIEW_COLUMNS]
            else:
                self._frame = pd.DataFrame(columns=REVIEW_COLUMNS)
        return self._frame

    def get(self, text_id: str) -> dict[str, str] | None:
        frame = self.frame()
        found = frame[frame["text_id"] == text_id]
        return None if found.empty else found.iloc[-1].to_dict()

    def save_decision(self, text_id: str, **values: str) -> dict[str, str]:
        """Upsert one decision (unspecified fields keep their previous value) and save."""
        frame = self.frame()
        record = self.get(text_id) or dict.fromkeys(REVIEW_COLUMNS, "")
        record.update({key: _cell(value) for key, value in values.items()})
        record["text_id"] = text_id
        frame = frame[frame["text_id"] != text_id]
        frame = pd.concat([frame, pd.DataFrame([record], columns=REVIEW_COLUMNS)])
        self._frame = frame.reset_index(drop=True)
        atomic_write_csv(self._frame, self.path, REVIEW_COLUMNS)
        return record


def apply_reviews(frame: pd.DataFrame, reviews: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """Overlay review decisions on corpus rows. Returns (frame, orphaned review text_ids).

    Orphaned = a decision for a text that is no longer in the corpus (its source
    changed); it stays in the review file in case the text comes back.
    """
    frame = frame.copy()
    if reviews.empty:
        return frame, []
    position = {
        text_id: index for index, text_id in zip(frame.index, frame["text_id"], strict=True)
    }
    orphaned = []
    for review in reviews.to_dict("records"):
        index = position.get(review["text_id"])
        if index is None:
            orphaned.append(review["text_id"])
            continue
        if review.get("intents"):
            frame.at[index, "intents"] = review["intents"]
            frame.at[index, "primary_intent"] = review["primary_intent"]
            frame.at[index, "intent_source"] = "reviewer"
        if review.get("language"):
            frame.at[index, "language"] = review["language"]
        for key in ("verified", "verified_by", "verified_at", "excluded", "exclusion_reason"):
            if review.get(key):
                frame.at[index, key] = review[key]
        if review.get("verified") == "true" or review.get("excluded") == "true":
            frame.at[index, "needs_review"] = "false"
    return frame, orphaned


# ---- freeze ------------------------------------------------------------------------------

MANIFEST_COLUMNS = [
    "text_id",
    "text_sha256",
    "language",
    "primary_intent",
    "intents",
    "source_type",
    "is_synthetic",
    "group_id",
    "split",
    "verified",
    "excluded",
]


def fingerprint(frame: pd.DataFrame) -> str:
    """One sha256 over (text_id, text hash, language, intents, split) of every row."""
    lines = sorted(
        "|".join(
            [
                row["text_id"],
                text_sha256(row["text"]),
                row["language"],
                row["intents"],
                row["split"],
                row["excluded"],
            ]
        )
        for row in frame.to_dict("records")
    )
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def freeze_corpus(paths: CorpusPaths, name: str, notes: str | None = None) -> tuple[Path, dict]:
    """Write data/corpus/manifests/<name>.{csv,json}: row ids + text hashes + counts, NO text.

    Like the dataset manifests (Part 1): never overwrites an existing name, so a
    result in the thesis can always be traced to the exact corpus it used.
    """
    if not NAME_PATTERN.match(name):
        raise ValueError(f"invalid corpus name {name!r}; use e.g. corpus_v1")
    csv_path = paths.manifests_dir / f"{name}.csv"
    json_path = paths.manifests_dir / f"{name}.json"
    if csv_path.exists() or json_path.exists():
        raise FileExistsError(
            f"corpus {name} is already frozen ({csv_path.name}); frozen corpora are never "
            "overwritten - choose a new name"
        )
    frame = load_corpus(paths).sort_values("text_id").reset_index(drop=True)
    if frame.empty:
        raise ValueError("the corpus is empty - nothing to freeze")
    manifest = frame.assign(text_sha256=[text_sha256(text) for text in frame["text"]])
    active = active_rows(frame)
    build = (
        json.loads(paths.build_info.read_text(encoding="utf-8"))
        if (paths.build_info.exists())
        else {}
    )
    taxonomy = load_taxonomy()
    info = {
        "name": name,
        "schema_version": CORPUS_SCHEMA_VERSION,
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "dataset_version": build.get("dataset_version"),
        "taxonomy_version": taxonomy.version,
        "taxonomy_sha256": taxonomy.file_hash,
        "corpus_rules_sha256": file_hash(rules_path()),
        "rows": len(frame),
        "active_rows": len(active),
        "excluded_rows": len(frame) - len(active),
        "verified_rows": int((active["verified"] == "true").sum()),
        "counts": {
            "split": active["split"].value_counts().sort_index().to_dict(),
            "language": active["language"].value_counts().sort_index().to_dict(),
            "source_type": active["source_type"].value_counts().sort_index().to_dict(),
            "primary_intent": active["primary_intent"].value_counts().sort_index().to_dict(),
        },
        "fingerprint": fingerprint(frame),
        "git_commit": git_commit(),
        "notes": notes,
    }
    atomic_write_csv(manifest, csv_path, MANIFEST_COLUMNS)
    atomic_write_text(json.dumps(info, indent=2, ensure_ascii=False) + "\n", json_path)
    return csv_path, info
