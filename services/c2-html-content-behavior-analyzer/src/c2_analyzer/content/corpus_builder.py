"""Build the scam-text corpus (corpus_v1) from four sources with different trust levels.

Part 5: Multilingual scam content analyzer (Batch B, Tasks 11-13).

Why: Part 6 needs short texts labelled with a social-engineering INTENT
(configs/intent_taxonomy.yaml) in English, Sinhala and Tamil. No such dataset
exists for Sri Lanka, so it is assembled from:

a) page_segment         titles / CTAs / form labels / alerts / headings / short
                        paragraphs of the dataset pages (Part 5A PageText).
                        Weak-labelled with the taxonomy cue words; text from a
                        BENIGN page stays benign unless a strong cue fires
                        (then needs_review). split = the page's split in the
                        SHARED split (data/splits/<version>/) - pages are never
                        re-split; group = the page's near-duplicate cluster.
b) real_message         data/corpus/real_texts.csv - SMS / WhatsApp / CERT /
                        news texts I collected by hand (may be missing). PII is
                        masked; grouped stratified 70/15/15 split by
                        language x intent (seed 42).
c) synthetic_template   data/corpus/raw_texts_clean.csv - ALWAYS train.
d) machine_translation  data/corpus/mt/*.csv (NLLB, notebooks/05_corpus_mt_colab)
                        - ALWAYS train; a translation of a val / test row (or of
                        a row that no longer exists) is dropped.

Research integrity: synthetic and machine-translated rows are train-only
augmentation; val / test hold only real text. A text that appears (near-
identically, see ``corpus.dedup_key``) in train AND val / test is kept only in
the held-out split (test > val > train), so a model is never tested on a
sentence it was trained on. Everything dropped or moved is counted in
data/corpus/corpus_v1_build.json and in the stats report.
"""

from __future__ import annotations

import json
import random
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

from c2_analyzer.config import load_yaml_config
from c2_analyzer.content import language as language_id
from c2_analyzer.content.corpus import (
    SPLITS,
    CorpusPaths,
    ReviewStore,
    apply_reviews,
    corpus_rules,
    dedup_key,
    file_hash,
    frame_to_rows,
    load_corpus,
    make_text_id,
    rows_to_frame,
    rules_path,
    write_corpus,
)
from c2_analyzer.content.taxonomy import BENIGN, Taxonomy, load_taxonomy, weak_label
from c2_analyzer.dataset.splits import check_current, load_split
from c2_analyzer.preprocessing.text_utils import normalize_inline
from c2_analyzer.schemas.content import CorpusRow, PageText
from c2_analyzer.utils.io import atomic_write_csv, write_json
from c2_analyzer.utils.pii import mask_pii, mask_url

MT_INPUT_NAME = "mt_input_en.csv"
MT_INPUT_COLUMNS = ["source_text_id", "text", "intent", "source_type"]
MT = "machine_translation"
SPLIT_PRIORITY = {"test": 0, "val": 1, "train": 2}  # where a cross-split duplicate is kept
SOURCE_TRUST = {
    "real_message": 0,
    "page_segment": 1,
    "synthetic_template": 2,
    "machine_translation": 3,
}


@dataclass
class BuildReport:
    """What the build did - saved as corpus_v1_build.json and shown by ``stats``."""

    dataset_version: str
    sources: dict[str, dict[str, Any]] = field(default_factory=lambda: defaultdict(Counter))
    real_split_cells: list[dict[str, Any]] = field(default_factory=list)
    leakage: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def count(self, source: str, key: str, amount: int = 1) -> None:
        self.sources[source][key] += amount


# ---- helpers -------------------------------------------------------------------------------


def clean_text(text: str) -> str:
    """NFC + whitespace collapse (Part 2 text_utils), then Part 2's PII rules.

    ``mask_pii`` replaces emails / phones / NIC / card numbers; ``mask_url`` also
    catches PII hidden percent-encoded in a URL's query or fragment
    (``?e=a%40b.com``). The URL itself stays (a scam domain is evidence).
    [NAME]-style placeholders in the source are kept as they are.
    """
    text = mask_pii(normalize_inline(text or ""))
    words = []
    for word in text.split(" "):
        if word.lower().startswith(("http://", "https://")):
            word = mask_url(word) or word
        words.append(word)
    return " ".join(words)


def parse_intents(value: str, taxonomy: Taxonomy) -> list[str] | None:
    """'fake_reward;urgency_threat' -> list (given order; first = primary); None if invalid."""
    parts = [
        part.strip().lower()
        for part in str(value).replace("|", ";").replace(",", ";").split(";")
        if part.strip()
    ]
    if not parts or any(part not in taxonomy.intents for part in parts):
        return None
    intents = list(dict.fromkeys(parts))
    if len(intents) > 1 and BENIGN in intents:
        intents.remove(BENIGN)
    return intents


def read_source(path: Path, required: set[str], report: BuildReport, source: str):
    """A source CSV as strings, or None (missing file / missing columns are reported)."""
    if not path.exists():
        report.count(source, "file_missing")
        return None
    frame = pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8-sig")
    missing = required - set(frame.columns)
    if missing:
        report.warnings.append(f"{path.name}: missing column(s) {sorted(missing)} - file skipped")
        report.count(source, "file_skipped_bad_columns")
        return None
    return frame


def detect(text: str) -> str:
    return language_id.detect_language(text)


def language_note(given: str, detected: str) -> str:
    return "" if given == detected else f"language given {given}, detected {detected}"


def merge_duplicate(kept: CorpusRow, other_intents: list[str]) -> None:
    """A near-identical copy: count it; disagreeing given labels need a person."""
    kept.dup_count += 1
    if other_intents and other_intents != kept.intents:
        kept.needs_review = True
        conflict = f"duplicate labelled {';'.join(other_intents)}"
        if conflict not in kept.notes:
            kept.notes = "; ".join(filter(None, [kept.notes, conflict]))


# ---- a) page segments ---------------------------------------------------------------------


def page_segment_rows(
    version: str,
    text_dir: Path,
    splits_root: Path | None,
    taxonomy: Taxonomy,
    report: BuildReport,
    manifests: Path | None = None,
) -> list[CorpusRow]:
    """Weak-labelled segments of every page in the shared split (see module docstring).

    ``manifests``: refuse a split made from another frozen manifest (as Part 4 does).
    """
    rules = corpus_rules()["page_segments"]
    limits: dict[str, dict] = rules["fields"]
    field_rank = {name: rank for rank, name in enumerate(limits)}
    split, split_info = load_split(version, splits_root)
    if manifests is not None:
        check_current(split_info, manifests, version)
    groups: dict[str, dict[str, CorpusRow]] = defaultdict(dict)  # cluster -> key -> row
    source = "page_segment"

    for page in split.sort_values("sample_id").to_dict("records"):
        if page["split"] not in SPLITS:
            report.count(source, "pages_not_in_train_val_test")
            continue
        path = text_dir / f"{page['sample_id']}.json"
        if not path.exists():
            report.count(source, "pages_missing_text_json")
            continue
        result = PageText.model_validate_json(path.read_text(encoding="utf-8"))
        report.count(source, "pages")
        chosen = []
        for segment in result.segments:
            limit = limits.get(segment.field)
            if limit is None:
                continue
            report.count(source, "segments_seen")
            if not limit["min_chars"] <= len(segment.text) <= limit["max_chars"]:
                report.count(source, "rejected_length")
            elif language_id.letter_count(segment.text) < rules["min_letters"]:
                report.count(source, "rejected_few_letters")
            else:
                chosen.append(segment)
        chosen.sort(key=lambda s: (field_rank[s.field], s.order))
        if len(chosen) > rules["max_segments_per_page"]:
            report.count(source, "capped_per_page", len(chosen) - rules["max_segments_per_page"])
            chosen = chosen[: rules["max_segments_per_page"]]

        benign_page = page["label"] == BENIGN
        group = groups[page["cluster_id"]]
        for segment in chosen:
            key = dedup_key(segment.text)
            if key in group:  # near-identical text on another page of the same cluster
                group[key].dup_count += 1
                report.count(source, "duplicates_merged_in_group")
                continue
            label = weak_label(segment.text, benign_page=benign_page, taxonomy=taxonomy)
            if label.needs_review:
                report.count(source, "benign_page_strong_cue")
            group[key] = CorpusRow(
                text_id=make_text_id(source, page["sample_id"], key),
                text=segment.text,
                language=segment.language,
                language_given=page["language"],
                intents=label.intents,
                primary_intent=label.primary,
                cue_intents=label.cue_intents,
                intent_source="weak_cue",
                source_type=source,
                source_ref=f"{page['sample_id']}:{segment.segment_id}",
                field=segment.field,
                page_label=page["label"],
                is_synthetic=False,
                group_id=page["cluster_id"],
                split=page["split"],
                needs_review=label.needs_review,
                notes=label.note,
            )
    rows = [row for group in groups.values() for row in group.values()]
    report.count(source, "rows", len(rows))
    return rows


# ---- b) real messages ----------------------------------------------------------------------


def _given_rows(
    frame: pd.DataFrame, path: Path, source: str, taxonomy: Taxonomy, report: BuildReport
) -> dict[str, tuple[CorpusRow, dict]]:
    """Shared by real / synthetic / MT: clean, validate, detect language, merge copies."""
    allowed = set(corpus_rules()["given_languages"])
    kept: dict[str, tuple[CorpusRow, dict]] = {}
    for number, record in enumerate(frame.to_dict("records"), start=2):  # 2 = first data line
        text = clean_text(record.get("text", ""))
        given = record.get("language", "").strip().lower()
        intents = parse_intents(record.get("intent", ""), taxonomy)
        if language_id.letter_count(text) < 2:
            report.count(source, "skipped_empty_text")
            continue
        if given not in allowed:
            report.count(source, "skipped_bad_language")
            continue
        if intents is None:
            report.count(source, "skipped_bad_intent")
            continue
        report.count(source, "rows_read")
        key = dedup_key(text)
        if key in kept:
            report.count(source, "duplicates_merged")
            merge_duplicate(kept[key][0], intents)
            continue
        detected = detect(text)
        note = language_note(given, detected)
        if note:
            report.count(source, "language_mismatch")
        cues = weak_label(text, taxonomy=taxonomy).cue_intents
        # a translation's id also depends on its source row and target language
        id_parts = [record["source_text_id"], given, key] if source == MT else [key]
        row = CorpusRow(
            text_id=make_text_id(source, *id_parts),
            text=text,
            language=detected,
            language_given=given,
            intents=intents,
            primary_intent=intents[0],
            cue_intents=cues,
            intent_source="given",
            source_type=source,
            source_ref=f"{path.name}:{number}",
            is_synthetic=source != "real_message",
            group_id="",
            split="train",
            needs_review=bool(note),
            notes=note,
        )
        kept[key] = (row, record)
    return kept


def assign_real_splits(rows: list[CorpusRow], seed: int, report: BuildReport) -> None:
    """Grouped, stratified (given language x given primary intent) train / val / test.

    The GIVEN labels decide the stratum, so a later review does not reshuffle
    the split. Each cell gets a string-seeded RNG ("42|si|fake_reward"), so
    adding messages to one cell never moves the messages of another cell.
    """
    config = corpus_rules()["real_messages"]
    ratios = config["ratios"]
    # (language, intent) -> group_id -> rows
    cells: dict[tuple[str, str], dict] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        cells[(row.language_given, row.primary_intent)][row.group_id].append(row)
    for (language, intent), groups in sorted(cells.items()):
        group_ids = sorted(groups)
        random.Random(f"{seed}|{language}|{intent}").shuffle(group_ids)
        n = len(group_ids)
        if n < config["min_groups_per_cell"]:
            n_test = n_val = 0
            status = "train_only"
        else:
            n_test = max(1, round(n * ratios["test"]))
            n_val = max(1, round(n * ratios["val"]))
            status = "small" if n < config["small_cell_groups"] else "ok"
        assigned = ["test"] * n_test + ["val"] * n_val + ["train"] * (n - n_test - n_val)
        for group_id, split in zip(group_ids, assigned, strict=True):
            for row in groups[group_id]:
                row.split = split
        report.real_split_cells.append(
            {
                "language": language,
                "intent": intent,
                "groups": n,
                "train": assigned.count("train"),
                "val": n_val,
                "test": n_test,
                "status": status,
            }
        )


def real_message_rows(path: Path, taxonomy: Taxonomy, seed: int, report: BuildReport):
    source = "real_message"
    frame = read_source(path, {"text", "language", "intent"}, report, source)
    if frame is None:
        return []
    rows = []
    for key, (row, record) in _given_rows(frame, path, source, taxonomy, report).items():
        row.group_id = "rg_" + make_text_id(source, key)[3:]  # hash of the normalized text
        details = [
            f"source={record['source']}" if record.get("source") else "",
            record.get("notes", "").strip(),
        ]
        row.notes = "; ".join(filter(None, [row.notes, *details]))
        rows.append(row)
    assign_real_splits(rows, seed, report)
    report.count(source, "rows", len(rows))
    return rows


# ---- c) synthetic templates, d) machine translations ----------------------------------------


def synthetic_rows(path: Path, taxonomy: Taxonomy, report: BuildReport) -> list[CorpusRow]:
    source = "synthetic_template"
    frame = read_source(path, {"text", "language", "intent", "template_group"}, report, source)
    if frame is None:
        return []
    rows = []
    for row, record in _given_rows(frame, path, source, taxonomy, report).values():
        row.group_id = record["template_group"] or f"tg_{row.text_id}"
        row.notes = "; ".join(filter(None, [row.notes, "synthetic template, train only"]))
        rows.append(row)
    report.count(source, "rows", len(rows))
    return rows


def mt_rows(mt_dir: Path, taxonomy: Taxonomy, report: BuildReport) -> list[tuple[CorpusRow, str]]:
    """(translation row, source_text_id) for every data/corpus/mt/*.csv except the input."""
    source = MT
    rows = []
    for path in sorted(mt_dir.glob("*.csv")) if mt_dir.exists() else []:
        if path.name == MT_INPUT_NAME:
            continue  # the English INPUT for the notebook, not a translation
        required = {"text", "language", "intent", "source_text_id"}
        frame = read_source(path, required, report, source)
        if frame is None:
            continue
        report.count(source, "files")
        for row, record in _given_rows(frame, path, source, taxonomy, report).values():
            row.notes = "; ".join(
                filter(
                    None,
                    [row.notes, f"machine translation of {record['source_text_id']}, train only"],
                )
            )
            rows.append((row, record["source_text_id"]))
    return rows


def filter_translations(
    translations: list[tuple[CorpusRow, str]], kept: list[CorpusRow], report: BuildReport
) -> list[CorpusRow]:
    """Keep a translation only if its source row exists and is in TRAIN (no leakage)."""
    by_id = {row.text_id: row for row in kept}
    result = []
    for row, source_text_id in translations:
        source_row = by_id.get(source_text_id)
        if source_row is None:
            report.count(MT, "dropped_source_missing")
        elif source_row.split != "train":
            report.count(MT, "dropped_source_in_val_test")
        else:
            row.group_id = source_row.group_id  # a translation stays with its source
            result.append(row)
    report.count(MT, "rows", len(result))
    return result


# ---- cross-source duplicates / leakage ------------------------------------------------------


def resolve_cross_split(rows: list[CorpusRow], report: BuildReport) -> list[CorpusRow]:
    """A near-identical text in several splits is kept only in the most held-out one."""
    by_key: dict[str, list[CorpusRow]] = defaultdict(list)
    for row in rows:
        by_key[dedup_key(row.text)].append(row)
    dropped: set[str] = set()
    for key, group in by_key.items():
        splits = {row.split for row in group}
        if len(splits) < 2:
            continue
        keep_split = min(splits, key=SPLIT_PRIORITY.get)
        gone = [row for row in group if row.split != keep_split]
        dropped.update(row.text_id for row in gone)
        for row in gone:
            report.count(row.source_type, f"dropped_duplicate_of_{keep_split}")
        report.leakage.append(
            {
                "key_sha": make_text_id("real_message", key)[3:],
                "kept_split": keep_split,
                "kept": [row.text_id for row in group if row.split == keep_split],
                "dropped": [
                    {"text_id": r.text_id, "split": r.split, "source_type": r.source_type}
                    for r in gone
                ],
            }
        )
    return [row for row in rows if row.text_id not in dropped]


# ---- the build ----------------------------------------------------------------------------


def text_dir_for(version: str) -> Path:
    from c2_analyzer.content.batch import output_dir  # Part 5A output folder

    return output_dir(version)


def build_corpus(
    version: str,
    paths: CorpusPaths | None = None,
    text_dir: Path | None = None,
    splits_root: Path | None = None,
    seed: int | None = None,
    manifests: Path | None = None,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Build, write and return (corpus frame with reviews applied, build info)."""
    paths = paths or CorpusPaths.from_config()
    text_dir = text_dir or text_dir_for(version)
    seed = seed if seed is not None else int(load_yaml_config("config")["project"]["random_seed"])
    taxonomy = load_taxonomy()
    report = BuildReport(version)

    rows = page_segment_rows(version, text_dir, splits_root, taxonomy, report, manifests)
    rows += real_message_rows(paths.real_texts, taxonomy, seed, report)
    rows += synthetic_rows(paths.synthetic_texts, taxonomy, report)
    rows = resolve_cross_split(rows, report)
    translations = filter_translations(mt_rows(paths.mt_dir, taxonomy, report), rows, report)
    rows = resolve_cross_split(rows + translations, report)  # MT is train: only MT can go

    ids = Counter(row.text_id for row in rows)
    clashes = [text_id for text_id, n in ids.items() if n > 1]
    if clashes:  # cannot happen with distinct keys; refuse rather than write an ambiguous corpus
        raise ValueError(f"duplicate text_id(s) {clashes[:5]} - report this as a bug")

    frame, orphaned = apply_reviews(rows_to_frame(rows), ReviewStore(paths.reviews_csv).frame())
    frame_to_rows(frame)  # validates the review overlay (e.g. a bad language value)
    written = write_corpus(frame, paths)

    info = {
        "schema_version": "corpus_v1",
        "dataset_version": version,
        "built_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "taxonomy_version": taxonomy.version,
        "taxonomy_sha256": taxonomy.file_hash,
        "corpus_rules_sha256": file_hash(rules_path()),
        "language_backend": language_id.latin_backend().name,
        "seed": seed,
        "rows": len(frame),
        "sources": {name: dict(counts) for name, counts in report.sources.items()},
        "real_split_cells": report.real_split_cells,
        "leakage_resolved": len(report.leakage),
        "leakage": report.leakage,
        "reviews_applied": int(len(ReviewStore(paths.reviews_csv).frame()) - len(orphaned)),
        "reviews_orphaned": orphaned,
        "warnings": report.warnings,
        "files": [str(path) for path in written],
    }
    write_json(info, paths.build_info)
    return frame, info


def export_mt_input(
    paths: CorpusPaths | None = None, source_types: list[str] | None = None
) -> tuple[Path, int]:
    """English TRAIN rows -> data/corpus/mt/mt_input_en.csv for the NLLB Colab notebook.

    Only train rows: translating a val / test text would put its meaning into
    train (the build drops such translations anyway).
    """
    paths = paths or CorpusPaths.from_config()
    frame = load_corpus(paths)
    mask = (
        (frame["excluded"] != "true")
        & (frame["language"] == "en")
        & (frame["split"] == "train")
        & (frame["source_type"] != "machine_translation")
    )
    if source_types:
        mask &= frame["source_type"].isin(source_types)
    rows = frame[mask].rename(columns={"text_id": "source_text_id", "intents": "intent"})
    path = paths.mt_dir / MT_INPUT_NAME
    atomic_write_csv(rows.sort_values("source_text_id"), path, MT_INPUT_COLUMNS)
    return path, len(rows)


def read_build_info(paths: CorpusPaths) -> dict[str, Any]:
    if not paths.build_info.exists():
        return {}
    return json.loads(paths.build_info.read_text(encoding="utf-8"))
