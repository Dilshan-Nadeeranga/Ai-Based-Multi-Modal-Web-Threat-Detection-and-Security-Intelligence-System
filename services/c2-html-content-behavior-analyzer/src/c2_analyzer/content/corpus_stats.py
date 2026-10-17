"""Corpus statistics + integrity checks -> reports/content/corpus_v1_stats.{json,md}.

Part 5: Multilingual scam content analyzer (Batch B, Tasks 11-14).

Why: the thesis has to show WHAT the intent corpus contains and that it is
clean: counts by language x intent x source x split, how much is verified, how
many duplicates were removed, how far the real Sinhala / Tamil text is from
the collection target, and three integrity checks that must pass:

1. synthetic share of val and test = 0 % (augmentation is train-only);
2. no near-identical text (``corpus.dedup_key``) in two splits;
3. no group (page cluster / template / message / translation + its source)
   in two splits.

The report holds counts and ids only - never corpus text - so it can be
committed while the corpus files themselves stay git-ignored.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

from c2_analyzer.content.corpus import (
    SPLITS,
    CorpusPaths,
    ReviewStore,
    active_rows,
    apply_reviews,
    corpus_rules,
    dedup_key,
    read_corpus_file,
)
from c2_analyzer.content.corpus_builder import read_build_info
from c2_analyzer.content.taxonomy import load_taxonomy
from c2_analyzer.utils.io import atomic_write_text, write_json

SOURCE_TYPES = ("page_segment", "real_message", "synthetic_template", "machine_translation")
REAL_SOURCES = ("page_segment", "real_message")
LANGUAGE_ORDER = ("en", "si", "ta", "si_latn", "ta_latn", "mixed", "other", "unknown")


def _languages(frame: pd.DataFrame) -> list[str]:
    present = set(frame["language"])
    return [name for name in LANGUAGE_ORDER if name in present]


def crosstab(frame: pd.DataFrame, rows: str, columns: str, row_order, column_order) -> dict:
    """{row: {column: count}} with every row / column present (zeros included)."""
    table = {row: dict.fromkeys(column_order, 0) for row in row_order}
    for (row, column), count in frame.groupby([rows, columns]).size().items():
        if row in table and column in table[row]:
            table[row][column] = int(count)
    return table


def percent(part: int, whole: int) -> float:
    return round(100 * part / whole, 2) if whole else 0.0


def integrity(frame: pd.DataFrame) -> dict[str, Any]:
    """The three checks of the module docstring (computed on ALL rows, excluded ones too)."""
    held_out = frame[frame["split"] != "train"]
    synthetic_held_out = held_out[held_out["is_synthetic"] == "true"]
    keys = frame.assign(key=[dedup_key(text) for text in frame["text"]])
    key_splits = keys.groupby("key")["split"].nunique()
    group_splits = frame.groupby("group_id")["split"].nunique()
    result = {
        "synthetic_rows_in_val_test": len(synthetic_held_out),
        "texts_in_several_splits": int((key_splits > 1).sum()),
        "groups_in_several_splits": int((group_splits > 1).sum()),
        "examples": {
            "synthetic_in_val_test": synthetic_held_out["text_id"].head(10).tolist(),
            "groups_in_several_splits": group_splits[group_splits > 1].index[:10].tolist(),
        },
    }
    result["passed"] = not any(
        result[key]
        for key in (
            "synthetic_rows_in_val_test",
            "texts_in_several_splits",
            "groups_in_several_splits",
        )
    )
    return result


def real_text_gap(frame: pd.DataFrame, intents: list[str]) -> dict[str, Any]:
    """Real (non-synthetic) si / ta rows per intent in val + test vs the collection target."""
    targets = corpus_rules()["targets"]["val_test_per_intent"]
    real = frame[(frame["is_synthetic"] == "false") & (frame["split"] != "train")]
    result: dict[str, Any] = {}
    for language, target in targets.items():
        subset = real[real["language"] == language]
        per_intent = {}
        for intent in intents:
            rows = subset[subset["primary_intent"] == intent]
            by_source = {s: int((rows["source_type"] == s).sum()) for s in REAL_SOURCES}
            per_intent[intent] = {
                "count": len(rows),
                "by_source": by_source,
                "target": target,
                "gap": max(0, target - len(rows)),
            }
        scam_intents = [name for name in intents if name != "benign"]
        result[language] = {
            "target_per_intent": target,
            "per_intent": per_intent,
            "intents_meeting_target": sum(per_intent[i]["gap"] == 0 for i in scam_intents),
            "scam_intents": len(scam_intents),
            "total_gap": sum(per_intent[i]["gap"] for i in scam_intents),
        }
    return result


def compute_stats(paths: CorpusPaths) -> dict[str, Any]:
    raw = read_corpus_file(paths)
    frame, orphaned = apply_reviews(raw, ReviewStore(paths.reviews_csv).frame())
    build = read_build_info(paths)
    taxonomy = load_taxonomy()
    intents = list(taxonomy.priority)
    active = active_rows(frame)
    languages = _languages(active) if not active.empty else []

    by_source = {}
    for source in SOURCE_TYPES:
        subset = active[active["source_type"] == source]
        by_source[source] = {
            "rows": len(subset),
            "language_x_intent": crosstab(subset, "language", "primary_intent", languages, intents),
            "split": {split: int((subset["split"] == split).sum()) for split in SPLITS},
        }
    synthetic_share = {}
    for split in SPLITS:
        subset = active[active["split"] == split]
        synthetic = int((subset["is_synthetic"] == "true").sum())
        synthetic_share[split] = {
            "rows": len(subset),
            "synthetic": synthetic,
            "share_percent": percent(synthetic, len(subset)),
        }
    verified = active["verified"] == "true"
    sources = build.get("sources", {})
    duplicates = {
        source: {
            key: value
            for key, value in counts.items()
            if key.startswith(("duplicates_", "dropped_"))
        }
        for source, counts in sources.items()
    }
    return {
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "schema_version": "corpus_v1",
        "dataset_version": build.get("dataset_version"),
        "built_at": build.get("built_at"),
        "taxonomy_version": taxonomy.version,
        "language_backend": build.get("language_backend"),
        "rows": len(frame),
        "active_rows": len(active),
        "excluded_rows": len(frame) - len(active),
        "exclusion_reasons": frame.loc[frame["excluded"] == "true", "exclusion_reason"]
        .value_counts()
        .to_dict(),
        "languages": languages,
        "intents": intents,
        "language_x_intent": crosstab(active, "language", "primary_intent", languages, intents),
        "language_x_split": crosstab(active, "language", "split", languages, SPLITS),
        "source_x_split": crosstab(active, "source_type", "split", SOURCE_TYPES, SPLITS),
        "intent_x_split": crosstab(active, "primary_intent", "split", intents, SPLITS),
        "by_source": by_source,
        "multi_intent_rows": int(active["intents"].str.contains(";").sum()),
        "verification": {
            "verified_rows": int(verified.sum()),
            "verified_percent": percent(int(verified.sum()), len(active)),
            "per_source": {
                s: percent(
                    int(verified[active["source_type"] == s].sum()),
                    int((active["source_type"] == s).sum()),
                )
                for s in SOURCE_TYPES
            },
            "per_language": {
                lang: percent(
                    int(verified[active["language"] == lang].sum()),
                    int((active["language"] == lang).sum()),
                )
                for lang in languages
            },
            "needs_review": int((active["needs_review"] == "true").sum()),
            "reviews_orphaned": len(orphaned),
        },
        "synthetic_share_per_split": synthetic_share,
        "duplicates_removed": duplicates,
        "build_counts": sources,
        "real_split_cells": build.get("real_split_cells", []),
        "real_text_gap": real_text_gap(active, intents),
        "integrity": integrity(frame),
        "warnings": build.get("warnings", []),
    }


# ---- markdown --------------------------------------------------------------------------------


def md_table(table: dict, row_title: str, total: bool = True) -> list[str]:
    if not table:
        return ["(no rows)", ""]
    columns = list(next(iter(table.values())))
    head = [row_title, *columns] + (["total"] if total else [])
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for name, row in table.items():
        cells = [str(row[c]) for c in columns] + ([str(sum(row.values()))] if total else [])
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    if total:
        sums = [sum(row[c] for row in table.values()) for c in columns]
        lines.append("| **total** | " + " | ".join(map(str, [*sums, sum(sums)])) + " |")
    return lines + [""]


def to_markdown(stats: dict[str, Any]) -> str:
    check = stats["integrity"]
    lines = [
        "# Scam-text corpus statistics (corpus_v1)",
        "",
        f"Dataset version: {stats['dataset_version']} | taxonomy: {stats['taxonomy_version']} | "
        f"built: {stats['built_at']} | language backend: {stats['language_backend']}",
        "",
        f"Rows: {stats['rows']} (active {stats['active_rows']}, excluded by review "
        f"{stats['excluded_rows']}). Counts below are ACTIVE rows; intent = primary_intent.",
        "",
        "**Research integrity:** synthetic templates and machine translations are train-only "
        "augmentation; validation / test contain only real text.",
        "",
        "## Integrity checks: " + ("PASSED" if check["passed"] else "**FAILED**"),
        "",
        f"- synthetic / MT rows in val or test: {check['synthetic_rows_in_val_test']} (must be 0)",
        f"- near-identical texts in more than one split: {check['texts_in_several_splits']} "
        "(must be 0)",
        f"- groups in more than one split: {check['groups_in_several_splits']} (must be 0)",
        "",
        "## Synthetic share per split",
        "",
        "| split | rows | synthetic | share |",
        "|---|---|---|---|",
    ]
    for split, row in stats["synthetic_share_per_split"].items():
        lines.append(f"| {split} | {row['rows']} | {row['synthetic']} | {row['share_percent']} % |")
    lines += ["", "## Language x intent (all sources)", ""]
    lines += md_table(stats["language_x_intent"], "language")
    lines += ["## Source x split", ""] + md_table(stats["source_x_split"], "source")
    lines += ["## Language x split", ""] + md_table(stats["language_x_split"], "language")
    lines += ["## Intent x split", ""] + md_table(stats["intent_x_split"], "intent")
    for source, block in stats["by_source"].items():
        if block["rows"]:
            lines += [f"## Language x intent: {source} ({block['rows']} rows)", ""]
            lines += md_table(block["language_x_intent"], "language")

    lines += ["## Real Sinhala / Tamil text in val + test vs target", ""]
    for language, block in stats["real_text_gap"].items():
        lines += [
            f"**{language}** (target {block['target_per_intent']} per intent): "
            f"{block['intents_meeting_target']} of {block['scam_intents']} scam intents met, "
            f"total gap {block['total_gap']} rows.",
            "",
            "| intent | page segments | real messages | total | target | gap |",
            "|---|---|---|---|---|---|",
        ]
        for intent, row in block["per_intent"].items():
            source = row["by_source"]
            lines.append(
                f"| {intent} | {source['page_segment']} | {source['real_message']} | "
                f"{row['count']} | {row['target']} | {row['gap']} |"
            )
        lines.append("")

    verification = stats["verification"]
    lines += [
        "## Verification",
        "",
        f"Verified: {verification['verified_rows']} rows ({verification['verified_percent']} %); "
        f"needs review: {verification['needs_review']}; review decisions whose text is no longer "
        f"in the corpus: {verification['reviews_orphaned']}.",
        "",
        "| source | verified % |",
        "|---|---|",
        *[f"| {s} | {p} % |" for s, p in verification["per_source"].items()],
        "",
        "| language | verified % |",
        "|---|---|",
        *[f"| {s} | {p} % |" for s, p in verification["per_language"].items()],
        "",
        "## Duplicates removed / rows dropped",
        "",
    ]
    for source, counts in stats["duplicates_removed"].items():
        if counts:
            lines.append(f"- {source}: " + ", ".join(f"{k} {v}" for k, v in counts.items()))
    lines += ["", "## Real-message split cells (language x intent, grouped)", ""]
    cells = stats["real_split_cells"]
    if cells:
        lines += ["| language | intent | groups | train | val | test | status |"]
        lines += ["|---|---|---|---|---|---|---|"]
        for cell in cells:
            lines.append(
                f"| {cell['language']} | {cell['intent']} | {cell['groups']} | {cell['train']} | "
                f"{cell['val']} | {cell['test']} | {cell['status']} |"
            )
    else:
        lines.append("No real messages yet (data/corpus/real_texts.csv missing or empty).")
    lines += ["", "## Build counts", ""]
    for source, counts in stats["build_counts"].items():
        lines.append(f"- {source}: " + ", ".join(f"{k} {v}" for k, v in counts.items()))
    if stats["warnings"]:
        lines += ["", "## Warnings", "", *[f"- {w}" for w in stats["warnings"]]]
    return "\n".join(lines) + "\n"


def write_stats(stats: dict[str, Any], paths: CorpusPaths) -> tuple[Path, Path]:
    json_path = paths.reports_dir / "corpus_v1_stats.json"
    md_path = paths.reports_dir / "corpus_v1_stats.md"
    write_json(stats, json_path)
    atomic_write_text(to_markdown(stats), md_path)
    return json_path, md_path


def load_stats(path: Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
