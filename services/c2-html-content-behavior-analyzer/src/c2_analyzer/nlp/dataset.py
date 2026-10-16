"""Page-level text examples from Part 5A page_text + the SHARED split (tasks 2-4).

Part 6: XLM-R content classification (6A, page level).

One example per page: ``{sample_id, text, label, label_id, language, language_detected,
split, cluster_id}``.

- **text** = the stored Part 5A ``page_text`` (``data/processed/text/<v>/<id>.json``),
  the same string the API builds for a new page, so training and serving read the
  same input. A JSON made from another file (sha256 differs from the manifest) or
  with another schema is refused - re-run ``build_text_corpus.py extract``.
- **label_id** (task 3) = Part 4's label encoding (``dom_baseline.data.label_order``
  / ``label_mapping``): labels.yaml order restricted to the split's included classes.
  Every arm of the ablation therefore numbers the classes the same way.
- **split** (task 4) = ``data/splits/<v>/split.csv`` as it is. Never re-split: the
  NLP-only arm must be scored on the SAME 68 test pages as DOM-only and
  Behavior-only, otherwise the comparison means nothing. The split is checked against
  the frozen manifest (``check_current``) and its fingerprint travels with the
  examples, the bundle and every trained model.
- **language** = Part 5A's detected page language in 5 buckets (en, si, ta, mixed,
  other): si_latn -> si, ta_latn -> ta, unknown -> other. The metadata language only
  has en / si / ta / unknown and misses the ~21 % non-English "other" pages.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import pandas as pd

from c2_analyzer.classifiers.dom_baseline.data import (
    DatasetError,
    encode_labels,
    label_mapping,
    label_order,
)
from c2_analyzer.content.batch import output_dir as text_output_dir
from c2_analyzer.dataset.manifest import git_commit, manifest_paths, manifests_dir
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dataset.splits import EXCLUDED, check_current, load_split, split_fingerprint
from c2_analyzer.nlp.train import LABEL_MAPPING_FILE, META_FILE, SPLITS, write_json, write_jsonl
from c2_analyzer.schemas.content import TEXT_SCHEMA_VERSION

LANGUAGE_BUCKETS = {"en": "en", "si": "si", "si_latn": "si", "ta": "ta", "ta_latn": "ta"}
LANGUAGE_BUCKETS["mixed"] = "mixed"
EXAMPLE_FIELDS = (
    "sample_id",
    "text",
    "label",
    "label_id",
    "language",
    "language_detected",
    "split",
    "cluster_id",
)


def language_bucket(detected: str | None) -> str:
    """Part 5A page language -> en / si / ta / mixed / other."""
    return LANGUAGE_BUCKETS.get(detected or "", "other")


@dataclass
class TextExamples:
    """Every page of a version as a text example, plus where it came from."""

    version: str
    labels: list[str]
    examples: list[dict]
    split_info: dict
    meta: dict = field(default_factory=dict)

    def rows(self, *splits: str) -> list[dict]:
        return [example for example in self.examples if example["split"] in splits]

    def frame(self, *splits: str) -> pd.DataFrame:
        return pd.DataFrame(self.rows(*splits) if splits else self.examples)

    @property
    def label_mapping(self) -> dict:
        return label_mapping(self.labels, self.split_info.get("excluded_classes", {}))


def build_examples(
    version: str,
    text_dir: Path | None = None,
    splits_root: Path | None = None,
    manifests: Path | None = None,
) -> TextExamples:
    """Join split.csv with the stored Part 5A page_text. Nothing is written."""
    manifests = manifests or manifests_dir(MetadataStore())
    split, info = load_split(version, splits_root)
    check_current(info, manifests, version)
    fingerprint = split_fingerprint(split)
    if info.get("split_fingerprint") and info["split_fingerprint"] != fingerprint:
        raise DatasetError(f"split.csv of {version} no longer matches split.json - re-run split")
    manifest_csv, manifest_json = manifest_paths(manifests, version)
    sha = pd.read_csv(manifest_csv, dtype=str, keep_default_na=False).set_index("sample_id")[
        "sha256"
    ]
    text_dir = Path(text_dir) if text_dir else text_output_dir(version)

    included = split[split["split"] != EXCLUDED].reset_index(drop=True)
    labels = label_order(info.get("included_classes") or sorted(included["label"].unique()))
    label_ids = encode_labels(included["label"], labels)
    examples, missing, stale, rules = [], [], [], set()
    for row, label_id in zip(included.itertuples(index=False), label_ids, strict=True):
        path = text_dir / f"{row.sample_id}.json"
        if not path.is_file():
            missing.append(row.sample_id)
            continue
        page = json.loads(path.read_text(encoding="utf-8"))
        meta = page.get("meta", {})
        if (
            meta.get("source_sha256") != sha.get(row.sample_id)
            or meta.get("schema_version") != TEXT_SCHEMA_VERSION
        ):
            stale.append(row.sample_id)
            continue
        rules.add(meta.get("rules_hash", ""))
        detected = (page.get("language") or {}).get("language")
        examples.append(
            {
                "sample_id": row.sample_id,
                "text": page.get("page_text") or "",
                "label": row.label,
                "label_id": int(label_id),
                "language": language_bucket(detected),
                "language_detected": detected or "unknown",
                "split": row.split,
                "cluster_id": row.cluster_id,
            }
        )
    hint = f"run: python scripts/build_text_corpus.py extract --version {version}"
    if missing:
        raise DatasetError(
            f"{len(missing)} page(s) have no Part 5A text (e.g. {missing[:3]}) - {hint}"
        )
    if stale:
        raise DatasetError(f"{len(stale)} Part 5A text(s) are stale (e.g. {stale[:3]}) - {hint}")
    if len(rules) > 1:
        raise DatasetError(f"Part 5A texts of {version} were made with different rules - {hint}")

    manifest_info = json.loads(manifest_json.read_text(encoding="utf-8"))
    counts = pd.DataFrame(examples).groupby("split").size().to_dict() if examples else {}
    meta = {
        "dataset_version": version,
        "manifest_fingerprint": manifest_info.get("fingerprint"),
        "split_fingerprint": fingerprint,
        "text_schema_version": TEXT_SCHEMA_VERSION,
        "text_rules_hash": next(iter(rules), None),
        "classes": labels,
        "counts": {split_name: int(counts.get(split_name, 0)) for split_name in SPLITS},
    }
    return TextExamples(version, labels, examples, info, meta)


def export_examples(data: TextExamples, out_dir: Path, model_name: str | None = None) -> Path:
    """train / val / test .jsonl + label_mapping.json + examples_meta.json in ``out_dir``."""
    out_dir = Path(out_dir)
    for split_name in SPLITS:
        rows = [{key: row[key] for key in EXAMPLE_FIELDS} for row in data.rows(split_name)]
        write_jsonl(rows, out_dir / f"{split_name}.jsonl")
    write_json(data.label_mapping, out_dir / LABEL_MAPPING_FILE)
    write_json(
        {
            **data.meta,
            "model_name": model_name,
            "git_commit": git_commit(),
            "exported_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        },
        out_dir / META_FILE,
    )
    return out_dir


def to_hf_datasets(data: TextExamples):
    """The examples as a Hugging Face ``DatasetDict`` (train / val / test)."""
    from datasets import Dataset, DatasetDict

    return DatasetDict(
        {
            split_name: Dataset.from_list(
                [{key: row[key] for key in EXAMPLE_FIELDS} for row in data.rows(split_name)]
            )
            for split_name in SPLITS
        }
    )
