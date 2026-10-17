"""XLM-R out-of-fold predictions via Colab: export-bundle --cv and import-oof.

Part 9: Tri-modal fusion + ablation study (Batch A, task 2) - the text_xlmr arm's OOF.

Why Colab: the fusion needs, for every train+val page, XLM-R probabilities from a model
that never saw the page (see fusion/oof.py) = 5 fine-tunings, one per shared CV fold.
That needs a GPU (~25 min on a free T4), the rest of the fusion runs on the laptop.

export-bundle --cv (``data/tmp/xlmr_cv_bundle_<v>.zip``, a few hundred KB):
    data/cv_examples.jsonl   train+val page_text with the SHARED cv fold (no test page at all)
    data/cv_plan.json        seed (Part 6A's final seed) + each fold's INNER validation ids:
                             a cluster-pure, label-stratified ~20 % slice of the training
                             folds (StratifiedGroupKFold, seeded) used for early stopping -
                             never the held-out fold, never the test split
    data/label_mapping.json, data/examples_meta.json (+ cv_folds fingerprint)
    configs/xlmr.yaml        the Part 6A hyperparameters, unchanged
    c2_nlp/ run_train.py requirements-colab.txt README.txt   (same as the Part 6A bundle)
Colab: ``python run_train.py --cv`` -> ``oof_out/<v>/{oof_meta.json, oof/fold_<k>.jsonl}``
(predictions only - no weights to download).

import-oof refuses a zip that does not belong to the current split: dataset version,
split + CV-fold fingerprints, classes, all folds complete, every train+val page exactly
once with its own fold and label, probabilities valid; a smoke run is refused too. Test
probabilities come from the Part 6A FINAL model (re-run on the local CPU, as the API
serves it). Output: ``data/processed/fusion/<v>/oof_text_xlmr.{csv,json}``.
"""

from __future__ import annotations

import json
import shutil
import zipfile
from collections import Counter
from collections.abc import Callable
from pathlib import Path, PurePosixPath

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

from c2_analyzer.dataset.manifest import git_commit
from c2_analyzer.dataset.splits import load_cv_folds
from c2_analyzer.fusion.common import FusionConfig
from c2_analyzer.fusion.oof import (
    ArmOof,
    Reference,
    base_manifest,
    folds_fingerprint,
    load_reference,
    make_frame,
    write_oof,
)
from c2_analyzer.nlp.bundle import ImportRefused, _safe_members, stage_code, zip_folder
from c2_analyzer.nlp.common import XlmrConfig
from c2_analyzer.nlp.dataset import EXAMPLE_FIELDS, TextExamples, build_examples
from c2_analyzer.nlp.train import (
    CV_EXAMPLES_FILE,
    CV_PLAN_FILE,
    LABEL_MAPPING_FILE,
    META_FILE,
    OOF_META_FILE,
    write_json,
    write_jsonl,
)

INNER_VAL_SPLITS = 5  # inner validation = 1 of 5 cluster-pure slices (~20 %) of the training folds

README_CV = """C2 Part 9A - XLM-R out-of-fold predictions (CV / OOF mode), Colab bundle ({version})

Made by: python scripts/train_xlmr.py export-bundle --version {version} --cv
Split fingerprint: {fingerprint}
CV folds fingerprint: {folds}
train+val pages: {n} in {k} folds (test pages are NOT in this bundle)
Seed: {seed} (Part 6A's final seed); hyperparameters: configs/xlmr.yaml (Part 6A)

  pip install -r requirements-colab.txt
  python run_train.py --cv                  # 5 fold models -> oof_out/{version}/
  python run_train.py --cv --folds 3 4      # only these folds (a finished fold is skipped)
  python run_train.py --cv --smoke          # 1-step pipeline check (import-oof refuses it)

Each fold model trains on the other 4 folds minus an inner-validation slice (early stopping),
predicts its held-out fold, and is deleted. Zip oof_out/{version} and run on the laptop:
  python scripts/train_xlmr.py import-oof --zip <zip> --version {version}
"""


def inner_validation_plan(rows: list[dict], seed: int) -> dict:
    """{"seed", "folds": {k: {"inner_val": [ids]}}} - a cluster-pure slice per fold."""
    folds = sorted({int(row["fold"]) for row in rows})
    plan = {"seed": int(seed), "inner_val_rule": "", "folds": {}}
    for fold in folds:
        candidates = [row for row in rows if int(row["fold"]) != fold]
        # 5 slices on real data; fewer only for tiny toy datasets (sklearn needs as many
        # groups and as many pages of the largest class as slices)
        largest = max(Counter(row["label_id"] for row in candidates).values())
        groups = len({row["cluster_id"] for row in candidates})
        n_splits = max(2, min(INNER_VAL_SPLITS, largest, groups))
        splitter = StratifiedGroupKFold(
            n_splits=n_splits, shuffle=True, random_state=int(seed) + fold
        )
        _, inner = next(
            splitter.split(
                np.zeros(len(candidates)),
                [row["label_id"] for row in candidates],
                [row["cluster_id"] for row in candidates],
            )
        )
        plan["folds"][str(fold)] = {
            "inner_val": sorted(candidates[i]["sample_id"] for i in inner),
            "n_train": len(candidates) - len(inner),
            "inner_slices": n_splits,
        }
    plan["inner_val_rule"] = (
        f"StratifiedGroupKFold({INNER_VAL_SPLITS}, shuffle, seed+fold) over the training folds "
        "(groups = cluster_id, y = label): first slice = inner validation for early stopping"
    )
    return plan


def final_seed(config: XlmrConfig, version: str) -> int:
    """Part 6A's final seed (selection.json) - else the first configured seed."""
    path = config.models_dir(version) / "final" / "selection.json"
    if path.is_file():
        return int(json.loads(path.read_text(encoding="utf-8"))["final_seed"])
    return config.seeds[0]


def export_cv_bundle(
    version: str,
    config: XlmrConfig | None = None,
    data: TextExamples | None = None,
    out_zip: Path | None = None,
    splits_root: Path | None = None,
) -> tuple[Path, list[tuple[str, int]], dict]:
    """Write data/tmp/xlmr_cv_bundle_<version>.zip; returns (path, members, cv plan)."""
    config = config or XlmrConfig.load()
    data = data or build_examples(version, splits_root=splits_root)
    folds = load_cv_folds(version, splits_root)
    fold_of = folds.set_index("sample_id")["fold"]
    rows = []
    for row in data.rows("train", "val"):
        rows.append(
            {**{key: row[key] for key in EXAMPLE_FIELDS}, "fold": int(fold_of[row["sample_id"]])}
        )
    seed = final_seed(config, version)
    plan = inner_validation_plan(rows, seed)

    out_zip = Path(out_zip or config.bundle_dir / f"xlmr_cv_bundle_{version}.zip")
    staging = out_zip.with_suffix("")
    shutil.rmtree(staging, ignore_errors=True)
    folder = staging / "data"
    write_jsonl(rows, folder / CV_EXAMPLES_FILE)
    write_json(plan, folder / CV_PLAN_FILE)
    write_json(data.label_mapping, folder / LABEL_MAPPING_FILE)
    write_json(
        {
            **data.meta,
            "mode": "cv",
            "cv_folds_fingerprint": folds_fingerprint(folds),
            "model_name": config.model_name,
            "git_commit": git_commit(),
        },
        folder / META_FILE,
    )
    stage_code(staging, config)
    (staging / "README.txt").write_text(
        README_CV.format(
            version=version,
            fingerprint=data.meta["split_fingerprint"],
            folds=folds_fingerprint(folds),
            n=len(rows),
            k=len(plan["folds"]),
            seed=seed,
        ),
        encoding="utf-8",
    )
    return out_zip, zip_folder(staging, out_zip), plan


# ---- import ----------------------------------------------------------------------------------


def read_oof_zip(zip_path: Path) -> tuple[dict, list[dict]]:
    """(oof_meta.json, every prediction row) from a Colab zip (zip-slip / symlinks refused)."""
    with zipfile.ZipFile(zip_path) as archive:
        members = _safe_members(archive)
        names = [m.filename.replace("\\", "/") for m in members]
        metas = [n for n in names if PurePosixPath(n).name == OOF_META_FILE]
        if len(metas) != 1:
            raise ImportRefused(f"the zip must contain exactly one {OOF_META_FILE}")
        root = metas[0][: -len(OOF_META_FILE)]
        meta = json.loads(archive.read(metas[0]).decode("utf-8"))
        rows = []
        for name in sorted(names):
            path = PurePosixPath(name)
            if (
                name.startswith(root + "oof/")
                and path.name.startswith("fold_")
                and path.suffix == ".jsonl"
            ):
                text = archive.read(name).decode("utf-8")
                rows += [json.loads(line) for line in text.splitlines() if line.strip()]
    return meta, rows


def check_oof(meta: dict, rows: list[dict], ref: Reference, allow_smoke: bool = False) -> list[str]:
    """Problems of a Colab OOF run vs the current split (empty = OK)."""
    problems = []
    if meta.get("mode") != "cv_oof":
        problems.append("not a CV / OOF run (oof_meta.json mode)")
    if meta.get("dataset_version") != ref.version:
        problems.append(f"dataset version {meta.get('dataset_version')} != {ref.version}")
    if meta.get("split_fingerprint") != ref.split_fingerprint:
        problems.append(
            f"split fingerprint {str(meta.get('split_fingerprint'))[:12]} != current "
            f"{ref.split_fingerprint[:12]}"
        )
    if meta.get("cv_folds_fingerprint") != ref.folds_fingerprint:
        problems.append("CV folds fingerprint differs from data/splits cv_folds.csv")
    if meta.get("classes") != ref.labels:
        problems.append(f"classes {meta.get('classes')} != {ref.labels}")
    if meta.get("smoke") and not allow_smoke:
        problems.append("a --smoke run (1 training step) - its numbers mean nothing")
    if not meta.get("complete"):
        problems.append(f"folds done {meta.get('folds_done')} of {meta.get('folds_expected')}")
    if problems:
        return problems
    expected = ref.pool.set_index("sample_id")
    seen: dict[str, int] = {}
    for row in rows:
        seen[row["sample_id"]] = seen.get(row["sample_id"], 0) + 1
    extra = sorted(set(seen) - set(expected.index))
    missing = sorted(set(expected.index) - set(seen))
    doubled = sorted(i for i, n in seen.items() if n > 1)
    if extra or missing or doubled:
        problems.append(
            f"sample ids differ from train+val (extra {extra[:3]}, missing {missing[:3]}, "
            f"twice {doubled[:3]})"
        )
        return problems
    k = len(ref.labels)
    for row in rows:
        truth = expected.loc[row["sample_id"]]
        probs = np.asarray(row.get("probabilities", []), dtype=float)
        if int(row["fold"]) != int(truth["fold"]):
            problems.append(f"{row['sample_id']}: fold {row['fold']} != {truth['fold']}")
        elif int(row["label_id"]) != int(truth["y"]):
            problems.append(f"{row['sample_id']}: label {row['label_id']} != {truth['y']}")
        elif probs.shape != (k,) or not np.isfinite(probs).all() or abs(probs.sum() - 1) > 1e-3:
            problems.append(f"{row['sample_id']}: invalid probabilities")
        if len(problems) >= 5:
            break
    return problems


def final_model_test_probabilities(
    ref: Reference, config: XlmrConfig
) -> tuple[list, np.ndarray, dict]:
    """(test ids, probabilities, info) of the Part 6A final model on the local CPU."""
    from c2_analyzer.nlp.evaluate import WEIGHTS, check_model_dir, local_predictions

    data = build_examples(ref.version)
    model_root = config.models_dir(ref.version)
    final = model_root / "final"
    if not (final / WEIGHTS).is_file():
        raise ImportRefused(
            f"no Part 6A final model in {final} - the test probabilities come from it "
            "(train_xlmr.py import-model first)"
        )
    check_model_dir(model_root, data)  # same split + label mapping as now
    test = data.rows("test")
    proba = local_predictions(final, test, config)
    selection = json.loads((final / "selection.json").read_text(encoding="utf-8"))
    card_path = model_root / "model_card.json"
    card = json.loads(card_path.read_text(encoding="utf-8")) if card_path.is_file() else {}
    info = {
        "test_source": f"Part 6A final model (seed {selection['final_seed']}) on the local CPU",
        "final_seed": selection["final_seed"],
        "base_model": card.get("base_model"),
        "text_rules_hash": data.meta["text_rules_hash"],
    }
    return [row["sample_id"] for row in test], proba, info


def import_oof(
    zip_path: Path,
    version: str,
    config: XlmrConfig | None = None,
    fusion: FusionConfig | None = None,
    ref: Reference | None = None,
    test_probabilities: Callable | None = None,
    out_dir: Path | None = None,
    allow_smoke: bool = False,
) -> dict:
    """Validate the Colab zip, add the final model's test probabilities, write the OOF table.

    ``test_probabilities(ref)`` -> (ids, proba, info) is injectable for tests."""
    config = config or XlmrConfig.load()
    fusion = fusion or FusionConfig.load()
    ref = ref or load_reference(version)
    meta, rows = read_oof_zip(Path(zip_path))
    problems = check_oof(meta, rows, ref, allow_smoke)
    if problems:
        raise ImportRefused("refused: " + "; ".join(problems))
    test_ids, test_proba, info = (
        test_probabilities(ref)
        if test_probabilities
        else final_model_test_probabilities(ref, config)
    )
    frame = make_frame(
        ref,
        [row["sample_id"] for row in rows],
        np.array([row["probabilities"] for row in rows], dtype=float),
        test_ids,
        test_proba,
    )
    manifest = {
        **base_manifest("text_xlmr", ref, fusion),
        "part": "Part 6A",
        "model": "xlmr",
        "model_display": "XLM-R (fine-tuned)",
        "params": meta.get("hyperparameters"),
        "seed": meta.get("seed"),
        "base_model": meta.get("model_name"),
        "oof_source": "Colab CV run: 5 fold models, early stopping on a cluster-pure inner "
        "validation slice of the training folds",
        "fold_metrics": meta.get("fold_metrics"),
        "gpu_name": meta.get("gpu_name"),
        "colab_library_versions": meta.get("library_versions"),
        "colab_finished_at": meta.get("finished_at"),
        **info,
    }
    oof = ArmOof(arm="text_xlmr", labels=ref.labels, frame=frame, manifest=manifest)
    csv_path, _ = write_oof(oof, out_dir or fusion.oof_dir(version))
    return {"path": str(csv_path), "n_oof": len(rows), "n_test": len(test_ids), **info}
