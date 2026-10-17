"""Part 9A tests: OOF predictions, fusion strategies, FPR threshold, bootstrap, ablation.

Synthetic and fast: toy splits, toy arm probabilities, no trained arm, no torch.

Why these tests (viva): the fusion numbers are only honest if (1) every train+val
probability comes from a model that never saw that page or its cluster, (2) the test pages
are predicted by the models trained on train+val and never used for a choice, and (3) the
statistics (threshold, bootstrap) do what their docstrings promise.
"""

from __future__ import annotations

import json
import logging
import zipfile

import joblib
import numpy as np
import pandas as pd
import pytest

from c2_analyzer.classifiers.dom_baseline import train as part4_train
from c2_analyzer.classifiers.dom_baseline.common import BaselineConfig
from c2_analyzer.classifiers.dom_baseline.data import DomDataset
from c2_analyzer.classifiers.dom_baseline.sources import DOM_SOURCE
from c2_analyzer.fusion import strategies
from c2_analyzer.fusion.ablation import run_ablation
from c2_analyzer.fusion.bootstrap import (
    bootstrap_scores,
    paired_difference,
    resample_indices,
    summarize,
)
from c2_analyzer.fusion.complementarity import complementarity
from c2_analyzer.fusion.model import restore, save_bundle, to_bundle
from c2_analyzer.fusion.oof import OofError, load_oof, load_reference, tabular_oof, write_oof
from c2_analyzer.fusion.operating_point import choose_threshold, threshold_predict
from c2_analyzer.fusion.report import render_markdown
from c2_analyzer.fusion.strategies import (
    FusionInputs,
    HybridFusion,
    MeanFusion,
    StackingFusion,
    WeightedFusion,
    simplex_grid,
)
from c2_analyzer.nlp import text_baseline
from c2_analyzer.nlp.bundle import ImportRefused
from c2_analyzer.nlp.oof_bundle import import_oof, inner_validation_plan
from c2_analyzer.nlp.train import fold_roles
from tests.fusion_helpers import (
    LABELS,
    fast_config,
    signal_proba,
    toy_data,
    toy_reference,
    toy_rows,
    write_split,
)

# ---- OOF: never from a model that saw the page ---------------------------------------------


class Memorizer:
    """Answers with certainty for rows it was trained on, uniform otherwise."""

    def fit(self, X, y, sample_weight=None):
        self.seen = {tuple(row): int(label) for row, label in zip(X, y, strict=True)}
        self.classes_ = np.unique(y)
        return self

    def predict_proba(self, X):
        proba = np.full((len(X), len(self.classes_)), 1 / len(self.classes_))
        for i, row in enumerate(X):
            if tuple(row) in self.seen:
                proba[i] = 0.0
                proba[i, list(self.classes_).index(self.seen[tuple(row)])] = 1.0
        return proba


def toy_dataset(seed: int = 0) -> DomDataset:
    """A tiny Part 4 dataset over the toy split (2 informative + 1 noise feature)."""
    ref = toy_reference()
    frame = ref.frame.copy()
    rng = np.random.default_rng(seed)
    frame["language"] = "en"
    frame["f0"] = frame["y"] + rng.normal(scale=0.3, size=len(frame))
    frame["f1"] = rng.normal(size=len(frame))
    frame["f2"] = frame["y"] * 2 + rng.normal(scale=0.5, size=len(frame))
    return DomDataset(
        version="v9.1",
        frame=frame,
        all_features=["f0", "f1", "f2"],
        features=["f0", "f1", "f2"],
        labels=LABELS,
        split_info={"split_fingerprint": ref.split_fingerprint},
        feature_set_version="toy",
        dictionary_hash="toy",
    )


def toy_baseline() -> BaselineConfig:
    return BaselineConfig(
        models={
            "logreg": {
                "fixed": {"max_iter": 2000, "class_weight": "balanced"},
                "grid": {"C": [1.0]},
            }
        },
        n_jobs=1,
    )


def test_part4_cv_predictions_are_out_of_fold(monkeypatch):
    """Part 4's cross_validate (reused by the dom / behavior OOF) never predicts a page with
    a model trained on it: a memorizing model would be 100 % sure about such a page."""
    monkeypatch.setattr(part4_train, "build_model", lambda *args, **kwargs: Memorizer())
    _, _, oof = part4_train.cross_validate("logreg", {}, toy_dataset(), toy_baseline())
    assert np.allclose(oof, 1 / len(LABELS))


def test_tfidf_cv_probabilities_never_see_the_held_fold(monkeypatch):
    class Recorder:
        def fit(self, texts, y):
            self.texts, self.classes_ = set(texts), np.unique(y)
            return self

        def predict_proba(self, texts):
            assert not self.texts & set(texts), "a held-out page was in the training texts"
            return np.full((len(texts), len(self.classes_)), 1 / len(self.classes_))

    monkeypatch.setattr(text_baseline, "make_pipeline", lambda settings, C, seed=42: Recorder())
    ref = toy_reference()
    pool = ref.pool
    proba = text_baseline.cv_probabilities(
        [f"text of {i}" for i in pool["sample_id"]],
        pool["y"].to_numpy(),
        pool["fold"].to_numpy(),
        {},
        1.0,
        len(LABELS),
    )
    assert proba.shape == (len(pool), len(LABELS))


def test_reference_refuses_a_cluster_in_two_folds(tmp_path):
    rows = toy_rows()
    rows[0]["fold"], rows[1]["fold"] = 0, 1  # the two pages of cluster cl_000000 split up
    write_split(tmp_path, "v9.1", rows)
    with pytest.raises(OofError, match="clusters in several CV folds"):
        load_reference("v9.1", tmp_path)
    write_split(tmp_path, "v9.1", toy_rows())
    ref = load_reference("v9.1", tmp_path)
    assert (ref.test["fold"] == -1).all() and (ref.pool["fold"] >= 0).all()


def test_fusion_cv_never_fits_on_the_held_fold():
    class Recorder:
        name = "recorder"

        def fit(self, inputs, y, folds):
            self.ids = set(inputs.features[:, 0].astype(int).tolist())
            return self

        def predict_proba(self, inputs):
            held = set(inputs.features[:, 0].astype(int).tolist())
            assert not self.ids & held
            return np.full((inputs.n, len(LABELS)), 1 / len(LABELS))

    n = 50
    y = np.arange(n) % len(LABELS)
    inputs = FusionInputs(
        arms=["dom"],
        probs={"dom": signal_proba(y, len(LABELS), 0.5, 0)},
        labels=LABELS,
        features=np.arange(n, dtype=float)[:, None],
        feature_names=["dom.row"],
    )
    strategies.cross_validate(Recorder, inputs, y, np.arange(n) % 5)


def test_xlmr_fold_roles_and_inner_validation_are_out_of_fold():
    rows = [
        {
            "sample_id": r["sample_id"],
            "fold": r["fold"],
            "cluster_id": r["cluster_id"],
            "label_id": i % 3,
        }
        for i, r in enumerate(toy_rows(n_pool=100, n_test=0))
    ]
    plan = inner_validation_plan(rows, seed=43)
    cluster = {r["sample_id"]: r["cluster_id"] for r in rows}
    for fold in range(5):
        train, val, held = fold_roles(rows, plan, fold)
        ids = [{r["sample_id"] for r in part} for part in (train, val, held)]
        assert not ids[0] & ids[1] and not ids[2] & (ids[0] | ids[1])
        assert ids[0] | ids[1] | ids[2] == {r["sample_id"] for r in rows}
        assert all(int(r["fold"]) == fold for r in held) and val
        # inner validation is cluster-pure: no cluster in both train and inner validation
        assert not {cluster[i] for i in ids[0]} & {cluster[i] for i in ids[1]}


def test_test_probabilities_come_from_the_train_val_model():
    """tabular_oof: OOF = 5 fold models; test = the saved bundle (trained on train+val)."""
    dataset, baseline = toy_dataset(), toy_baseline()
    bundle = part4_train.train_model("logreg", dataset, baseline, show_progress=False)
    ref = toy_reference()
    oof = tabular_oof(
        "dom",
        DOM_SOURCE,
        ref,
        fast_config(),
        log=lambda *a: None,
        baseline=baseline,
        dataset=dataset,
        bundles={"logreg": bundle},
    )
    assert bundle["n_train"] == len(ref.pool)  # the final model saw all of train+val
    test_ids = ref.test["sample_id"].tolist()
    expected = bundle["estimator"].predict_proba(dataset.X("test"))
    assert np.allclose(oof.proba(test_ids), expected, atol=1e-6)
    assert oof.manifest["reproduces_part_oof"] is True  # same folds -> Part 4's stored OOF
    pool = oof.frame[oof.frame["split"] != "test"]
    assert (pool["fold"] >= 0).all() and (
        oof.frame.loc[oof.frame["split"] == "test", "fold"] == -1
    ).all()


def test_oof_files_round_trip_and_refuse_another_split(tmp_path):
    data = toy_data()
    write_oof(data.oofs["dom"], tmp_path)
    loaded = load_oof("dom", data.ref, tmp_path)
    pd.testing.assert_frame_equal(loaded.frame, data.oofs["dom"].frame, check_dtype=False)
    other = toy_reference(toy_rows(n_pool=55))
    with pytest.raises(OofError, match="stale"):
        load_oof("dom", other, tmp_path)
    assert load_oof("text_xlmr", data.ref, tmp_path) is None  # missing = None, not an error


# ---- strategies ------------------------------------------------------------------------------


def test_simplex_grid_and_weights_sum_to_one():
    grid = simplex_grid(3, 0.1)
    assert all(abs(sum(point) - 1) < 1e-9 and min(point) >= 0 for point in grid)
    assert (1 / 3, 1 / 3, 1 / 3) in grid and len(grid) == 66 + 1
    data = toy_data()
    ids = data.ids("pool")
    model = WeightedFusion(0.1).fit(data.inputs(data.available, ids), data.y("pool"), data.folds())
    weights = model.weights()
    assert abs(sum(weights.values()) - 1) < 1e-9 and min(weights.values()) >= 0
    proba = model.predict_proba(data.inputs(data.available, data.ids("test")))
    assert np.allclose(proba.sum(axis=1), 1)


@pytest.mark.parametrize(
    "make",
    [
        MeanFusion,
        lambda: StackingFusion(1.0),
        lambda: HybridFusion(fast_config().strategy("hybrid")["params"]),
    ],
)
def test_strategies_train_on_toy_data_and_round_trip(make, tmp_path):
    data = toy_data()
    pool = data.inputs(data.available, data.ids("pool"))
    test = data.inputs(data.available, data.ids("test"))
    model = make().fit(pool, data.y("pool"), data.folds())
    proba = model.predict_proba(test)
    assert proba.shape == (len(data.ids("test")), len(LABELS))
    assert np.allclose(proba.sum(axis=1), 1, atol=1e-5)
    assert (proba.argmax(axis=1) == data.y("test")).mean() > 1 / len(LABELS)  # learns something
    if model.name == "hybrid":
        assert "dom.f5" in {d["feature"] for d in model.dropped}  # constant -> dropped
        assert "dom.f5" not in model.columns
    bundle = to_bundle(model, LABELS, ["text_tfidf"])
    save_bundle(bundle, tmp_path)
    restored = restore(joblib.load(tmp_path / "fusion.joblib"))
    assert np.allclose(restored.predict_proba(test), proba)


# ---- operating point, bootstrap, complementarity --------------------------------------------


def test_threshold_search_reaches_the_target_fpr():
    rng = np.random.default_rng(0)
    y = rng.integers(0, 3, size=400)
    proba = signal_proba(y, 3, 0.3, 1)
    result = choose_threshold(y, proba, benign=0, target=0.02)
    assert result["oof_benign_fpr"] <= 0.02
    # it is the LARGEST such threshold: the next benign score up breaks the target
    scores = np.sort(proba[y == 0, 0])
    above = scores[scores > result["threshold"]][0]
    predicted = threshold_predict(proba, 0, above + 1e-12)
    assert ((predicted[y == 0] != 0).mean()) > 0.02
    assert choose_threshold(y, proba, 0, 0.0)["oof_benign_fpr"] == 0.0


def test_bootstrap_ci_on_known_cases():
    y = np.array([0, 1, 2] * 10)
    indices = resample_indices(len(y), 200, 42)
    perfect = bootstrap_scores(y, y, indices)
    assert summarize(1.0, perfect, 0.95)["ci_low"] == 1.0
    wrong = (y + 1) % 3
    better = paired_difference(y, y, wrong, indices, 0.95)
    assert (
        better["point"] == 1.0 and not better["includes_zero"] and better["share_a_better"] == 1.0
    )
    same = paired_difference(y, y, y, indices, 0.95)
    assert same["point"] == 0.0 and same["includes_zero"]
    assert np.array_equal(indices, resample_indices(len(y), 200, 42))  # seeded = reproducible


def test_complementarity_buckets():
    ids = ["p0", "p1", "p2", "p3", "p4", "p5"]
    y = np.array([0, 0, 0, 0, 1, 1])
    preds = {
        "dom": np.array([0, 1, 1, 1, 0, 1]),
        "behavior": np.array([1, 0, 1, 1, 0, 1]),
        "text": np.array([1, 1, 0, 1, 1, 1]),
    }
    result = complementarity(ids, y, preds, fused=np.array([0, 0, 1, 1, 1, 1]), examples=5)
    buckets = result["buckets"]
    assert buckets["only_dom_right"] == {"count": 1, "examples": ["p0"], "fusion_right": 1}
    assert buckets["only_behavior_right"]["count"] == 1
    assert buckets["only_text_right"]["examples"] == ["p2", "p4"]
    assert buckets["all_wrong"]["examples"] == ["p3"] and buckets["all_right"]["examples"] == ["p5"]
    assert result["oracle_accuracy"] == pytest.approx(5 / 6)


# ---- the ablation with missing arms ---------------------------------------------------------


def test_ablation_runs_without_xlmr_and_says_so():
    data = toy_data()
    results = run_ablation(
        "v9.1", data.config, data, figures=False, save=False, log=lambda *a: None
    )
    assert results["arms_missing"] == ["text_xlmr"]
    assert results["final"]["group"] == "tri"
    assert results["final"]["strategy"] in ("mean", "weighted", "stacking", "hybrid")
    keys = {e["key"] for e in results["entries"]}
    assert {
        "dom",
        "behavior",
        "text_tfidf",
        "tri:mean",
        "tri:hybrid",
        "dom+behavior:weighted",
    } <= keys
    final = results["final"]
    assert final["cv"]["mean"]["macro_f1"] == max(
        e["cv"]["mean"]["macro_f1"] for e in results["entries"] if e["group"] == "tri"
    )
    assert (
        final["bootstrap"]["ci_low"] <= final["test"]["macro_f1"] <= final["bootstrap"]["ci_high"]
    )
    assert "not included: text_xlmr" in render_markdown(results)


def test_ablation_with_two_arms_fuses_the_pair():
    data = toy_data(arms=("dom", "text_tfidf"))
    results = run_ablation(
        "v9.1", data.config, data, figures=False, save=False, log=lambda *a: None
    )
    assert set(results["arms_missing"]) == {"behavior", "text_xlmr"}
    assert results["final"]["group"] == "pair"


# ---- import-oof (XLM-R from Colab) ----------------------------------------------------------


def colab_zip(path, ref, **meta_changes):
    pool = ref.pool
    meta = {
        "mode": "cv_oof",
        "dataset_version": ref.version,
        "split_fingerprint": ref.split_fingerprint,
        "cv_folds_fingerprint": ref.folds_fingerprint,
        "classes": ref.labels,
        "complete": True,
        "smoke": False,
        "seed": 43,
        "folds_done": [0, 1, 2, 3, 4],
        "folds_expected": [0, 1, 2, 3, 4],
        **meta_changes,
    }
    proba = signal_proba(pool["y"].to_numpy(), len(ref.labels), 0.4, 3)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("v0.3/oof_meta.json", json.dumps(meta))
        for fold in range(5):
            mask = (pool["fold"] == fold).to_numpy()
            lines = [
                json.dumps(
                    {"sample_id": s, "fold": fold, "label_id": int(y), "probabilities": p.tolist()}
                )
                for s, y, p in zip(
                    pool["sample_id"][mask], pool["y"][mask], proba[mask], strict=True
                )
            ]
            archive.writestr(f"v0.3/oof/fold_{fold}.jsonl", "\n".join(lines) + "\n")
    return path


def test_import_oof_accepts_a_matching_run_and_refuses_mismatches(tmp_path):
    write_split(tmp_path / "splits", "v9.1", toy_rows())
    ref = load_reference("v9.1", tmp_path / "splits")
    test_ids = ref.test["sample_id"].tolist()

    def test_probabilities(_ref):
        return test_ids, signal_proba(ref.test["y"].to_numpy(), 3, 0.4, 9), {"test_source": "toy"}

    def run(zip_path, **kwargs):
        return import_oof(
            zip_path,
            "v9.1",
            fusion=fast_config(),
            ref=ref,
            test_probabilities=test_probabilities,
            out_dir=tmp_path / "out",
            **kwargs,
        )

    result = run(colab_zip(tmp_path / "ok.zip", ref))
    assert result["n_oof"] == len(ref.pool) and result["n_test"] == len(test_ids)
    assert load_oof("text_xlmr", ref, tmp_path / "out").manifest["seed"] == 43

    for name, changes, message in [
        ("split", {"split_fingerprint": "0" * 64}, "split fingerprint"),
        ("folds", {"cv_folds_fingerprint": "f" * 64}, "CV folds fingerprint"),
        ("version", {"dataset_version": "v9.9"}, "dataset version"),
        ("classes", {"classes": ["benign", "phishing"]}, "classes"),
        ("smoke", {"smoke": True}, "smoke"),
        ("incomplete", {"complete": False}, "folds done"),
    ]:
        with pytest.raises(ImportRefused, match=message):
            run(colab_zip(tmp_path / f"{name}.zip", ref, **changes))

    other = toy_reference(toy_rows(n_pool=55))  # another split: page ids differ
    other_zip = colab_zip(
        tmp_path / "other.zip",
        other,
        split_fingerprint=ref.split_fingerprint,
        cv_folds_fingerprint=ref.folds_fingerprint,
        dataset_version="v9.1",
    )
    with pytest.raises(ImportRefused, match="sample ids differ"):
        run(other_zip)

    unsafe = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(unsafe, "w") as archive:
        archive.writestr("../oof_meta.json", "{}")
    with pytest.raises(ImportRefused, match="unsafe path"):
        run(unsafe)


# ---- Part 9A section 0: tokenizer warning filter + Colab vs CPU rule ------------------------


def test_only_the_false_mistral_regex_warning_is_dropped():
    from c2_analyzer.nlp.tokenizer import _WARNING_LOGGER, silence_false_regex_warning

    silence_false_regex_warning()
    silence_false_regex_warning()  # idempotent
    logger = logging.getLogger(_WARNING_LOGGER)
    records: list[str] = []

    class Collect(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    handler = Collect(level=logging.WARNING)
    logger.addHandler(handler)
    try:
        logger.warning("loading with an incorrect regex pattern ... set fix_mistral_regex=True")
        logger.warning("some other tokenizer warning")
    finally:
        logger.removeHandler(handler)
    assert records == ["some other tokenizer warning"]


def test_colab_vs_cpu_rule_labels_identical_and_small_difference():
    from c2_analyzer.nlp.evaluate import consistency_check

    local = np.array([[0.7, 0.3], [0.2, 0.8]])
    assert consistency_check(local + [[0.0016, -0.0016], [0, 0]], local, 0.01)["ok"]
    big = consistency_check(local + [[0.02, -0.02], [0, 0]], local, 0.01)
    assert not big["ok"] and big["labels_identical"] and big["max_abs_diff"] == 0.02
    flipped = consistency_check(
        np.array([[0.49, 0.51], [0.2, 0.8]]), np.array([[0.505, 0.495], [0.2, 0.8]]), 0.01
    )
    assert not flipped["ok"] and not flipped["labels_identical"]
