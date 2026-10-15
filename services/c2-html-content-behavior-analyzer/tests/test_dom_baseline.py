"""Part 4 tests: shared split, DOM dataset prep, the three baselines, metrics, outputs.

Everything runs on a small SYNTHETIC dataset in a temporary folder (fast, and
the real data/, models/ and reports/ folders are never touched):
- a frozen manifest with 3 trainable classes, one too-small class
  (fake_ecommerce, 5 pages) and none of crypto_scam, a few Sinhala/Tamil pages
  and near-duplicate clusters of 2-3 pages;
- a Part 3 style dom_features.csv with the real dom_v1 columns, where a few
  features carry the label signal.

Why: these pin the rules every later part relies on - no cluster in two
splits, the test split never in a CV fold, feature cleaning decided on train
only, labels in labels.yaml order - plus the metric formulas (checked on a
known confusion matrix) and the saved outputs (model card, predict CLI).
"""

from __future__ import annotations

import importlib.util
import io
import json
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient

from c2_analyzer.api.dependencies import get_dev_dataset
from c2_analyzer.api.dev_data import DevDataset
from c2_analyzer.api.main import create_app
from c2_analyzer.classifiers.dom_baseline.common import (
    BaselineConfig,
    load_bundles,
    parse_models,
)
from c2_analyzer.classifiers.dom_baseline.data import (
    DatasetError,
    check_feature_table,
    clean_features,
    encode_labels,
    label_mapping,
    label_order,
    prepare_dataset,
)
from c2_analyzer.classifiers.dom_baseline.evaluate import benign_fpr, compute_metrics
from c2_analyzer.classifiers.dom_baseline.predict import predict_features
from c2_analyzer.classifiers.dom_baseline.report import StaleModelError, check_bundles, run_report
from c2_analyzer.classifiers.dom_baseline.train import build_model, fit_model, train_all
from c2_analyzer.dataset.manifest import MANIFEST_COLUMNS, fingerprint
from c2_analyzer.dataset.splits import (
    EXCLUDED,
    SplitConfig,
    SplitError,
    assign_splits,
    create_split,
    load_cv_folds,
    load_split,
)
from c2_analyzer.dom.dictionary import dictionary_hash, load_dictionary
from c2_analyzer.dom.exporter import ID_COLUMNS, export_dictionary
from c2_analyzer.utils.hashing import sha256_file

VERSION = "v0.1"
LABELS = ["benign", "phishing", "malware_delivery"]
COUNTS = {"benign": 70, "phishing": 55, "malware_delivery": 40, "fake_ecommerce": 5}
SIGNAL = ["node_count", "null_link_ratio", "internal_link_count", "inline_script_count"]
FIXTURE_PAGE = Path(__file__).parent / "fixtures" / "sample_pages" / "phishing_external_form.html"
SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "train_dom_baseline.py"


# ---- synthetic dataset ----------------------------------------------------------------------


def _manifest_rows() -> list[dict]:
    """Rows of a manifest: clusters of 2-3 pages per label, a few si/ta pages."""
    rows, cluster = [], 0
    for label, count in COUNTS.items():
        for i in range(count):
            # pages 0-11 of each label form clusters of 3 (near-duplicates), the rest are alone
            if i < 12 and i % 3 != 0:
                pass
            else:
                cluster += 1
            language = (
                "si" if i in (5, 20) else "ta" if (label == "benign" and i in (7, 30, 50)) else "en"
            )
            rows.append(
                {
                    "sample_id": f"c2_{label}_{i + 1:06d}",
                    "label": label,
                    "language": language,
                    "cluster_id": f"cl_{cluster:06d}",
                }
            )
    return rows


def write_dataset(root: Path) -> dict[str, Path]:
    """Raw files + manifest + DOM features (+ dictionary) under ``root``."""
    raw, manifests, features = root / "raw", root / "manifests", root / "features"
    rows = _manifest_rows()
    for row in rows:
        path = raw / row["label"] / f"{row['sample_id']}.html"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"<html><body><p>{row['sample_id']}</p></body></html>", encoding="utf-8")
        row["file_path"] = f"{row['label']}/{row['sample_id']}.html"
        row["sha256"] = sha256_file(path)
    manifest = pd.DataFrame(rows, columns=MANIFEST_COLUMNS)
    manifests.mkdir(parents=True)
    manifest.to_csv(manifests / f"dataset_{VERSION}.csv", index=False)
    info = {"version": VERSION, "total": len(manifest), "fingerprint": fingerprint(manifest)}
    (manifests / f"dataset_{VERSION}.json").write_text(json.dumps(info), encoding="utf-8")

    rng = np.random.default_rng(7)
    specs = load_dictionary().features
    table = manifest[ID_COLUMNS].copy()
    label_index = {label: i for i, label in enumerate(COUNTS)}
    y = manifest["label"].map(label_index).to_numpy()
    for spec in specs:
        if spec.type == "binary":
            values = rng.integers(0, 2, len(table)).astype(float)
        else:
            values = rng.poisson(3, len(table)).astype(float)
        if spec.name in SIGNAL:
            values = values + 6.0 * y + rng.normal(0, 1.0, len(table)).clip(-2, 2)
        table[spec.name] = values
    table["base_url_known"] = 1.0  # constant -> must be dropped
    table["element_count"] = table["node_count"] * 0.8  # |r| = 1 with node_count -> dropped
    features.mkdir(parents=True)
    table.to_csv(features / "dom_features.csv", index=False)
    export_dictionary(features / "feature_dictionary.json")
    return {"raw": raw, "manifests": manifests, "features": features, "splits": root / "splits"}


def small_config(root: Path) -> BaselineConfig:
    """Tiny grids so all three models train in a few seconds."""
    return replace(
        BaselineConfig.load(),
        models={
            "logreg": {
                "display_name": "Logistic Regression",
                "fixed": {"max_iter": 2000, "class_weight": "balanced"},
                "grid": {"C": [0.1, 1.0]},
            },
            "random_forest": {
                "display_name": "Random Forest",
                "n_jobs": 1,
                "fixed": {"n_estimators": 30, "class_weight": "balanced_subsample"},
                "grid": {"max_depth": [None, 4]},
            },
            "xgboost": {
                "display_name": "XGBoost",
                "fixed": {
                    "n_estimators": 30,
                    "tree_method": "hist",
                    "objective": "multi:softprob",
                    "eval_metric": "mlogloss",
                },
                "grid": {"max_depth": [3]},
            },
        },
        n_jobs=1,
        permutation_repeats=2,
        models_dir=root / "models",
        reports_dir=root / "reports",
    )


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    """Synthetic data -> split -> train (all 3) -> report, done once for the module."""
    root = tmp_path_factory.mktemp("dom_baseline")
    paths = write_dataset(root)
    info = create_split(VERSION, paths["manifests"], paths["raw"], paths["splits"])
    config = small_config(root)
    dataset = prepare_dataset(
        VERSION, 0.98, paths["features"], paths["splits"], manifests=paths["manifests"]
    )
    bundles = train_all(dataset, config, show_progress=False)
    results = run_report(dataset, bundles, config)
    return {
        "root": root,
        "paths": paths,
        "info": info,
        "config": config,
        "dataset": dataset,
        "bundles": bundles,
        "results": results,
    }


@pytest.fixture
def fresh(tmp_path):
    return write_dataset(tmp_path)


# ---- 1. split -------------------------------------------------------------------------------


def test_split_ratios_and_stratification(trained):
    info = trained["info"]
    split, _ = load_split(VERSION, trained["paths"]["splits"])
    included = split[split["split"] != EXCLUDED]
    for name, target in {"train": 0.70, "val": 0.15, "test": 0.15}.items():
        assert abs(info["actual_ratios"][name] - target) < 0.04, info["actual_ratios"]
    overall = included["label"].value_counts(normalize=True)
    for name in ("train", "val", "test"):
        share = included[included["split"] == name]["label"].value_counts(normalize=True)
        for label in LABELS:
            assert abs(share[label] - overall[label]) < 0.08, (name, label)
    assert info["max_ratio_difference"] < 0.04


def test_no_cluster_in_two_splits(trained):
    split, info = load_split(VERSION, trained["paths"]["splits"])
    assert split.groupby("cluster_id")["split"].nunique().max() == 1
    assert info["clusters_in_two_splits"] == 0
    assert split["cluster_id"].duplicated().any()  # the fixture really has clusters


def test_small_classes_are_excluded_and_listed(trained):
    split, info = load_split(VERSION, trained["paths"]["splits"])
    assert info["excluded_classes"] == {"fake_ecommerce": 5, "crypto_scam": 0}
    assert info["included_classes"] == LABELS and info["pilot"] is True
    assert set(split.loc[split["label"] == "fake_ecommerce", "split"]) == {EXCLUDED}
    assert info["total_excluded"] == 5


def test_sinhala_tamil_are_spread_and_reported(trained):
    placement = trained["info"]["language_placement"]
    assert set(placement) == {"si", "ta"}
    assert all(n >= 1 for n in placement["si"].values()), placement
    assert sum(1 for n in placement["ta"].values() if n) >= 2, placement


def test_split_refuses_overwrite_unless_forced(fresh):
    create_split(VERSION, fresh["manifests"], fresh["raw"], fresh["splits"])
    with pytest.raises(FileExistsError):
        create_split(VERSION, fresh["manifests"], fresh["raw"], fresh["splits"])
    create_split(VERSION, fresh["manifests"], fresh["raw"], fresh["splits"], force=True)


def test_split_refuses_a_manifest_that_no_longer_verifies(fresh):
    victim = next(fresh["raw"].glob("phishing/*.html"))
    victim.write_text("changed", encoding="utf-8")
    with pytest.raises(SplitError, match="no longer verifies"):
        create_split(VERSION, fresh["manifests"], fresh["raw"], fresh["splits"])


def test_split_is_deterministic_with_seed():
    manifest = pd.DataFrame(_manifest_rows())
    first = assign_splits(manifest, SplitConfig(seed=42))
    again = assign_splits(manifest, SplitConfig(seed=42))
    other = assign_splits(manifest, SplitConfig(seed=7))
    assert first["split"].tolist() == again["split"].tolist()
    assert first["split"].tolist() != other["split"].tolist()


def test_cv_folds_never_contain_test_pages(trained):
    split, _ = load_split(VERSION, trained["paths"]["splits"])
    folds = load_cv_folds(VERSION, trained["paths"]["splits"])
    test_ids = set(split.loc[split["split"] == "test", "sample_id"])
    pool_ids = set(split.loc[split["split"].isin(["train", "val"]), "sample_id"])
    assert set(folds["sample_id"]) == pool_ids and not (set(folds["sample_id"]) & test_ids)
    assert sorted(folds["fold"].unique()) == [0, 1, 2, 3, 4]
    assert folds.groupby("cluster_id")["fold"].nunique().max() == 1  # grouped too


# ---- 2. dataset prep ------------------------------------------------------------------------


def test_feature_dropping_uses_train_only(fresh):
    create_split(VERSION, fresh["manifests"], fresh["raw"], fresh["splits"])
    split, _ = load_split(VERSION, fresh["splits"])
    csv_path = fresh["features"] / "dom_features.csv"
    table = pd.read_csv(csv_path, dtype={c: str for c in ID_COLUMNS}, keep_default_na=False)
    train_ids = set(split.loc[split["split"] == "train", "sample_id"])
    # constant on TRAIN, varying on val/test: must be dropped (decided on train only)
    table["iframe_count"] = [
        0.0 if s in train_ids else float(i % 4) for i, s in enumerate(table["sample_id"])
    ]
    # varying on train, constant elsewhere: must be KEPT
    table["external_script_count"] = [
        float(i % 5) if s in train_ids else 1.0 for i, s in enumerate(table["sample_id"])
    ]
    table.to_csv(csv_path, index=False)
    dataset = prepare_dataset(VERSION, 0.98, fresh["features"], fresh["splits"])
    dropped = {item["feature"]: item["reason"] for item in dataset.dropped}
    assert dropped["iframe_count"] == "constant"
    assert dropped["base_url_known"] == "constant"
    assert dropped["element_count"] == "correlated"  # node_count is earlier in the dictionary
    assert "node_count" in dataset.features and "external_script_count" in dataset.features
    assert dataset.features == [f for f in dataset.all_features if f not in dropped]


def test_clean_features_keeps_the_earlier_of_a_correlated_pair():
    train = pd.DataFrame(
        {"a": [1.0, 2, 3, 4], "b": [2.0, 4, 6, 8], "c": [5.0, 5, 5, 5], "d": [1.0, 0, 1, 0]}
    )
    kept, dropped = clean_features(train, ["a", "b", "c", "d"], 0.98)
    assert kept == ["a", "d"]
    assert [(d["feature"], d["reason"]) for d in dropped] == [
        ("c", "constant"),
        ("b", "correlated"),
    ]


def test_label_mapping_order_and_restriction():
    assert label_order(["malware_delivery", "benign", "phishing"]) == LABELS
    assert encode_labels(["phishing", "benign", "malware_delivery"], LABELS).tolist() == [1, 0, 2]
    with pytest.raises(DatasetError):
        encode_labels(["fake_ecommerce"], LABELS)
    with pytest.raises(DatasetError):
        label_order(["not_a_label"])
    mapping = label_mapping(LABELS, {"fake_ecommerce": 5})
    assert mapping["index"] == {"benign": 0, "phishing": 1, "malware_delivery": 2}
    assert mapping["labels_yaml_id"] == {"benign": 0, "phishing": 1, "malware_delivery": 4}


def test_feature_columns_must_match_the_dictionary(trained):
    dictionary = json.loads(
        (trained["paths"]["features"] / "feature_dictionary.json").read_text("utf-8")
    )
    columns = ID_COLUMNS + [f["name"] for f in dictionary["features"]]
    assert len(check_feature_table(columns, dictionary)) == len(dictionary["features"])
    with pytest.raises(DatasetError):
        check_feature_table(columns[:-1], dictionary)  # a missing column
    with pytest.raises(DatasetError):
        check_feature_table(ID_COLUMNS + columns[len(ID_COLUMNS) :][::-1], dictionary)  # reordered
    with pytest.raises(DatasetError, match="another dictionary"):
        check_feature_table(columns, {**dictionary, "dictionary_hash": "0" * 64})


# ---- 3. models ------------------------------------------------------------------------------


def test_all_three_models_train_and_predict(trained):
    dataset, bundles = trained["dataset"], trained["bundles"]
    assert list(bundles) == ["logreg", "random_forest", "xgboost"]
    X = dataset.X("test")
    for bundle in bundles.values():
        proba = bundle["estimator"].predict_proba(X)
        assert proba.shape == (len(X), 3)
        assert np.allclose(proba.sum(axis=1), 1.0)
        assert bundle["features"] == dataset.features and bundle["labels"] == LABELS
        assert bundle["cv"]["mean"]["macro_f1"] > 0.6  # the synthetic signal is learnable
        assert len(bundle["cv"]["folds"]) == 5


def test_best_grid_point_is_chosen_on_cv(trained):
    for bundle in trained["bundles"].values():
        scores = [point["mean_macro_f1"] for point in bundle["grid"]]
        assert bundle["grid"][bundle["best_grid_index"]]["mean_macro_f1"] == max(scores)
        assert bundle["params"] == bundle["grid"][bundle["best_grid_index"]]["params"]


def test_models_are_reproducible(trained):
    dataset, config = trained["dataset"], trained["config"]
    X, y = dataset.X("train"), dataset.y("train")
    params = {"n_estimators": 10, "max_depth": 3}
    first = fit_model("xgboost", build_model("xgboost", params, 42, 1, 3), X, y)
    again = fit_model("xgboost", build_model("xgboost", params, 42, 1, 3), X, y)
    assert np.array_equal(first.predict_proba(X), again.predict_proba(X))
    assert config.jobs("random_forest") == 1


def test_parse_models_aliases():
    assert parse_models("rf,xgb") == ["random_forest", "xgboost"]
    assert parse_models(None) == ["logreg", "random_forest", "xgboost"]
    with pytest.raises(ValueError):
        parse_models("svm")


# ---- 4. metrics -----------------------------------------------------------------------------


def _from_confusion(matrix):
    y_true, y_pred = [], []
    for i, row in enumerate(matrix):
        for j, n in enumerate(row):
            y_true += [i] * n
            y_pred += [j] * n
    return np.array(y_true), np.array(y_pred)


def test_metrics_on_a_known_confusion_matrix():
    matrix = [[8, 1, 1], [2, 6, 2], [0, 1, 9]]  # rows = true benign/phishing/malware
    y_true, y_pred = _from_confusion(matrix)
    m = compute_metrics(y_true, y_pred, None, LABELS)
    assert m["confusion_matrix"] == matrix
    assert m["accuracy"] == pytest.approx(23 / 30)
    precision = [8 / 10, 6 / 8, 9 / 12]
    recall = [8 / 10, 6 / 10, 9 / 10]
    f1 = [2 * p * r / (p + r) for p, r in zip(precision, recall, strict=True)]
    for i, label in enumerate(LABELS):
        assert m["per_class"][label]["precision"] == pytest.approx(precision[i])
        assert m["per_class"][label]["recall"] == pytest.approx(recall[i])
        assert m["per_class"][label]["support"] == 10
    assert m["macro_f1"] == pytest.approx(sum(f1) / 3)
    assert m["weighted_f1"] == pytest.approx(sum(f1) / 3)  # equal supports
    assert m["balanced_accuracy"] == pytest.approx(sum(recall) / 3)
    assert m["benign_fpr"] == pytest.approx(2 / 10)  # 1 phishing + 1 malware out of 10 benign
    assert m["roc_auc_ovr_macro"] is None  # no probabilities given


def test_benign_fpr_formula():
    assert benign_fpr(np.array([0, 0, 0, 0, 1]), np.array([0, 2, 0, 1, 1]), 0) == 0.5
    assert benign_fpr(np.array([0, 0]), np.array([0, 0]), 0) == 0.0
    assert benign_fpr(np.array([1, 2]), np.array([0, 0]), 0) is None  # no benign page


def test_roc_auc_with_probabilities():
    y = np.array([0, 1, 2, 0, 1, 2])
    perfect = np.eye(3)[y]
    m = compute_metrics(y, y, perfect, LABELS)
    assert m["roc_auc_ovr_macro"] == pytest.approx(1.0) and m["macro_f1"] == 1.0


# ---- 5-6. outputs ---------------------------------------------------------------------------


def test_report_files_and_results(trained):
    folder = trained["config"].reports_dir / VERSION
    results = trained["results"]
    for name in ("results.json", "results.md", "misclassified.csv", "dropped_features.csv"):
        assert (folder / name).is_file(), name
    for name in (
        "confusion_logreg.png",
        "confusion_random_forest.png",
        "confusion_xgboost.png",
        "shap_global_xgboost.png",
        "shap_beeswarm_phishing.png",
        "importance_random_forest_permutation.png",
        "importance_logreg_coefficients.png",
    ):
        assert (folder / "figures" / name).is_file(), name
    assert results["best_model"] in results["models"]
    best_cv = results["models"][results["best_model"]]["cv"]["mean"]["macro_f1"]
    assert best_cv == max(m["cv"]["mean"]["macro_f1"] for m in results["models"].values())
    wrong = pd.read_csv(folder / "misclassified.csv")
    assert len(wrong) == results["misclassified_total"]
    assert set(wrong["true"]) <= set(LABELS) and (wrong["true"] != wrong["predicted"]).all()
    assert len(results["importance"]["xgboost"]["shap_global"]) == 15
    assert "indicative" in results["importance"]["caveat"]
    markdown = (folder / "results.md").read_text(encoding="utf-8")
    assert "Baseline 1" in markdown and "PILOT" in markdown and "Benign FPR" in markdown


def test_model_card_contents(trained):
    card_path = trained["config"].models_dir / VERSION / "model_card.json"
    card = json.loads(card_path.read_text(encoding="utf-8"))
    dataset = trained["dataset"]
    assert card["dataset_version"] == VERSION and card["pilot"] is True
    assert card["split_fingerprint"] == trained["info"]["split_fingerprint"]
    assert card["feature_set_version"] == load_dictionary().feature_set_version
    assert card["final_features"] == dataset.features
    assert card["label_mapping"]["classes"] == LABELS
    assert card["excluded_classes"] == {"fake_ecommerce": 5, "crypto_scam": 0}
    assert set(card["models"]) == {"logreg", "random_forest", "xgboost"}
    for model in card["models"].values():
        assert model["best_params"] and model["test"]["macro_f1"] is not None
        assert model["cv_mean"]["macro_f1"] is not None
    assert {"scikit-learn", "xgboost", "numpy"} <= set(card["library_versions"])
    assert "git_commit" in card and card["created_at"]
    assert (trained["config"].models_dir / VERSION / "label_mapping.json").is_file()


def test_stale_models_are_refused(trained):
    dataset = trained["dataset"]
    other = replace(dataset, features=dataset.features[:-1])
    with pytest.raises(StaleModelError, match="feature list"):
        check_bundles(trained["bundles"], other)


# ---- 7. predict -----------------------------------------------------------------------------


def test_predict_features_explains_with_direction(trained):
    dataset = trained["dataset"]
    row = dataset.rows("test").iloc[0]
    features = {name: float(row[name]) for name in dataset.all_features}
    prediction = predict_features(
        features,
        trained["bundles"],
        version=VERSION,
        dictionary_hash=dictionary_hash(),
        excluded_classes={"fake_ecommerce": 5},
        explain="xgboost",
        top=5,
    )
    assert prediction.pilot and prediction.classes == LABELS
    for answer in prediction.models:
        assert sum(answer.probabilities.values()) == pytest.approx(1.0)
    assert prediction.explained_model == "xgboost"
    assert 1 <= len(prediction.contributions) <= 5
    for item in prediction.contributions:
        assert item.direction in ("towards", "away") and item.feature in dataset.features
        assert ("towards" in item.text) == (item.contribution > 0)


def _load_script():
    spec = importlib.util.spec_from_file_location("train_dom_baseline_cli", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_predict_cli_returns_probabilities_summing_to_one(trained):
    cli = _load_script()
    config = trained["config"]
    out = io.StringIO()
    with redirect_stdout(out):
        code = cli.main(
            [
                "--models-dir",
                str(config.models_dir),
                "--reports-dir",
                str(config.reports_dir),
                "predict",
                "--file",
                str(FIXTURE_PAGE),
                "--url",
                "https://example.com/login",
                "--version",
                VERSION,
                "--json",
            ]
        )
    assert code == 0
    result = json.loads(out.getvalue())
    assert [m["model"] for m in result["models"]] == ["logreg", "random_forest", "xgboost"]
    for model in result["models"]:
        assert sum(model["probabilities"].values()) == pytest.approx(1.0)
    assert result["pilot"] is True and result["explained_model"] == "xgboost"
    assert result["features_source"] == "computed"


# ---- 8. dev endpoint + inspector filter -----------------------------------------------------


def test_dev_prediction_endpoint_and_misclassified_filter(trained):
    paths, config = trained["paths"], trained["config"]
    dataset = DevDataset(
        paths["manifests"],
        trained["root"] / "parsed",
        paths["raw"],
        metadata_csv=trained["root"] / "metadata.csv",
        baseline_models=config.models_dir,
        baseline_reports=config.reports_dir,
        splits=paths["splits"],
    )
    app = create_app("development")
    app.dependency_overrides[get_dev_dataset] = lambda: dataset
    client = TestClient(app)

    split, _ = load_split(VERSION, paths["splits"])
    sample = split.loc[split["split"] == "test", "sample_id"].iloc[0]
    response = client.get(f"/api/v1/dev/samples/{sample}/dom-prediction")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["split"] == "test" and body["pilot"] is True
    assert body["best_model"] == trained["results"]["best_model"]
    assert sum(body["probabilities"].values()) == pytest.approx(1.0)
    assert len(body["contributions"]) <= 5 and body["misclassified_test"] in (True, False)

    wrong = pd.read_csv(config.reports_dir / VERSION / "misclassified.csv")
    expected = set(wrong.loc[wrong["model"] == trained["results"]["best_model"], "sample_id"])
    listed = client.get("/api/v1/dev/samples", params={"misclassified": "true"}).json()
    assert {row["sample_id"] for row in listed} == expected
    assert all(row["misclassified"] for row in listed)

    assert client.get("/api/v1/dev/samples/c2_benign_999999/dom-prediction").status_code == 404
    dataset.baseline_models = trained["root"] / "no-models"
    missing = client.get(f"/api/v1/dev/samples/{sample}/dom-prediction")
    assert missing.status_code == 404 and "train_dom_baseline.py" in missing.json()["detail"]


def test_load_bundles_reads_what_train_saved(trained):
    bundles = load_bundles(trained["config"], VERSION)
    assert list(bundles) == ["logreg", "random_forest", "xgboost"]
    assert bundles["xgboost"]["params"] == trained["bundles"]["xgboost"]["params"]
