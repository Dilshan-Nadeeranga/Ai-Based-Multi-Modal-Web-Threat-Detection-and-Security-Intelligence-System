"""Part 6A tests: page-level text models (XLM-R + TF-IDF baseline).

Offline and fast: a synthetic 5-class project in tmp_path (manifest, shared split,
Part 5A text JSONs) and a tiny random-init XLM-R built in code (2 layers, Unigram
tokenizer trained on the fixture texts) - no internet, no model download. Tests that
need torch / transformers are skipped (not failed) when those are not installed.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient

from c2_analyzer.api.dependencies import get_dev_dataset, get_text_models
from c2_analyzer.api.main import create_app
from c2_analyzer.classifiers.dom_baseline.data import DatasetError, label_mapping, label_order
from c2_analyzer.config import get_labels
from c2_analyzer.dataset.splits import split_fingerprint
from c2_analyzer.nlp.bundle import (
    PORTABLE_MODULES,
    ImportRefused,
    export_bundle,
    import_model,
)
from c2_analyzer.nlp.common import XlmrConfig
from c2_analyzer.nlp.dataset import build_examples, language_bucket
from c2_analyzer.nlp.inference import TextModelRegistry, TextModels
from c2_analyzer.nlp.metrics import full_metrics, per_language, seed_summary
from c2_analyzer.nlp.report import ablation_rows
from c2_analyzer.nlp.train import class_weights, smoke_subset

HAS_TORCH = all(importlib.util.find_spec(m) for m in ("torch", "transformers", "tokenizers"))
needs_torch = pytest.mark.skipif(not HAS_TORCH, reason="torch / transformers not installed")

NLP_DIR = Path(__file__).parents[1] / "src" / "c2_analyzer" / "nlp"
VERSION = "v9.9"
LABELS = list(get_labels())
WORDS = {
    "benign": "welcome to our university library opening hours news",
    "phishing": "verify your account password sign in bank suspended",
    "fake_ecommerce": "huge discount sale 90 percent off cart checkout shoes",
    "crypto_scam": "bitcoin wallet airdrop connect wallet claim tokens",
    "malware_delivery": "download update installer exe flash player required",
}
LANG_TEXT = {
    "en": "",
    "si": " ඔබගේ ගිණුම",
    "ta": " உங்கள் கணக்கு",
    "mixed": " ශ්‍රී தமிழ்",
    "other": " Konto",
}
LANG_DETECTED = {"en": "en", "si": "si", "ta": "ta_latn", "mixed": "mixed", "other": "de"}
# per class: 4 train, 2 val, 2 test (split by page index)
SPLIT_OF = ["train", "train", "train", "train", "val", "val", "test", "test"]
LANG_OF = ["en", "si", "other", "en", "ta", "en", "mixed", "en"]


# ---- synthetic project ---------------------------------------------------------------------


def make_project(root: Path) -> dict[str, Path]:
    manifests, splits, text = root / "manifests", root / "splits", root / "text" / VERSION
    manifests.mkdir(parents=True)
    (splits / VERSION).mkdir(parents=True)
    text.mkdir(parents=True)
    rows = []
    for c, label in enumerate(LABELS):
        for i, (split, lang) in enumerate(zip(SPLIT_OF, LANG_OF, strict=True)):
            sample_id = f"c2_{label}_{i + 1:06d}"
            sha = hashlib.sha256(sample_id.encode()).hexdigest()
            rows.append(
                {
                    "sample_id": sample_id,
                    "label": label,
                    "language": "en",
                    "cluster_id": f"cl_{c * 100 + i:06d}",
                    "sha256": sha,
                    "file_path": f"{label}/{sample_id}.html",
                    "split": split,
                    "lang": lang,
                }
            )
            page_text = (
                f"[TITLE] {WORDS[label]} {i}{LANG_TEXT[lang]}\n[CTA] {WORDS[label].split()[0]}"
            )
            (text / f"{sample_id}.json").write_text(
                json.dumps(
                    {
                        "meta": {
                            "sample_id": sample_id,
                            "source_sha256": sha,
                            "schema_version": "text_v1",
                            "rules_hash": "rules1",
                        },
                        "language": {"language": LANG_DETECTED[lang]},
                        "page_text": page_text,
                    }
                ),
                encoding="utf-8",
            )
    frame = pd.DataFrame(rows)
    frame[["sample_id", "label", "language", "cluster_id", "sha256", "file_path"]].to_csv(
        manifests / f"dataset_{VERSION}.csv", index=False
    )
    (manifests / f"dataset_{VERSION}.json").write_text(json.dumps({"fingerprint": "mf1"}))
    split = frame[["sample_id", "label", "language", "cluster_id", "split"]]
    split.to_csv(splits / VERSION / "split.csv", index=False)
    pool = split[split["split"] != "test"].copy()
    pool["fold"] = [i % 2 for i in range(len(pool))]
    pool[["sample_id", "label", "language", "cluster_id", "fold"]].to_csv(
        splits / VERSION / "cv_folds.csv", index=False
    )
    (splits / VERSION / "split.json").write_text(
        json.dumps(
            {
                "manifest": {"fingerprint": "mf1"},
                "included_classes": LABELS,
                "excluded_classes": {},
                "split_fingerprint": split_fingerprint(split),
            }
        )
    )
    return {"manifests": manifests, "splits": splits, "text": text, "root": root}


def make_config(root: Path, model_name: str = "tiny") -> XlmrConfig:
    config = XlmrConfig.load()
    raw = json.loads(json.dumps(config.raw))
    raw["paths"] = {
        "models_dir": str(root / "models" / "xlmr"),
        "reports_dir": str(root / "reports" / "xlmr"),
        "baseline_models_dir": str(root / "models" / "text_baseline"),
        "baseline_reports_dir": str(root / "reports" / "text_baseline"),
        "bundle_dir": str(root / "tmp"),
        "smoke_dir": str(root / "tmp" / "smoke"),
    }
    raw["seeds"] = [1, 2]
    raw["smoke"] = {"per_class": 2, "max_steps": 1, "max_length": 32}
    raw["training"].update(batch_size=4, eval_batch_size=8)
    raw["evaluation"]["min_language_support"] = 3
    raw["text_baseline"]["C"] = [1.0, 10.0]
    raw["text_baseline"]["min_df"] = 1
    return XlmrConfig(raw=raw, model_name=model_name, source=config.source)


@pytest.fixture
def project(tmp_path: Path) -> dict[str, Path]:
    return make_project(tmp_path)


def examples_of(paths: dict[str, Path]):
    return build_examples(VERSION, paths["text"], paths["splits"], paths["manifests"])


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    """A smoke-trained 2-seed tiny XLM-R (shared by the torch tests of this module)."""
    if not HAS_TORCH:
        pytest.skip("torch / transformers not installed")
    from c2_analyzer.nlp.dataset import export_examples
    from c2_analyzer.nlp.model import build_tiny_model_dir
    from c2_analyzer.nlp.train import train_all

    root = tmp_path_factory.mktemp("xlmr")
    paths = make_project(root)
    data = examples_of(paths)
    tiny = build_tiny_model_dir(root / "tiny", [row["text"] for row in data.examples])
    config = make_config(root, str(tiny))
    examples_dir = export_examples(data, root / "examples", model_name=str(tiny))
    model_root = config.models_dir(VERSION)
    card = train_all(
        examples_dir,
        model_root,
        config.training_config(),
        str(tiny),
        [1, 2],
        smoke=True,
        log=lambda *_: None,
    )
    return {
        "root": root,
        "paths": paths,
        "data": data,
        "config": config,
        "card": card,
        "model_root": model_root,
    }


# ---- portable code ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", PORTABLE_MODULES)
def test_portable_modules_never_import_the_repo(name):
    tree = ast.parse((NLP_DIR / name).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert node.level == 1 or not (node.module or "").startswith("c2_analyzer"), name
        if isinstance(node, ast.Import):
            assert not any(a.name.startswith("c2_analyzer") for a in node.names), name


# ---- dataset (tasks 2-4) ---------------------------------------------------------------------


def test_dataset_respects_the_shared_split(project):
    data = examples_of(project)
    split = pd.read_csv(project["splits"] / VERSION / "split.csv").set_index("sample_id")["split"]
    assert len(data.examples) == len(split)
    assert all(row["split"] == split[row["sample_id"]] for row in data.examples)
    assert data.meta["counts"] == {"train": 20, "val": 10, "test": 10}
    assert data.meta["split_fingerprint"] == split_fingerprint(split.reset_index())
    assert data.meta["text_rules_hash"] == "rules1"


def test_label_encoding_is_part4_order(project):
    data = examples_of(project)
    assert data.labels == label_order(LABELS) == list(get_labels())
    assert data.label_mapping == label_mapping(LABELS, {})
    for row in data.examples:
        assert data.labels[row["label_id"]] == row["label"]


def test_language_buckets():
    assert [language_bucket(x) for x in ("en", "si", "si_latn", "ta", "ta_latn", "mixed")] == [
        "en",
        "si",
        "si",
        "ta",
        "ta",
        "mixed",
    ]
    assert language_bucket("de") == language_bucket("unknown") == language_bucket(None) == "other"


def test_dataset_refuses_stale_or_missing_text(project):
    path = project["text"] / "c2_benign_000001.json"
    page = json.loads(path.read_text(encoding="utf-8"))
    page["meta"]["source_sha256"] = "0" * 64
    path.write_text(json.dumps(page), encoding="utf-8")
    with pytest.raises(DatasetError, match="stale"):
        examples_of(project)
    path.unlink()
    with pytest.raises(DatasetError, match="no Part 5A text"):
        examples_of(project)


def test_dataset_refuses_a_split_of_another_manifest(project):
    (project["manifests"] / f"dataset_{VERSION}.json").write_text(json.dumps({"fingerprint": "x"}))
    with pytest.raises(Exception, match="different manifest"):
        examples_of(project)


# ---- loss, metrics ---------------------------------------------------------------------------


def test_class_weights_are_balanced():
    weights = class_weights([0, 0, 0, 1], 3)
    assert weights == pytest.approx([4 / 9, 4 / 3, 0.0])
    assert smoke_subset([{"label_id": i % 2} for i in range(10)], 2) == [
        {"label_id": 0},
        {"label_id": 1},
        {"label_id": 0},
        {"label_id": 1},
    ]


@needs_torch
def test_weighted_loss_matches_manual_cross_entropy():
    import torch

    from c2_analyzer.nlp.train import weighted_trainer_class

    trainer_class = weighted_trainer_class()
    trainer = trainer_class.__new__(trainer_class)  # compute_loss only needs the weights
    trainer.class_weight_tensor = torch.tensor([1.0, 3.0])

    class Out:
        logits = torch.tensor([[2.0, 0.0], [0.0, 1.0], [1.0, 1.0]])

    class Model:
        def __call__(self, **_):
            return Out()

    loss = trainer.compute_loss(Model(), {"labels": torch.tensor([0, 1, 1]), "input_ids": None})
    log_p = torch.log_softmax(Out.logits, dim=-1)
    nll = -torch.stack([log_p[0, 0], log_p[1, 1], log_p[2, 1]])
    expected = (nll * torch.tensor([1.0, 3.0, 3.0])).sum() / 7.0
    assert float(loss) == pytest.approx(float(expected), rel=1e-6)
    unweighted = float(nll.mean())
    assert float(loss) != pytest.approx(unweighted)


def test_metrics_on_a_known_confusion_matrix():
    labels = ["benign", "phishing", "crypto_scam"]
    # true benign x4 (1 flagged as phishing), phishing x3 (1 -> crypto), crypto x1
    y = np.array([0, 0, 0, 0, 1, 1, 1, 2])
    p = np.array([0, 0, 0, 1, 1, 1, 2, 2])
    m = full_metrics(y, p, None, labels)
    assert m["confusion_matrix"] == [[3, 1, 0], [0, 2, 1], [0, 0, 1]]
    precision = [3 / 3, 2 / 3, 1 / 2]
    recall = [3 / 4, 2 / 3, 1 / 1]
    f1 = [2 * a * b / (a + b) for a, b in zip(precision, recall, strict=True)]
    assert m["macro_precision"] == pytest.approx(np.mean(precision))
    assert m["macro_recall"] == pytest.approx(np.mean(recall))
    assert m["macro_f1"] == pytest.approx(np.mean(f1))
    assert m["benign_fpr"] == pytest.approx(1 / 4)
    assert m["accuracy"] == pytest.approx(6 / 8)

    langs = ["en", "en", "si", "si", "en", "ta", "en", "en"]
    result = per_language(y, p, langs, labels, ["en", "si", "ta", "mixed", "other"], 3)
    assert result["en"]["n"] == 5 and not result["en"]["small_n"]
    assert result["si"]["n"] == 2 and result["si"]["small_n"]
    assert result["si"]["labels"] == {"benign": 2} and result["si"]["benign_fpr"] == 0.5
    assert result["mixed"] == {"n": 0, "small_n": True}  # empty buckets are listed, not hidden
    summary = seed_summary([m, full_metrics(y, y, None, labels)])
    assert summary["mean"]["macro_f1"] == pytest.approx((m["macro_f1"] + 1.0) / 2)
    assert summary["n_seeds"] == 2


# ---- TF-IDF baseline -------------------------------------------------------------------------


def test_text_baseline_runs_on_the_shared_folds(project):
    from c2_analyzer.nlp.text_baseline import train_text_baseline

    config = make_config(project["root"])
    results = train_text_baseline(
        VERSION,
        config,
        examples_of(project),
        splits_root=project["splits"],
        figures=False,
        log=lambda *_: None,
    )
    model = results["models"]["tfidf_logreg"]
    assert model["params"]["C"] in (1.0, 10.0) and len(model["cv_grid"]) == 2
    assert model["test"]["n"] == 10 and model["test"]["macro_f1"] > 0.5  # keywords are easy
    assert set(model["per_language"]) >= {"en", "si", "ta", "mixed", "other"}
    reports = config.baseline_reports_dir(VERSION)
    assert (reports / "results.json").is_file() and (reports / "results.md").is_file()
    assert (config.baseline_models_dir(VERSION) / "tfidf_logreg.joblib").is_file()

    models = TextModels.from_config(VERSION, config)
    out = models.predict("[TITLE] bitcoin wallet airdrop connect wallet")
    tfidf = out.models[1]
    assert tfidf.available and sum(tfidf.probabilities.values()) == pytest.approx(1.0, abs=1e-4)


# ---- training, evaluation, inference (torch) ------------------------------------------------


@needs_torch
def test_smoke_training_saves_checkpoints(trained):
    root = trained["model_root"]
    for folder in ("seed_1", "seed_2", "final"):
        for name in (
            "model.safetensors",
            "config.json",
            "tokenizer.json",
            "training_args.json",
            "label_mapping.json",
            "metrics.json",
            "predictions.jsonl",
        ):
            assert (root / folder / name).is_file(), (folder, name)
        assert not (root / folder / "_checkpoints").exists()
    selection = json.loads((root / "final" / "selection.json").read_text())
    assert selection["final_seed"] in (1, 2)
    metrics = json.loads((root / "seed_1" / "metrics.json").read_text())
    assert metrics["global_steps"] == 1 and metrics["smoke"] is True
    assert metrics["split_fingerprint"] == trained["data"].meta["split_fingerprint"]
    config = json.loads((root / "final" / "config.json").read_text())
    assert config["id2label"] == {str(i): c for i, c in enumerate(LABELS)}
    card = json.loads((root / "model_card.json").read_text())
    assert card["split_fingerprint"] == trained["data"].meta["split_fingerprint"]
    assert set(card["seeds"]) == {"1", "2"}


@needs_torch
def test_evaluation_per_language_and_seeds(trained):
    from c2_analyzer.nlp.evaluate import evaluate_xlmr

    config, data = trained["config"], trained["data"]
    results = evaluate_xlmr(VERSION, config, data, figures=False, log=lambda *_: None)
    final = results["models"]["final"]
    assert final["test"]["n"] == 10 and final["val"]["n"] == 10
    assert set(final["per_language"]["test"]) >= {"en", "si", "ta", "mixed", "other"}
    assert {"macro_precision", "macro_recall", "macro_f1"} <= set(final["test"])
    assert results["seed_summary"]["test"]["n_seeds"] == 2
    assert {"seed_1", "seed_2"} <= set(results["models"])
    reports = config.reports_dir(VERSION)
    assert (reports / "results.json").is_file() and (reports / "misclassified.csv").is_file()
    card = json.loads((trained["model_root"] / "model_card.json").read_text())
    assert card["final_test"]["macro_f1"] == pytest.approx(final["test"]["macro_f1"])


@needs_torch
def test_inference_probabilities_sum_to_one(trained):
    models = TextModels.from_config(VERSION, trained["config"])
    outputs = models.predict_many(["[TITLE] verify your account password", "", "ශ්‍රී தமிழ்"])
    for xlmr, _ in outputs:
        assert xlmr.available and xlmr.model == "xlmr"
        assert set(xlmr.probabilities) == set(LABELS)
        assert sum(xlmr.probabilities.values()) == pytest.approx(1.0, abs=1e-4)
        assert xlmr.predicted in LABELS and xlmr.input_tokens >= 2


# ---- Colab round trip -----------------------------------------------------------------------


def test_export_bundle_contents(project):
    config = make_config(project["root"], "xlm-roberta-base")
    data = examples_of(project)
    path, members = export_bundle(VERSION, config, data)
    names = {name for name, _ in members}
    assert names == {
        "README.txt",
        "run_train.py",
        "requirements-colab.txt",
        "configs/xlmr.yaml",
        "c2_nlp/__init__.py",
        "c2_nlp/tokenizer.py",
        "c2_nlp/model.py",
        "c2_nlp/train.py",
        "data/train.jsonl",
        "data/val.jsonl",
        "data/test.jsonl",
        "data/label_mapping.json",
        "data/examples_meta.json",
    }
    with zipfile.ZipFile(path) as archive:
        for name in PORTABLE_MODULES:
            assert archive.read(f"c2_nlp/{name}") == (NLP_DIR / name).read_bytes()
        meta = json.loads(archive.read("data/examples_meta.json"))
        assert meta["split_fingerprint"] == data.meta["split_fingerprint"]
        assert "model_name: xlm-roberta-base" in archive.read("configs/xlmr.yaml").decode()
        assert b"transformers==" in archive.read("requirements-colab.txt")
        train = [json.loads(line) for line in archive.read("data/train.jsonl").splitlines()]
        assert len(train) == 20 and {"sample_id", "text", "label_id", "language"} <= set(train[0])


def _fake_model_zip(path: Path, fingerprint: str, mapping: dict, extra: dict | None = None):
    files = {
        "v9.9/final/config.json": "{}",
        "v9.9/final/model.safetensors": "weights",
        "v9.9/final/selection.json": json.dumps({"final_seed": 1}),
        "v9.9/model_card.json": "{}",
    }
    for folder in ("final", "seed_1"):
        files[f"v9.9/{folder}/metrics.json"] = json.dumps(
            {"split_fingerprint": fingerprint, "dataset_version": VERSION}
        )
        files[f"v9.9/{folder}/label_mapping.json"] = json.dumps(mapping)
    files.update(extra or {})
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return path


def test_import_model_checks_fingerprint_and_paths(project, tmp_path):
    config = make_config(project["root"])
    data = examples_of(project)
    good = data.meta["split_fingerprint"]
    target = tmp_path / "imported"

    bad = _fake_model_zip(tmp_path / "bad.zip", "f" * 64, data.label_mapping)
    with pytest.raises(ImportRefused, match="split fingerprint"):
        import_model(bad, VERSION, config, data, target=target)
    assert not target.exists()

    wrong_labels = dict(data.label_mapping, classes=list(reversed(LABELS)))
    with pytest.raises(ImportRefused, match="label mapping"):
        import_model(
            _fake_model_zip(tmp_path / "l.zip", good, wrong_labels),
            VERSION,
            config,
            data,
            target=target,
        )

    slip = _fake_model_zip(tmp_path / "s.zip", good, data.label_mapping, {"../evil.txt": "x"})
    with pytest.raises(ImportRefused, match="unsafe path"):
        import_model(slip, VERSION, config, data, target=target)

    ok = _fake_model_zip(tmp_path / "ok.zip", good, data.label_mapping)
    result = import_model(ok, VERSION, config, data, target=target)
    assert result["final_seed"] == 1 and (target / "final" / "model.safetensors").is_file()
    with pytest.raises(ImportRefused, match="--force"):
        import_model(ok, VERSION, config, data, target=target)
    import_model(ok, VERSION, config, data, target=target, force=True)


# ---- API -----------------------------------------------------------------------------------


class _FakeDataset:
    """The three DevDataset methods the text-prediction route uses."""

    def latest_version(self) -> str:
        return VERSION

    def content(self, version: str, sample_id: str):
        from c2_analyzer.api.dev_data import NotFoundError
        from c2_analyzer.schemas.content import PageText

        if sample_id != "c2_phishing_000001":
            raise NotFoundError("unknown sample")
        page = PageText(page_text="[TITLE] verify your account password")
        return page.model_dump_json(), "stored"

    def label_of(self, version: str, sample_id: str) -> str:
        return "phishing"

    def split_of(self, version: str, sample_id: str) -> str:
        return "test"


def test_api_says_model_not_available_gracefully(tmp_path):
    app = create_app("development")
    app.dependency_overrides[get_text_models] = lambda: TextModelRegistry(make_config(tmp_path))
    app.dependency_overrides[get_dev_dataset] = lambda: _FakeDataset()
    client = TestClient(app)

    response = client.post(
        "/api/v1/text-prediction", json={"html": "<title>Verify your account</title>"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["page_language"] and body["page_text_chars"] > 0
    assert [m["model"] for m in body["models"]] == ["xlmr", "tfidf_logreg"]
    for model in body["models"]:
        assert model["available"] is False and model["probabilities"] == {}
        assert model["reason"].startswith("model not available")

    dev = client.get("/api/v1/dev/samples/c2_phishing_000001/text-prediction")
    assert dev.status_code == 200
    assert dev.json()["true_label"] == "phishing" and dev.json()["split"] == "test"
    assert client.get("/api/v1/dev/samples/c2_phishing_000002/text-prediction").status_code == 404

    production = TestClient(create_app("production"))
    assert production.get("/api/v1/dev/samples/x/text-prediction").status_code == 404


def test_api_does_not_import_torch_at_startup():
    import subprocess
    import sys

    code = (
        "import sys; import c2_analyzer.api.main; "
        "print('torch' in sys.modules, 'transformers' in sys.modules)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, timeout=120
    )
    assert result.stdout.strip().splitlines()[-1] == "False False"


# ---- ablation --------------------------------------------------------------------------------


def test_ablation_flags_another_split(tmp_path):
    def results(fingerprint: str) -> dict:
        per_class = {c: {"f1": 0.5} for c in LABELS}
        return {
            "best_model": "m",
            "split": {"split_fingerprint": fingerprint},
            "models": {
                "m": {
                    "display_name": "M",
                    "cv": {"mean": {"macro_f1": 0.6}, "std": {"macro_f1": 0.1}},
                    "test": {"macro_f1": 0.7, "benign_fpr": 0.1, "n": 68, "per_class": per_class},
                }
            },
        }

    (tmp_path / "a.json").write_text(json.dumps(results("same")))
    (tmp_path / "b.json").write_text(json.dumps(results("other")))
    rows = ablation_rows(
        {"A": tmp_path / "a.json", "B": tmp_path / "b.json", "C": tmp_path / "none.json"}, "same"
    )
    assert [r["available"] for r in rows] == [True, True, False]
    assert rows[0]["same_split"] and not rows[1]["same_split"]
    assert rows[0]["score_label"] == "CV" and rows[0]["test_macro_f1"] == 0.7
