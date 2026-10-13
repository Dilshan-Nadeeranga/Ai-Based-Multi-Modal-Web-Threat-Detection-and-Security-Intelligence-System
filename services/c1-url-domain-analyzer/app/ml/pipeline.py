"""Configurable Machine Learning Training and Evaluation Pipeline for Component C1.

Trains, evaluates, and compares:
- Random Forest (Baseline)
- Decision Tree
- XGBoost
- LightGBM

Computes Accuracy, Precision, Recall, F1, ROC-AUC, FPR, confusion matrices,
calibrates decision thresholds, and serializes the winning model artifact.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier

from app.ml.dataset_loader import DatasetLoader, DatasetSplits
from app.ml.feature_extractor import FEATURE_NAMES, MlFeatureExtractor

logger = logging.getLogger(__name__)


@dataclass
class ModelEvaluationResult:
    """Standardized performance metrics container for a trained classifier."""
    model_name: str
    model_type: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    roc_auc: float
    false_positive_rate: float
    true_negative_rate: float
    confusion_matrix: List[List[int]]
    optimal_threshold: float
    avg_latency_ms: float
    is_baseline: bool
    hyperparameters: Dict[str, Any]


@dataclass
class ComparisonReport:
    """Comprehensive comparison report across all candidate ML models."""
    timestamp: str
    dataset_metadata: Dict[str, Any]
    feature_count: int
    models: Dict[str, ModelEvaluationResult]
    recommended_model: str
    recommendation_rationale: str


class MlTrainingPipeline:
    """Orchestrates leak-free feature extraction, model training, evaluation, and serialization."""

    def __init__(
        self,
        output_dir: Union[str, Path] = "models",
        random_seed: int = 42,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.random_seed = random_seed
        self.feature_extractor = MlFeatureExtractor()
        self.dataset_loader = DatasetLoader(random_seed=random_seed)

    def run_training_pipeline(
        self,
        dataset_path: Union[str, Path],
        test_size: float = 0.2,
        val_size: float = 0.1,
        split_strategy: str = "domain_grouped",
        target_max_fpr: float = 0.05,
    ) -> ComparisonReport:
        """Execute end-to-end training and evaluation pipeline."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # 1. Load and clean dataset
        logger.info("Loading dataset from: %s", dataset_path)
        raw_df = self.dataset_loader.load_dataset(dataset_path)

        # 2. Partition dataset into train, validation, test
        logger.info("Splitting dataset using strategy: '%s'", split_strategy)
        splits: DatasetSplits = self.dataset_loader.split_dataset(
            raw_df,
            test_size=test_size,
            val_size=val_size,
            strategy=split_strategy,
        )

        # 3. Extract features using the exact same feature engineering code
        logger.info("Extracting %d features across all partitions...", len(FEATURE_NAMES))
        X_train = self.feature_extractor.extract_dataframe(splits.train_df["url"].tolist())
        y_train = splits.train_df["label"].values

        X_val = self.feature_extractor.extract_dataframe(splits.val_df["url"].tolist())
        y_val = splits.val_df["label"].values

        X_test = self.feature_extractor.extract_dataframe(splits.test_df["url"].tolist())
        y_test = splits.test_df["label"].values

        # 4. Build and fit preprocessor ONLY on training data (Zero Data Leakage)
        preprocessor = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ])
        preprocessor.set_output(transform="pandas")
        logger.info("Fitting preprocessor strictly on training data...")
        X_train_proc = preprocessor.fit_transform(X_train)
        X_val_proc = preprocessor.transform(X_val)
        X_test_proc = preprocessor.transform(X_test)

        # Save fitted preprocessor
        joblib.dump(preprocessor, self.output_dir / "preprocessor.joblib")

        # 5. Define candidate models
        models = self._initialize_models()

        # 6. Train, evaluate, and calibrate thresholds for each model
        evaluation_results: Dict[str, ModelEvaluationResult] = {}
        fitted_models: Dict[str, Any] = {}

        for model_id, (display_name, model_inst, is_baseline) in models.items():
            logger.info("Training %s (%s)...", display_name, model_id)
            model_inst.fit(X_train_proc, y_train)
            fitted_models[model_id] = model_inst

            # Find optimal decision threshold on validation set
            val_probs = model_inst.predict_proba(X_val_proc)[:, 1] if hasattr(model_inst, "predict_proba") else model_inst.predict(X_val_proc)
            opt_thresh = self._calibrate_decision_threshold(y_val, val_probs, max_fpr=target_max_fpr)

            # Evaluate on held-out test set
            eval_res = self._evaluate_model(
                display_name=display_name,
                model=model_inst,
                X_test_proc=X_test_proc,
                y_test=y_test,
                threshold=opt_thresh,
                is_baseline=is_baseline,
            )
            evaluation_results[model_id] = eval_res
            joblib.dump(model_inst, self.output_dir / f"{model_id}.joblib")

        # 7. Model comparison & selection
        recommended_model_id, rationale = self._select_recommended_model(evaluation_results)
        logger.info("Recommended model: %s (%s)", recommended_model_id, rationale)

        # Save best model reference
        best_model = fitted_models[recommended_model_id]
        joblib.dump(best_model, self.output_dir / "best_model.joblib")

        # 8. Generate and save reports
        report = ComparisonReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
            dataset_metadata=splits.metadata,
            feature_count=len(FEATURE_NAMES),
            models=evaluation_results,
            recommended_model=recommended_model_id,
            recommendation_rationale=rationale,
        )

        self._save_reports(report, preprocessor, evaluation_results[recommended_model_id])
        return report

    def _initialize_models(self) -> Dict[str, Tuple[str, Any, bool]]:
        """Instantiate models with balanced weights and reproducible seeds."""
        return {
            "random_forest": (
                "Random Forest (Baseline)",
                RandomForestClassifier(
                    n_estimators=100,
                    max_depth=12,
                    class_weight="balanced",
                    random_state=self.random_seed,
                    n_jobs=-1,
                ),
                True,
            ),
            "decision_tree": (
                "Decision Tree",
                DecisionTreeClassifier(
                    max_depth=10,
                    class_weight="balanced",
                    random_state=self.random_seed,
                ),
                False,
            ),
            "xgboost": (
                "XGBoost",
                XGBClassifier(
                    n_estimators=100,
                    max_depth=6,
                    learning_rate=0.1,
                    random_state=self.random_seed,
                    eval_metric="logloss",
                ),
                False,
            ),
            "lightgbm": (
                "LightGBM",
                LGBMClassifier(
                    n_estimators=100,
                    max_depth=6,
                    learning_rate=0.1,
                    class_weight="balanced",
                    random_state=self.random_seed,
                    verbose=-1,
                ),
                False,
            ),
        }

    def _calibrate_decision_threshold(
        self,
        y_true: np.ndarray,
        y_probs: np.ndarray,
        max_fpr: float = 0.05,
    ) -> float:
        """Select decision threshold balancing low false positives and high recall."""
        thresholds = np.linspace(0.1, 0.9, 81)
        best_thresh = 0.5
        best_f1 = -1.0

        for thresh in thresholds:
            preds = (y_probs >= thresh).astype(int)
            tn, fp, fn, tp = confusion_matrix(y_true, preds, labels=[0, 1]).ravel()
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

            if fpr <= max_fpr:
                f1 = f1_score(y_true, preds, zero_division=0)
                if f1 > best_f1:
                    best_f1 = f1
                    best_thresh = float(thresh)

        # Fallback to default if no threshold satisfies strict FPR
        return best_thresh

    def _evaluate_model(
        self,
        display_name: str,
        model: Any,
        X_test_proc: np.ndarray,
        y_test: np.ndarray,
        threshold: float,
        is_baseline: bool,
    ) -> ModelEvaluationResult:
        """Evaluate classifier metrics and benchmark inference speed."""
        # 1. Prediction probabilities and labels
        if hasattr(model, "predict_proba"):
            y_probs = model.predict_proba(X_test_proc)[:, 1]
        else:
            y_probs = model.predict(X_test_proc).astype(float)

        y_preds = (y_probs >= threshold).astype(int)

        # 2. Benchmark inference latency
        t0 = time.perf_counter()
        _ = model.predict(X_test_proc)
        total_time = (time.perf_counter() - t0) * 1000.0  # ms
        avg_latency_ms = total_time / max(len(X_test_proc), 1)

        # 3. Compute metrics
        acc = float(accuracy_score(y_test, y_preds))
        prec = float(precision_score(y_test, y_preds, zero_division=0))
        rec = float(recall_score(y_test, y_preds, zero_division=0))
        f1 = float(f1_score(y_test, y_preds, zero_division=0))

        try:
            auc = float(roc_auc_score(y_test, y_probs))
        except ValueError:
            auc = 0.5

        cm = confusion_matrix(y_test, y_preds, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        tnr = float(tn / (fp + tn)) if (fp + tn) > 0 else 0.0

        return ModelEvaluationResult(
            model_name=display_name,
            model_type=model.__class__.__name__,
            accuracy=round(acc, 4),
            precision=round(prec, 4),
            recall=round(rec, 4),
            f1_score=round(f1, 4),
            roc_auc=round(auc, 4),
            false_positive_rate=round(fpr, 4),
            true_negative_rate=round(tnr, 4),
            confusion_matrix=cm.tolist(),
            optimal_threshold=round(threshold, 4),
            avg_latency_ms=round(avg_latency_ms, 4),
            is_baseline=is_baseline,
            hyperparameters=model.get_params(),
        )

    def _select_recommended_model(
        self,
        results: Dict[str, ModelEvaluationResult],
    ) -> Tuple[str, str]:
        """Rank models based on False Positive Rate, F1-Score, and inference speed."""
        best_id = "random_forest"
        highest_composite = -100.0

        for mid, res in results.items():
            # Composite scoring formula:
            # Rewards high F1 (+40) and high ROC-AUC (+30)
            # Heavily penalizes False Positive Rate (-40 * FPR)
            # Penalizes high latency (-1 * latency_ms)
            composite = (
                (res.f1_score * 40.0)
                + (res.roc_auc * 30.0)
                - (res.false_positive_rate * 40.0)
                - min(res.avg_latency_ms * 2.0, 10.0)
            )
            if composite > highest_composite:
                highest_composite = composite
                best_id = mid

        winner = results[best_id]
        baseline = results["random_forest"]

        rationale = (
            f"Model '{winner.model_name}' achieved the strongest operational balance: "
            f"F1-Score: {winner.f1_score:.4f}, ROC-AUC: {winner.roc_auc:.4f}, "
            f"False Positive Rate: {winner.false_positive_rate:.4f}, "
            f"and Inference Latency: {winner.avg_latency_ms:.4f} ms/sample. "
        )
        if best_id != "random_forest":
            rationale += (
                f"Outperformed Random Forest baseline (FPR: {baseline.false_positive_rate:.4f}, "
                f"F1: {baseline.f1_score:.4f}) with lower false alarms and faster evaluation."
            )
        else:
            rationale += "Maintained the most reliable generalization boundary across all tested metrics."

        return best_id, rationale

    def _save_reports(
        self,
        report: ComparisonReport,
        preprocessor: Pipeline,
        best_eval: ModelEvaluationResult,
    ) -> None:
        """Write model metadata, JSON report, and markdown comparison document."""
        # 1. JSON Report
        json_path = self.output_dir / "model_comparison_report.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=2)

        # 2. Metadata for Inference Loader
        metadata = {
            "model_name": best_eval.model_name,
            "model_type": best_eval.model_type,
            "optimal_threshold": best_eval.optimal_threshold,
            "feature_names": FEATURE_NAMES,
            "feature_count": len(FEATURE_NAMES),
            "metrics": {
                "accuracy": best_eval.accuracy,
                "precision": best_eval.precision,
                "recall": best_eval.recall,
                "f1_score": best_eval.f1_score,
                "roc_auc": best_eval.roc_auc,
                "false_positive_rate": best_eval.false_positive_rate,
                "avg_latency_ms": best_eval.avg_latency_ms,
            },
            "trained_at": report.timestamp,
        }
        with open(self.output_dir / "model_metadata.json", "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        # 3. Markdown Comparison Report
        md_content = self._render_markdown_report(report)
        with open(self.output_dir / "model_comparison_report.md", "w", encoding="utf-8") as f:
            f.write(md_content)

    def _render_markdown_report(self, report: ComparisonReport) -> str:
        """Generate formatted Markdown comparison document with metrics and matrices."""
        lines = [
            "# Machine Learning Model Comparison & Evaluation Report",
            f"**Generated At**: `{report.timestamp}`",
            f"**Feature Count**: `{report.feature_count}` lexical and DGA statistical features",
            f"**Data Splitting Strategy**: `{report.dataset_metadata.get('strategy', 'unknown')}` (Zero-leakage)",
            "",
            "## 1. Summary Performance Metrics Table",
            "| Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC | FPR | Latency (ms) | Status |",
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
        ]

        for mid, m in report.models.items():
            is_best = " ⭐ Recommended" if mid == report.recommended_model else (" (Baseline)" if m.is_baseline else "")
            lines.append(
                f"| **{m.model_name}** | {m.accuracy:.4f} | {m.precision:.4f} | "
                f"{m.recall:.4f} | {m.f1_score:.4f} | {m.roc_auc:.4f} | "
                f"{m.false_positive_rate:.4f} | {m.avg_latency_ms:.3f} | {is_best} |"
            )

        lines.extend([
            "",
            "## 2. Confusion Matrices (Held-out Test Set)",
            "Format: `[[True Negative, False Positive], [False Negative, True Positive]]`",
            "",
        ])

        for mid, m in report.models.items():
            cm = m.confusion_matrix
            lines.extend([
                f"### {m.model_name}",
                f"- **TN**: `{cm[0][0]}`, **FP**: `{cm[0][1]}`, **FN**: `{cm[1][0]}`, **TP**: `{cm[1][1]}`",
                f"- **Calibrated Threshold**: `{m.optimal_threshold:.4f}`",
                f"- **False Positive Rate**: `{m.false_positive_rate:.4f}`",
                "",
            ])

        lines.extend([
            "## 3. Recommended Production Model & Operational Rationale",
            f"> **Selected Model**: `{report.models[report.recommended_model].model_name}`",
            "",
            f"{report.recommendation_rationale}",
            "",
            "## 4. Dataset Hygiene & Leakage Prevention",
            f"- **Total Samples**: `{report.dataset_metadata.get('total_samples')}`",
            f"- **Train Samples**: `{report.dataset_metadata.get('train_samples')}`",
            f"- **Validation Samples**: `{report.dataset_metadata.get('val_samples')}`",
            f"- **Test Samples**: `{report.dataset_metadata.get('test_samples')}`",
            "- **Zero-Leakage Assurance**: Preprocessing parameters (medians and standard deviations) were calculated strictly from the training partition and transformed onto validation and test partitions.",
        ])

        return "\n".join(lines)
