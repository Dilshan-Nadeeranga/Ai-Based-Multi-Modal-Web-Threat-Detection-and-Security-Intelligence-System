"""Explain the saved fusion model's decision for one dataset sample (dev inspector).

Part 9: Tri-modal fusion + ablation study (Batch A, task 5).

For a dataset sample the arm probabilities are the STORED ones of
``data/processed/fusion/<v>/oof_<arm>.csv``: out-of-fold for train / val pages (what the
fusion model was trained on) and the final arm models' for test pages (what it was scored
on) - so the inspector shows exactly the numbers behind the ablation. Scoring a NEW page
(running every arm live) is Batch B's /analyze.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np

from c2_analyzer.fusion.common import FusionConfig
from c2_analyzer.fusion.data import FusionData, load_features
from c2_analyzer.fusion.explain import page_drivers
from c2_analyzer.fusion.model import load_bundle, restore
from c2_analyzer.fusion.oof import load_oof, load_reference
from c2_analyzer.fusion.operating_point import threshold_predict
from c2_analyzer.schemas.fusion import ArmProbabilities, FusionDriver, FusionExplanation


class FusionUnavailable(LookupError):
    """No fusion model for the version (run run_ablation.py)."""


class FusionStale(RuntimeError):
    """The fusion model or its OOF tables no longer match the split."""


class FusionPredictor:
    def __init__(
        self,
        version: str,
        config: FusionConfig | None = None,
        models_root: Path | None = None,
        oof_root: Path | None = None,
        splits_root: Path | None = None,
    ) -> None:
        self.config = config or FusionConfig.load()
        self.version = version
        models = Path(models_root) / version if models_root else self.config.models_dir(version)
        oof_dir = Path(oof_root) / version if oof_root else self.config.oof_dir(version)
        self.bundle = load_bundle(models)
        if self.bundle is None:
            raise FusionUnavailable(
                f"no fusion model for {version} - run: python scripts/run_ablation.py "
                f"--version {version}"
            )
        try:
            self.ref = load_reference(version, splits_root)
            oofs, missing = {}, []
            for arm in self.config.arms:
                oof = load_oof(arm, self.ref, oof_dir)
                if oof is None:
                    missing.append(arm)
                else:
                    oofs[arm] = oof
        except (ValueError, FileNotFoundError) as error:
            raise FusionStale(str(error)) from None
        problems = []
        if self.bundle["split_fingerprint"] != self.ref.split_fingerprint:
            problems.append("the fusion model was trained on another split")
        if self.bundle["labels"] != self.ref.labels:
            problems.append("the fusion model has other classes")
        lacking = [arm for arm in self.bundle["arms"] if arm not in oofs]
        if lacking:
            problems.append(f"no OOF table for {', '.join(lacking)}")
        if problems:
            raise FusionStale(
                "; ".join(problems) + f" - re-run scripts/run_ablation.py --version {version}"
            )
        tabular = [arm for arm in self.bundle["arms"] if arm not in self.bundle["text_arms"]]
        features = load_features(version, tabular) if self.bundle["strategy"] == "hybrid" else {}
        self.data = FusionData(self.ref, oofs, missing, self.config, features)
        self.model = restore(self.bundle)

    def explain(self, sample_id: str) -> FusionExplanation:
        frame = self.ref.frame.set_index("sample_id")
        if sample_id not in frame.index:
            raise KeyError(f"{sample_id} is not in the {self.version} split (excluded class?)")
        row = frame.loc[sample_id]
        labels, bundle = self.ref.labels, self.bundle
        inputs = self.data.inputs(bundle["arms"], [sample_id])
        proba = self.model.predict_proba(inputs)[0]
        predicted = int(np.argmax(proba))
        benign = labels.index("benign")
        threshold = float(bundle["threshold"]["threshold"])
        at_threshold = int(threshold_predict(proba[None, :], benign, threshold)[0])
        drivers = page_drivers(self.model, inputs, predicted, self.config.page_drivers)
        source = (
            "final model (trained on train+val)"
            if row["split"] == "test"
            else "out-of-fold (model trained on the other CV folds)"
        )
        arms = []
        for arm in self.config.arms:
            oof = self.data.oofs.get(arm)
            if oof is None:
                arms.append(
                    ArmProbabilities(
                        arm=arm,
                        display=self.config.arm_display(arm),
                        available=False,
                        used_by_model=arm in bundle["arms"],
                        reason="no OOF predictions for this arm yet",
                    )
                )
                continue
            p = oof.proba([sample_id])[0]
            arms.append(
                ArmProbabilities(
                    arm=arm,
                    display=self.config.arm_display(arm),
                    available=True,
                    used_by_model=arm in bundle["arms"],
                    source=source,
                    predicted=labels[int(np.argmax(p))],
                    probabilities={label: float(v) for label, v in zip(labels, p, strict=True)},
                )
            )
        contributions = drivers["arms"]
        return FusionExplanation(
            sample_id=sample_id,
            dataset_version=self.version,
            split=str(row["split"]),
            true_label=str(row["label"]),
            strategy=bundle["strategy"],
            strategy_display=self.config.strategy_display(bundle["strategy"]),
            arms=arms,
            missing_arms=list(self.data.missing),
            probabilities={label: float(v) for label, v in zip(labels, proba, strict=True)},
            predicted=labels[predicted],
            benign_threshold=threshold,
            benign_fpr_target=float(bundle["threshold"]["target"]),
            predicted_at_threshold=labels[at_threshold],
            driver_method=drivers["method"],
            arm_contributions=contributions,
            driving_arm=max(contributions, key=contributions.get),
            top_drivers=[
                FusionDriver(
                    name=f["feature"],
                    arm=f["feature"].split(".", 1)[0],
                    value=f["value"],
                    contribution=f["contribution"],
                )
                for f in drivers["features"]
            ],
            note=(
                "train / val page: the fusion model was trained on these OOF probabilities"
                if row["split"] != "test"
                else "test page: scored once in the ablation (reports/ablation)"
            ),
        )
