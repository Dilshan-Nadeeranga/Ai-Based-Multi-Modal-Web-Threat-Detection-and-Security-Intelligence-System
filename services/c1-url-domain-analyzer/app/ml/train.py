"""Command-line interface to train and compare ML models for Component C1."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from app.ml.pipeline import MlTrainingPipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("ml_trainer")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train and evaluate Machine Learning models for Component C1 (URL & Domain Analyzer)",
    )
    parser.add_argument(
        "--data-path",
        type=str,
        default="data/benchmark_urls.csv",
        help="Path to training dataset (.csv, .parquet, .json)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="models",
        help="Directory to save models and comparison reports",
    )
    parser.add_argument(
        "--model-type",
        type=str,
        default="random_forest",
        choices=["random_forest", "random_forest_baseline", "decision_tree", "xgboost", "lightgbm", "all"],
        help="Model architecture to train (default: random_forest)",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Fraction of dataset reserved for testing (default: 0.2)",
    )
    parser.add_argument(
        "--val-size",
        type=float,
        default=0.1,
        help="Fraction of dataset reserved for validation (default: 0.1)",
    )
    parser.add_argument(
        "--split-strategy",
        type=str,
        choices=["domain_grouped", "time_based", "stratified"],
        default="domain_grouped",
        help="Data partitioning strategy to prevent leakage (default: domain_grouped)",
    )
    parser.add_argument(
        "--max-fpr",
        type=float,
        default=0.05,
        help="Maximum permissible False Positive Rate for threshold tuning (default: 0.05)",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=50000,
        help="Chunk size for streaming large CSV datasets (default: 50000)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=10000,
        help="Batch size for feature extraction (default: 10000)",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=None,
        help="Maximum samples to train on (e.g. 200,000)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Reproducible random seed (default: 42)",
    )

    args = parser.parse_args()

    data_file = Path(args.data_path)
    if not data_file.exists():
        logger.error("Dataset not found at '%s'. Aborting training.", data_file)
        sys.exit(1)

    logger.info("Initializing ML Training Pipeline with seed %d...", args.seed)
    trainer = MlTrainingPipeline(
        output_dir=args.output_dir,
        random_seed=args.seed,
    )

    try:
        report = trainer.run_training_pipeline(
            dataset_path=data_file,
            test_size=args.test_size,
            val_size=args.val_size,
            split_strategy=args.split_strategy,
            target_max_fpr=args.max_fpr,
            model_selection=args.model_type,
            batch_size=args.batch_size,
            chunk_size=args.chunk_size,
            max_samples=args.max_samples,
        )

        logger.info("Training complete!")
        logger.info("Recommended Model: %s", report.recommended_model)
        logger.info("Recommendation Rationale: %s", report.recommendation_rationale)
        logger.info(
            "Reports and models successfully saved to '%s'",
            args.output_dir,
        )
    except Exception as exc:
        logger.exception("Training pipeline failed with error: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
