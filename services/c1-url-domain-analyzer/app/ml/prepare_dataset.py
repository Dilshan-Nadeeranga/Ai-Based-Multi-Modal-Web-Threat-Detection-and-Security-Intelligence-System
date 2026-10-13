"""Large-Scale Dataset Preparation & Ingestion Pipeline for Component C1.

Efficiently loads, standardizes, validates, and deduplicates URL datasets
containing 200,000+ records. Supports single unified CSVs, separate benign/malicious
files, or live feeds from permitted threat intelligence providers (PhishTank,
URLhaus, OpenPhish, Tranco Top 1M).
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlsplit

import pandas as pd

from app.ml.dataset_loader import DatasetLoader

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("dataset_preparer")


@dataclass
class DatasetQualityReport:
    """Quality and summary statistics for a prepared dataset."""
    total_raw_rows: int
    dropped_empty_or_malformed: int
    dropped_unknown_labels: int
    dropped_duplicates: int
    valid_records_retained: int
    legitimate_count: int
    legitimate_percentage: float
    malicious_count: int
    malicious_percentage: float
    unique_domains: int
    processing_time_sec: float
    records_per_sec: float
    output_path: str


class LargeDatasetPreparer:
    """Prepares and validates large-scale URL datasets (200k+ records) with low memory usage."""

    def __init__(self, random_seed: int = 42) -> None:
        self.random_seed = random_seed
        self.loader = DatasetLoader(random_seed=random_seed)

    def prepare_from_csv(
        self,
        input_csv: Union[str, Path],
        output_csv: Union[str, Path],
        url_col: Optional[str] = None,
        label_col: Optional[str] = None,
        chunk_size: int = 50000,
        max_samples: Optional[int] = None,
        balance_classes: bool = False,
        report_json_path: Optional[Union[str, Path]] = None,
    ) -> DatasetQualityReport:
        """Stream a large CSV dataset in chunks, standardize URLs and labels, deduplicate, and save."""
        t0 = time.perf_counter()
        in_path = Path(input_csv)
        out_path = Path(output_csv)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        if not in_path.exists():
            raise FileNotFoundError(f"Input dataset file not found: {in_path}")

        logger.info("Starting dataset preparation from: %s", in_path)
        logger.info("Target output: %s (Chunk size: %d)", out_path, chunk_size)

        seen_urls: set = set()
        cleaned_dfs: List[pd.DataFrame] = []

        total_raw_rows = 0
        dropped_malformed = 0
        dropped_unknown = 0
        dropped_duplicates = 0

        # Read in chunks to prevent memory bloat on 200k+ datasets
        chunk_count = 0
        for chunk in pd.read_csv(in_path, chunksize=chunk_size, low_memory=False):
            chunk_count += 1
            raw_len = len(chunk)
            total_raw_rows += raw_len

            # 1. Resolve columns
            try:
                u_col, l_col = self.loader._resolve_columns(chunk, url_col, label_col)
            except ValueError as e:
                logger.error("Failed to resolve URL/label columns in chunk #%d: %s", chunk_count, e)
                continue

            chunk = chunk.rename(columns={u_col: "url", l_col: "label"})

            # 2. Drop empty / invalid (must be 4-4096 chars and contain a dot or scheme)
            chunk["url"] = chunk["url"].astype(str).str.strip()
            valid_url_mask = (
                (chunk["url"].str.len() >= 4) &
                (chunk["url"].str.len() <= 4096) &
                (chunk["url"] != "nan") &
                (chunk["url"].str.contains(r"\.|localhost|://", regex=True))
            )
            dropped_malformed += int((~valid_url_mask).sum())
            chunk = chunk[valid_url_mask].copy()

            # 3. Canonicalize labels (Strict: never invent labels for unknown URLs)
            chunk["mapped_label"] = chunk["label"].apply(self.loader._map_label)
            unknown_mask = chunk["mapped_label"].isna()
            dropped_unknown += int(unknown_mask.sum())
            chunk = chunk[~unknown_mask].copy()
            chunk["label"] = chunk["mapped_label"].astype(int)
            chunk = chunk.drop(columns=["mapped_label"])

            # 4. Deduplicate across stream and within current chunk
            in_chunk_dup = chunk["url"].duplicated()
            stream_dup = chunk["url"].isin(seen_urls)
            dup_mask = in_chunk_dup | stream_dup
            dropped_duplicates += int(dup_mask.sum())
            chunk = chunk[~dup_mask].copy()
            seen_urls.update(chunk["url"].tolist())

            # 5. Extract domain for leak-free grouping
            chunk["registered_domain"] = chunk["url"].apply(self.loader._extract_domain)

            # Keep essential columns and any real domain features if present
            keep_cols = ["url", "label", "registered_domain"]
            for opt_col in ["domain_age_days", "is_nrd", "has_dns_records", "collection_date", "source"]:
                if opt_col in chunk.columns:
                    keep_cols.append(opt_col)

            cleaned_chunk = chunk[keep_cols]
            cleaned_dfs.append(cleaned_chunk)

            logger.info(
                "Chunk #%d processed: %d valid URLs retained (Running total: %d)",
                chunk_count,
                len(cleaned_chunk),
                len(seen_urls),
            )

            if max_samples and len(seen_urls) >= max_samples:
                logger.info("Reached target limit of %d samples. Stopping ingestion.", max_samples)
                break

        if not cleaned_dfs:
            raise ValueError(f"No valid records could be extracted from: {in_path}")

        full_df = pd.concat(cleaned_dfs, ignore_index=True)

        # 6. Apply max_samples capping if specified
        if max_samples and len(full_df) > max_samples:
            full_df = full_df.iloc[:max_samples].reset_index(drop=True)

        # 7. Optional class balancing (undersample majority class)
        if balance_classes:
            full_df = self._balance_dataset(full_df)

        # 8. Save cleaned dataset
        full_df.to_csv(out_path, index=False)
        total_time = time.perf_counter() - t0

        legit_count = int((full_df["label"] == 0).sum())
        mal_count = int((full_df["label"] == 1).sum())
        total_valid = len(full_df)

        report = DatasetQualityReport(
            total_raw_rows=total_raw_rows,
            dropped_empty_or_malformed=dropped_malformed,
            dropped_unknown_labels=dropped_unknown,
            dropped_duplicates=dropped_duplicates,
            valid_records_retained=total_valid,
            legitimate_count=legit_count,
            legitimate_percentage=round((legit_count / max(total_valid, 1)) * 100.0, 2),
            malicious_count=mal_count,
            malicious_percentage=round((mal_count / max(total_valid, 1)) * 100.0, 2),
            unique_domains=int(full_df["registered_domain"].nunique()),
            processing_time_sec=round(total_time, 2),
            records_per_sec=round(total_raw_rows / max(total_time, 0.001), 1),
            output_path=str(out_path.resolve()),
        )

        logger.info("=== Dataset Preparation Quality Report ===")
        logger.info("Total Raw Rows:        %d", report.total_raw_rows)
        logger.info("Dropped Malformed:     %d", report.dropped_empty_or_malformed)
        logger.info("Dropped Unknown Label: %d", report.dropped_unknown_labels)
        logger.info("Dropped Duplicates:    %d", report.dropped_duplicates)
        logger.info("Valid Records Ready:   %d", report.valid_records_retained)
        logger.info("Class Distribution:    Legit=%d (%.1f%%) | Malicious=%d (%.1f%%)",
                    report.legitimate_count, report.legitimate_percentage,
                    report.malicious_count, report.malicious_percentage)
        logger.info("Unique Apex Domains:   %d", report.unique_domains)
        logger.info("Processing Speed:      %.1f rows/sec (Elapsed: %.2fs)",
                    report.records_per_sec, report.processing_time_sec)
        logger.info("Cleaned Dataset Saved: %s", report.output_path)

        if report_json_path:
            r_path = Path(report_json_path)
            r_path.parent.mkdir(parents=True, exist_ok=True)
            with open(r_path, "w", encoding="utf-8") as f:
                json.dump(asdict(report), f, indent=2)
            logger.info("Quality report saved to: %s", r_path)

        return report

    def prepare_from_separate_files(
        self,
        benign_csv: Union[str, Path],
        malicious_csv: Union[str, Path],
        output_csv: Union[str, Path],
        benign_url_col: Optional[str] = None,
        malicious_url_col: Optional[str] = None,
        max_samples: Optional[int] = None,
        balance_classes: bool = True,
        report_json_path: Optional[Union[str, Path]] = None,
    ) -> DatasetQualityReport:
        """Merge separate benign and malicious URL files into a single leak-free dataset."""
        t0 = time.perf_counter()
        b_path = Path(benign_csv)
        m_path = Path(malicious_csv)

        if not b_path.exists():
            raise FileNotFoundError(f"Benign dataset not found: {b_path}")
        if not m_path.exists():
            raise FileNotFoundError(f"Malicious dataset not found: {m_path}")

        logger.info("Merging separate datasets: Benign='%s' + Malicious='%s'", b_path.name, m_path.name)

        # Load benign
        b_df = pd.read_csv(b_path)
        b_u_col = benign_url_col or next((c for c in b_df.columns if c.lower() in ["url", "domain", "site", "link"]), b_df.columns[0])
        b_df = pd.DataFrame({"url": b_df[b_u_col], "label": 0})

        # Load malicious
        m_df = pd.read_csv(m_path)
        m_u_col = malicious_url_col or next((c for c in m_df.columns if c.lower() in ["url", "phish_url", "domain", "link"]), m_df.columns[0])
        m_df = pd.DataFrame({"url": m_df[m_u_col], "label": 1})

        combined_df = pd.concat([b_df, m_df], ignore_index=True)
        temp_csv = Path(output_csv).parent / "_temp_raw_merged.csv"
        combined_df.to_csv(temp_csv, index=False)

        try:
            report = self.prepare_from_csv(
                input_csv=temp_csv,
                output_csv=output_csv,
                url_col="url",
                label_col="label",
                max_samples=max_samples,
                balance_classes=balance_classes,
                report_json_path=report_json_path,
            )
        finally:
            if temp_csv.exists():
                temp_csv.unlink()

        return report

    def _balance_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """Undersample majority class to produce exactly balanced 50/50 dataset."""
        counts = df["label"].value_counts()
        min_class_size = counts.min()

        df_0 = df[df["label"] == 0].sample(n=min_class_size, random_state=self.random_seed)
        df_1 = df[df["label"] == 1].sample(n=min_class_size, random_state=self.random_seed)

        balanced = pd.concat([df_0, df_1], ignore_index=True).sample(frac=1.0, random_state=self.random_seed).reset_index(drop=True)
        logger.info("Balanced dataset classes: %d legitimate, %d malicious (Total: %d)", min_class_size, min_class_size, len(balanced))
        return balanced


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare, clean, and standardize large-scale URL datasets (200k+ records) for Component C1.",
    )
    parser.add_argument("--input-csv", type=str, default=None, help="Path to raw combined CSV file")
    parser.add_argument("--benign-csv", type=str, default=None, help="Path to separate benign URL CSV file")
    parser.add_argument("--malicious-csv", type=str, default=None, help="Path to separate malicious URL CSV file")
    parser.add_argument("--output-csv", type=str, default="data/cleaned_urls.csv", help="Destination path for cleaned CSV")
    parser.add_argument("--url-col", type=str, default=None, help="URL column name (auto-detected if omitted)")
    parser.add_argument("--label-col", type=str, default=None, help="Label column name (auto-detected if omitted)")
    parser.add_argument("--chunk-size", type=int, default=50000, help="Chunk size for streaming large files (default: 50,000)")
    parser.add_argument("--max-samples", type=int, default=None, help="Maximum valid samples to retain (e.g. 200,000)")
    parser.add_argument("--balance", action="store_true", help="Balance legitimate and malicious classes evenly (50/50)")
    parser.add_argument("--report-json", type=str, default=None, help="Path to save dataset quality report JSON")

    args = parser.parse_args()
    preparer = LargeDatasetPreparer()

    if args.input_csv:
        preparer.prepare_from_csv(
            input_csv=args.input_csv,
            output_csv=args.output_csv,
            url_col=args.url_col,
            label_col=args.label_col,
            chunk_size=args.chunk_size,
            max_samples=args.max_samples,
            balance_classes=args.balance,
            report_json_path=args.report_json,
        )
    elif args.benign_csv and args.malicious_csv:
        preparer.prepare_from_separate_files(
            benign_csv=args.benign_csv,
            malicious_csv=args.malicious_csv,
            output_csv=args.output_csv,
            max_samples=args.max_samples,
            balance_classes=args.balance,
            report_json_path=args.report_json,
        )
    else:
        logger.error("Please provide either --input-csv OR both --benign-csv and --malicious-csv.")
        sys.exit(1)


if __name__ == "__main__":
    main()
