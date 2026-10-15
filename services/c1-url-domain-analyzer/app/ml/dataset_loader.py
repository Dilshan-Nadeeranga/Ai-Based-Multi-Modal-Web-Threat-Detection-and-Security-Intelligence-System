"""Dataset loading, validation, cleaning, and data-splitting pipeline.

Supports CSV, Parquet, and JSON datasets with label canonicalization,
domain-grouped splitting to prevent domain memorization leakage,
and time-based chronological splitting.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit, train_test_split

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:  # pragma: no cover
    _HAS_TLDEXTRACT = False

logger = logging.getLogger(__name__)


@dataclass
class DatasetSplits:
    """Container for partitioned dataset splits preventing data leakage."""
    train_df: pd.DataFrame
    val_df: pd.DataFrame
    test_df: pd.DataFrame
    strategy: str
    metadata: Dict[str, Any]


class DatasetLoader:
    """Loads, sanitizes, and splits URL datasets for machine learning."""

    LABEL_MAPPING = {
        # Positive (Malicious/Phishing/Malware) -> 1
        1: 1, "1": 1, 1.0: 1,
        "phishing": 1, "phish": 1, "malicious": 1, "malware": 1,
        "bad": 1, "scam": 1, "spam": 1, "suspicious": 1, "defacement": 1,
        # Negative (Legitimate/Benign/Clean) -> 0
        0: 0, "0": 0, 0.0: 0,
        "legitimate": 0, "benign": 0, "clean": 0, "good": 0, "safe": 0,
    }

    def __init__(self, random_seed: int = 42) -> None:
        self.random_seed = random_seed

    CANDIDATE_URL_COLS = ["url", "URL", "Url", "phish_url", "domain", "site", "link", "address", "hostname"]
    CANDIDATE_LABEL_COLS = ["label", "Label", "class", "Class", "result", "type", "target", "status", "is_malicious", "verified"]

    def load_dataset(
        self,
        file_path: Union[str, Path],
        url_col: Optional[str] = "url",
        label_col: Optional[str] = "label",
        timestamp_col: Optional[str] = "collection_date",
        chunk_size: Optional[int] = None,
        max_samples: Optional[int] = None,
    ) -> pd.DataFrame:
        """Load, sanitize, and validate URL dataset with memory-efficient streaming for large files."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Dataset file not found at: {path}")

        suffix = path.suffix.lower()

        # Handle chunked CSV/TSV loading for large datasets (e.g. 200,000+ records)
        if suffix in [".csv", ".tsv"] and chunk_size is not None and chunk_size > 0:
            sep = "\t" if suffix == ".tsv" else ","
            cleaned_chunks: List[pd.DataFrame] = []
            seen_urls: set = set()
            total_loaded = 0

            logger.info("Streaming large dataset '%s' in chunks of %d...", path.name, chunk_size)
            for chunk_idx, chunk_df in enumerate(pd.read_csv(path, sep=sep, chunksize=chunk_size)):
                u_col, l_col = self._resolve_columns(chunk_df, url_col, label_col)
                chunk_df = chunk_df.rename(columns={u_col: "url", l_col: "label"})
                cleaned_chunk = self._clean_and_canonicalize(
                    chunk_df,
                    timestamp_col=timestamp_col,
                    seen_urls=seen_urls,
                )
                if not cleaned_chunk.empty:
                    cleaned_chunks.append(cleaned_chunk)
                    total_loaded += len(cleaned_chunk)

                if max_samples and total_loaded >= max_samples:
                    logger.info("Reached target limit of %d samples. Stopping stream.", max_samples)
                    break

            if not cleaned_chunks:
                raise ValueError(f"No valid records found in dataset '{path}'.")

            df = pd.concat(cleaned_chunks, ignore_index=True)
            if max_samples and len(df) > max_samples:
                df = df.iloc[:max_samples].reset_index(drop=True)
            logger.info("Completed chunked loading: %d valid records ready.", len(df))
            return df

        # Standard file loading (CSV, Parquet, JSON)
        if suffix in [".csv", ".tsv"]:
            sep = "\t" if suffix == ".tsv" else ","
            df = pd.read_csv(path, sep=sep)
        elif suffix in [".parquet", ".pq"]:
            df = pd.read_parquet(path)
        elif suffix in [".json", ".jsonl"]:
            lines = suffix == ".jsonl"
            df = pd.read_json(path, lines=lines)
        else:
            raise ValueError(f"Unsupported file format '{suffix}'. Supported: .csv, .tsv, .parquet, .json, .jsonl")

        # Resolve column names
        u_col, l_col = self._resolve_columns(df, url_col, label_col)
        df = df.rename(columns={u_col: "url", l_col: "label"})

        if max_samples and len(df) > max_samples * 2:
            # Pre-filter to reduce memory before cleaning
            df = df.head(max_samples * 2)

        df = self._clean_and_canonicalize(df, timestamp_col=timestamp_col)
        if max_samples and len(df) > max_samples:
            df = df.iloc[:max_samples].reset_index(drop=True)
        return df

    def _resolve_columns(
        self,
        df: pd.DataFrame,
        url_col: Optional[str],
        label_col: Optional[str],
    ) -> Tuple[str, str]:
        """Auto-detect URL and label column names from dataset headers."""
        actual_url = url_col if url_col and url_col in df.columns else None
        if not actual_url:
            for candidate in self.CANDIDATE_URL_COLS:
                if candidate in df.columns:
                    actual_url = candidate
                    break
        if not actual_url:
            raise ValueError(f"URL column not found. Available columns: {list(df.columns)}")

        actual_label = label_col if label_col and label_col in df.columns else None
        if not actual_label:
            for candidate in self.CANDIDATE_LABEL_COLS:
                if candidate in df.columns:
                    actual_label = candidate
                    break
        if not actual_label:
            raise ValueError(f"Label column not found. Available columns: {list(df.columns)}")

        return actual_url, actual_label

    def _extract_domain(self, url: str) -> str:
        """Extract registered domain for domain-grouped evaluation."""
        try:
            parsed = urlsplit(url if "://" in url else f"http://{url}")
            host = parsed.netloc.split(":")[0].strip().lower()
            if not host:
                return "unknown_domain"
            if _HAS_TLDEXTRACT:
                ext = tldextract.extract(host)
                top = getattr(ext, "top_domain_under_public_suffix", "")
                if top:
                    return top
                elif ext.suffix:
                    return f"{ext.domain}.{ext.suffix}"
                return ext.domain or host
            return host
        except Exception:
            return "unknown_domain"

    def _clean_and_canonicalize(
        self,
        df: pd.DataFrame,
        timestamp_col: Optional[str] = None,
        seen_urls: Optional[set] = None,
    ) -> pd.DataFrame:
        """Remove nulls, malformed records, duplicates, and canonicalize labels."""
        initial_count = len(df)

        # Drop null URLs and labels
        df = df.dropna(subset=["url", "label"]).copy()

        # Clean string whitespace
        df["url"] = df["url"].astype(str).str.strip()

        # Reject empty strings or unreasonably long/short strings
        df = df[df["url"].str.len() >= 4]
        df = df[df["url"].str.len() <= 4096]

        # Canonicalize labels to 0 and 1 strictly (never invent labels)
        df["normalized_label"] = df["label"].apply(self._map_label)
        df = df.dropna(subset=["normalized_label"])
        df["label"] = df["normalized_label"].astype(int)
        df = df.drop(columns=["normalized_label"])

        # Investigate and eliminate conflicting labels across duplicate URLs instead of silently choosing one
        conflicting_mask = df.groupby("url")["label"].transform("nunique") > 1
        if conflicting_mask.any():
            conflict_count = int(df.loc[conflicting_mask, "url"].nunique())
            logger.warning(
                "Detected %d URLs with conflicting labels across records! Dropping ambiguous conflicting URLs.",
                conflict_count,
            )
            df = df[~conflicting_mask]

        # Deduplicate identical URLs
        if seen_urls is not None:
            if isinstance(seen_urls, dict):
                conflicts = [u for u, l in zip(df["url"], df["label"]) if u in seen_urls and seen_urls[u] != l]
                if conflicts:
                    logger.warning("Detected %d streaming URLs with conflicting labels! Discarding conflicting records.", len(conflicts))
                    df = df[~df["url"].isin(set(conflicts))]
                mask = ~df["url"].isin(seen_urls)
                df = df[mask]
                for u, l in zip(df["url"], df["label"]):
                    seen_urls[u] = l
            else:
                # Streaming deduplication across chunks
                mask = ~df["url"].isin(seen_urls)
                df = df[mask]
                seen_urls.update(df["url"].tolist())
        else:
            df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)

        # Extract registered domain for grouping
        df["registered_domain"] = df["url"].apply(self._extract_domain)

        # Format timestamp if present
        if timestamp_col and timestamp_col in df.columns:
            df["timestamp"] = pd.to_datetime(df[timestamp_col], errors="coerce")

        final_count = len(df)
        logger.debug(
            "Cleaned chunk: %d initial records -> %d valid records (%d dropped / deduplicated)",
            initial_count,
            final_count,
            initial_count - final_count,
        )
        return df

    def _map_label(self, val: Any) -> Optional[int]:
        """Convert arbitrary label value into binary 0 or 1."""
        if pd.isna(val):
            return None
        if isinstance(val, (int, float)) and val in (0, 1):
            return int(val)
        norm_val = str(val).strip().lower()
        return self.LABEL_MAPPING.get(norm_val, None)

    def split_dataset(
        self,
        df: pd.DataFrame,
        test_size: float = 0.2,
        val_size: float = 0.1,
        strategy: str = "domain_grouped",
    ) -> DatasetSplits:
        """Split dataset into train, validation, and test partitions without data leakage.

        Strategies:
        - 'domain_grouped': GroupShuffleSplit on 'registered_domain'. URLs from the
          same apex domain are guaranteed to be isolated in either train or test, preventing
          domain memorization leakage.
        - 'time_based': Chronological split if 'timestamp' is present in DataFrame.
        - 'stratified': Standard stratified train/val/test split using reproducible seed.
        """
        if len(df) < 10:
            raise ValueError(f"Dataset too small ({len(df)} records) for train/val/test split.")

        if strategy == "time_based" and "timestamp" in df.columns and not df["timestamp"].isna().all():
            return self._split_time_based(df, test_size=test_size, val_size=val_size)
        elif strategy == "domain_grouped":
            return self._split_domain_grouped(df, test_size=test_size, val_size=val_size)
        else:
            return self._split_stratified(df, test_size=test_size, val_size=val_size)

    def _split_domain_grouped(
        self,
        df: pd.DataFrame,
        test_size: float = 0.2,
        val_size: float = 0.1,
    ) -> DatasetSplits:
        """Split data grouping by registered_domain to test generalization to unseen threats."""
        groups = df["registered_domain"]
        gss_test = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=self.random_seed)
        train_val_idx, test_idx = next(gss_test.split(df, df["label"], groups))

        train_val_df = df.iloc[train_val_idx].reset_index(drop=True)
        test_df = df.iloc[test_idx].reset_index(drop=True)

        # Sub-split train_val into train and validation
        adj_val_size = val_size / (1.0 - test_size)
        gss_val = GroupShuffleSplit(n_splits=1, test_size=adj_val_size, random_state=self.random_seed)
        train_idx, val_idx = next(gss_val.split(train_val_df, train_val_df["label"], train_val_df["registered_domain"]))

        train_df = train_val_df.iloc[train_idx].reset_index(drop=True)
        val_df = train_val_df.iloc[val_idx].reset_index(drop=True)

        metadata = self._build_metadata(df, train_df, val_df, test_df, "domain_grouped")
        return DatasetSplits(train_df=train_df, val_df=val_df, test_df=test_df, strategy="domain_grouped", metadata=metadata)

    def _split_time_based(
        self,
        df: pd.DataFrame,
        test_size: float = 0.2,
        val_size: float = 0.1,
    ) -> DatasetSplits:
        """Chronological split simulating real deployment against future threats."""
        df_sorted = df.sort_values(by="timestamp").reset_index(drop=True)
        n = len(df_sorted)
        test_count = int(n * test_size)
        val_count = int(n * val_size)
        train_count = n - test_count - val_count

        train_df = df_sorted.iloc[:train_count].reset_index(drop=True)
        val_df = df_sorted.iloc[train_count:train_count + val_count].reset_index(drop=True)
        test_df = df_sorted.iloc[train_count + val_count:].reset_index(drop=True)

        metadata = self._build_metadata(df, train_df, val_df, test_df, "time_based")
        return DatasetSplits(train_df=train_df, val_df=val_df, test_df=test_df, strategy="time_based", metadata=metadata)

    def _split_stratified(
        self,
        df: pd.DataFrame,
        test_size: float = 0.2,
        val_size: float = 0.1,
    ) -> DatasetSplits:
        """Stratified random split with reproducible seed."""
        train_val_df, test_df = train_test_split(
            df,
            test_size=test_size,
            random_state=self.random_seed,
            stratify=df["label"],
        )
        adj_val_size = val_size / (1.0 - test_size)
        train_df, val_df = train_test_split(
            train_val_df,
            test_size=adj_val_size,
            random_state=self.random_seed,
            stratify=train_val_df["label"],
        )
        metadata = self._build_metadata(df, train_df, val_df, test_df, "stratified")
        return DatasetSplits(train_df=train_df.reset_index(drop=True), val_df=val_df.reset_index(drop=True), test_df=test_df.reset_index(drop=True), strategy="stratified", metadata=metadata)

    def _build_metadata(
        self,
        total_df: pd.DataFrame,
        train_df: pd.DataFrame,
        val_df: pd.DataFrame,
        test_df: pd.DataFrame,
        strategy: str,
    ) -> Dict[str, Any]:
        """Compute summary statistics across dataset splits."""
        return {
            "strategy": strategy,
            "random_seed": self.random_seed,
            "total_samples": len(total_df),
            "train_samples": len(train_df),
            "val_samples": len(val_df),
            "test_samples": len(test_df),
            "class_distribution_total": total_df["label"].value_counts().to_dict(),
            "class_distribution_train": train_df["label"].value_counts().to_dict(),
            "class_distribution_val": val_df["label"].value_counts().to_dict(),
            "class_distribution_test": test_df["label"].value_counts().to_dict(),
            "unique_domains_total": total_df["registered_domain"].nunique(),
            "unique_domains_train": train_df["registered_domain"].nunique(),
            "unique_domains_test": test_df["registered_domain"].nunique(),
        }
