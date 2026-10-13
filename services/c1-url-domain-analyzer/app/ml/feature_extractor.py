"""Feature extraction bridge for Machine Learning training and inference.

Reuses the exact feature engineering logic from UrlLexicalAnalyzer and DgaAnalyzer
to prevent training-serving skew and guarantee feature consistency.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional
import numpy as np
import pandas as pd

from app.analyzers.dga_analyzer import DgaAnalyzer
from app.analyzers.lexical_analyzer import UrlLexicalAnalyzer
from app.schemas.url_schema import UrlLexicalFeatures

logger = logging.getLogger(__name__)

# Canonical ordered list of features used across all ML models
FEATURE_NAMES: List[str] = [
    # Length metrics
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "tld_length",
    "subdomain_length",
    "domain_depth",
    # Character counts & structural metrics
    "num_dots",
    "num_dots_hostname",
    "num_hyphens",
    "num_hyphens_hostname",
    "num_digits",
    "num_digits_hostname",
    "num_letters",
    "num_special_chars",
    "num_subdomains",
    "path_depth",
    "num_query_params",
    # Protocol & HTTPS indicator
    "is_https",
    # Keyword & suspicious flags
    "suspicious_keyword_count",
    "has_suspicious_keyword",
    "is_suspicious_tld",
    # IP address features
    "is_ip_address",
    "is_private_ip",
    # Repetition & numeric patterns
    "max_consecutive_digits",
    "digit_ratio",
    "max_character_repetition",
    "has_excessive_repetition",
    # Shannon Entropy
    "url_entropy",
    "hostname_entropy",
    "path_entropy",
    "query_entropy",
    # Punycode & Obfuscation
    "is_punycode",
    "is_idn",
    "has_homoglyphs",
    "is_encoded",
    "is_double_encoded",
    "encoded_char_count",
    "has_at_symbol",
    "has_hex_obfuscation",
    "has_misleading_delimiter",
    # DGA Statistical Features
    "dga_label_length",
    "dga_label_entropy",
    "dga_vowel_ratio",
    "dga_consonant_ratio",
    "dga_digit_ratio",
    "dga_max_consecutive_consonants",
    "dga_bigram_perplexity",
    # Domain-level features (integrated when real data is available, imputed when missing)
    "domain_age_days",
    "is_nrd",
    "has_dns_records",
    "has_domain_data",
]


class MlFeatureExtractor:
    """Extracts standardized, ordered numeric feature vectors from URLs for ML models."""

    def __init__(
        self,
        lexical_analyzer: Optional[UrlLexicalAnalyzer] = None,
        dga_analyzer: Optional[DgaAnalyzer] = None,
    ) -> None:
        self.lexical_analyzer = lexical_analyzer or UrlLexicalAnalyzer()
        self.dga_analyzer = dga_analyzer or DgaAnalyzer()

    def extract_dict(
        self,
        url: str,
        domain_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, float]:
        """Extract a dictionary of feature names to float values for a URL."""
        lexical: UrlLexicalFeatures = self.lexical_analyzer.extract_features(url)
        target_domain = lexical.registered_domain or lexical.hostname

        # DGA features computed on target domain label
        dga = self.dga_analyzer.analyze(target_domain)

        # Domain-level features: use real telemetry when available; set -1.0 / 0.0 when missing
        domain_age = -1.0
        is_nrd_val = 0.0
        has_dns_val = 0.0
        has_domain_flag = 0.0

        if domain_data:
            has_domain_flag = 1.0
            raw_age = domain_data.get("domain_age_days", domain_data.get("age_days"))
            if raw_age is not None:
                domain_age = float(raw_age)
            if "is_nrd" in domain_data and domain_data["is_nrd"] is not None:
                is_nrd_val = 1.0 if domain_data["is_nrd"] else 0.0
            if "has_dns_records" in domain_data and domain_data["has_dns_records"] is not None:
                has_dns_val = 1.0 if domain_data["has_dns_records"] else 0.0
            elif "dns_resolved" in domain_data and domain_data["dns_resolved"] is not None:
                has_dns_val = 1.0 if domain_data["dns_resolved"] else 0.0

        return {
            # Length metrics
            "url_length": float(lexical.url_length),
            "hostname_length": float(lexical.hostname_length),
            "path_length": float(lexical.path_length),
            "query_length": float(lexical.query_length),
            "tld_length": float(lexical.tld_length),
            "subdomain_length": float(lexical.subdomain_length),
            "domain_depth": float(lexical.domain_depth),
            # Character counts
            "num_dots": float(lexical.num_dots),
            "num_dots_hostname": float(lexical.num_dots_hostname),
            "num_hyphens": float(lexical.num_hyphens),
            "num_hyphens_hostname": float(lexical.num_hyphens_hostname),
            "num_digits": float(lexical.num_digits),
            "num_digits_hostname": float(lexical.num_digits_hostname),
            "num_letters": float(lexical.num_letters),
            "num_special_chars": float(lexical.num_special_chars),
            "num_subdomains": float(lexical.num_subdomains),
            "path_depth": float(lexical.path_depth),
            "num_query_params": float(lexical.num_query_params),
            # Protocol / HTTPS indicator
            "is_https": 1.0 if (lexical.scheme or "").lower() == "https" else 0.0,
            # Keyword & suspicious flags
            "suspicious_keyword_count": float(lexical.suspicious_keyword_count),
            "has_suspicious_keyword": 1.0 if lexical.has_suspicious_keyword else 0.0,
            "is_suspicious_tld": 1.0 if lexical.is_suspicious_tld else 0.0,
            # IP features
            "is_ip_address": 1.0 if lexical.is_ip_address else 0.0,
            "is_private_ip": 1.0 if lexical.is_private_ip else 0.0,
            # Repetition
            "max_consecutive_digits": float(lexical.max_consecutive_digits),
            "digit_ratio": float(lexical.digit_ratio),
            "max_character_repetition": float(lexical.max_character_repetition),
            "has_excessive_repetition": 1.0 if lexical.has_excessive_repetition else 0.0,
            # Shannon Entropy
            "url_entropy": float(lexical.url_entropy),
            "hostname_entropy": float(lexical.hostname_entropy),
            "path_entropy": float(lexical.path_entropy),
            "query_entropy": float(lexical.query_entropy),
            # Punycode & Obfuscation
            "is_punycode": 1.0 if lexical.is_punycode else 0.0,
            "is_idn": 1.0 if lexical.is_idn else 0.0,
            "has_homoglyphs": 1.0 if lexical.has_homoglyphs else 0.0,
            "is_encoded": 1.0 if lexical.is_encoded else 0.0,
            "is_double_encoded": 1.0 if lexical.is_double_encoded else 0.0,
            "encoded_char_count": float(lexical.encoded_char_count),
            "has_at_symbol": 1.0 if lexical.has_at_symbol else 0.0,
            "has_hex_obfuscation": 1.0 if lexical.has_hex_obfuscation else 0.0,
            "has_misleading_delimiter": 1.0 if lexical.has_misleading_delimiter else 0.0,
            # DGA features
            "dga_label_length": float(dga.label_length),
            "dga_label_entropy": float(dga.label_entropy),
            "dga_vowel_ratio": float(dga.vowel_ratio),
            "dga_consonant_ratio": float(dga.consonant_ratio),
            "dga_digit_ratio": float(dga.digit_ratio),
            "dga_max_consecutive_consonants": float(dga.max_consecutive_consonants),
            "dga_bigram_perplexity": float(dga.bigram_perplexity),
            # Domain-level features
            "domain_age_days": float(domain_age),
            "is_nrd": float(is_nrd_val),
            "has_dns_records": float(has_dns_val),
            "has_domain_data": float(has_domain_flag),
        }

    def extract_vector(
        self,
        url: str,
        domain_data: Optional[Dict[str, Any]] = None,
    ) -> np.ndarray:
        """Extract ordered 1D NumPy array of feature values for a single URL."""
        f_dict = self.extract_dict(url, domain_data=domain_data)
        return np.array([f_dict[name] for name in FEATURE_NAMES], dtype=np.float32)

    def extract_matrix(
        self,
        urls: List[str],
        domain_data_list: Optional[List[Optional[Dict[str, Any]]]] = None,
        batch_size: int = 10000,
        show_progress: bool = True,
    ) -> np.ndarray:
        """Extract a pre-allocated 2D NumPy array (N, n_features) of float32 features.

        Pre-allocating the matrix avoids intermediate Python object bloat, bounding memory
        consumption to ~41 MB per 200,000 URLs.
        """
        n_samples = len(urls)
        n_features = len(FEATURE_NAMES)
        X = np.empty((n_samples, n_features), dtype=np.float32)

        start_time = time.perf_counter()
        has_domain_list = domain_data_list is not None and len(domain_data_list) == n_samples

        for idx, url in enumerate(urls):
            dom_data = domain_data_list[idx] if has_domain_list else None
            f_dict = self.extract_dict(url, domain_data=dom_data)
            for f_idx, fname in enumerate(FEATURE_NAMES):
                X[idx, f_idx] = f_dict[fname]

            if show_progress and ((idx + 1) % batch_size == 0 or (idx + 1) == n_samples):
                elapsed = time.perf_counter() - start_time
                speed = (idx + 1) / max(elapsed, 0.001)
                remaining = (n_samples - (idx + 1)) / max(speed, 0.001)
                logger.info(
                    "Feature extraction progress: %d/%d (%.1f%%) | %.0f URLs/sec | ETA: %.1fs",
                    idx + 1,
                    n_samples,
                    ((idx + 1) / n_samples) * 100.0,
                    speed,
                    remaining,
                )

        return X

    def extract_dataframe(
        self,
        urls: List[str],
        domain_data_list: Optional[List[Optional[Dict[str, Any]]]] = None,
        batch_size: int = 10000,
        show_progress: bool = False,
    ) -> pd.DataFrame:
        """Extract a pandas DataFrame of features for a list of URLs."""
        X = self.extract_matrix(
            urls,
            domain_data_list=domain_data_list,
            batch_size=batch_size,
            show_progress=show_progress,
        )
        return pd.DataFrame(X, columns=FEATURE_NAMES)
