"""Feature extraction bridge for Machine Learning training and inference.

Reuses the exact feature engineering logic from UrlLexicalAnalyzer and DgaAnalyzer
to prevent training-serving skew and guarantee feature consistency.
"""

from __future__ import annotations

import logging
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

    def extract_dict(self, url: str) -> Dict[str, float]:
        """Extract a dictionary of feature names to float values for a URL."""
        lexical: UrlLexicalFeatures = self.lexical_analyzer.extract_features(url)
        target_domain = lexical.registered_domain or lexical.hostname

        # DGA features computed on target domain label
        dga = self.dga_analyzer.analyze(target_domain)

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
        }

    def extract_vector(self, url: str) -> np.ndarray:
        """Extract ordered 1D NumPy array of feature values for a single URL."""
        f_dict = self.extract_dict(url)
        return np.array([f_dict[name] for name in FEATURE_NAMES], dtype=np.float32)

    def extract_dataframe(self, urls: List[str]) -> pd.DataFrame:
        """Extract a pandas DataFrame of features for a list of URLs."""
        rows = [self.extract_dict(u) for u in urls]
        return pd.DataFrame(rows, columns=FEATURE_NAMES)
