"""Pydantic schemas for URL feature extraction and analysis response models."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class UrlAnalysisRequest(BaseModel):
    """Input payload containing target URL for static intelligence analysis."""
    url: str = Field(..., description="Target URL or domain to analyze", json_schema_extra={"example": "https://login.paypal.verify-account.com/security/login.php?user=123"})


class UrlLexicalFeatures(BaseModel):
    """Structured features extracted from URL for machine learning inference and heuristic analysis.

    All features are derived purely via static parsing and lexical analysis without executing or rendering
    the destination webpage.
    """
    # URL components & normalization
    original_url: str = Field(..., description="Original raw URL input provided by user")
    normalized_url: str = Field(..., description="Safely normalized URL used for parsing")
    scheme: str = Field(..., description="URL scheme (http, https, etc.)")
    hostname: str = Field(..., description="Parsed hostname or IP address")
    port: Optional[int] = Field(None, description="Explicit port number if present")
    path: str = Field("", description="URL path segment")
    query: str = Field("", description="URL query string")
    fragment: str = Field("", description="URL fragment (# identifier)")

    # Domain structure (tldextract breakdown)
    registered_domain: str = Field("", description="Registered domain name (SLD + TLD)")
    subdomain: str = Field("", description="Subdomain prefix")
    tld: str = Field("", description="Top-Level Domain")
    domain_depth: int = Field(0, description="Depth of domain labels count")
    is_suspicious_tld: bool = Field(False, description="Flag for high-risk scam TLDs")

    # Length metrics
    url_length: int = Field(..., description="Total length of normalized URL")
    hostname_length: int = Field(..., description="Length of hostname")
    path_length: int = Field(..., description="Length of URL path")
    query_length: int = Field(..., description="Length of query string")
    tld_length: int = Field(..., description="Length of top-level domain")
    subdomain_length: int = Field(..., description="Length of subdomain prefix")

    # Character counts & structural metrics
    num_dots: int = Field(..., description="Total dots in entire URL")
    num_dots_hostname: int = Field(..., description="Dots in hostname")
    num_hyphens: int = Field(..., description="Total hyphens in URL")
    num_hyphens_hostname: int = Field(..., description="Hyphens in hostname")
    num_digits: int = Field(..., description="Total numeric digits in URL")
    num_digits_hostname: int = Field(..., description="Numeric digits in hostname")
    num_letters: int = Field(..., description="Total alphabetic letters in URL")
    num_special_chars: int = Field(..., description="Non-alphanumeric character count")
    num_subdomains: int = Field(..., description="Number of subdomain labels")
    path_depth: int = Field(..., description="Depth of directory levels in path")
    num_query_params: int = Field(..., description="Count of query parameters")

    # Keywords
    suspicious_keyword_count: int = Field(..., description="Count of security keywords detected")
    suspicious_keywords_found: List[str] = Field(default_factory=list, description="List of matched suspicious keywords")
    has_suspicious_keyword: bool = Field(..., description="True if any suspicious keyword was found")

    # IP address features
    is_ip_address: bool = Field(..., description="True if hostname is an IPv4 or IPv6 address")
    ip_type: str = Field("none", description="IP format: 'none', 'ipv4', 'ipv6', 'hex_ip', 'octal_ip', 'decimal_ip'")
    is_private_ip: bool = Field(False, description="True if IP is private/loopback/reserved")

    # Repetition & numeric patterns
    max_consecutive_digits: int = Field(..., description="Max continuous digits run")
    digit_ratio: float = Field(..., description="Ratio of digits to URL length")
    max_character_repetition: int = Field(..., description="Max consecutive identical characters")
    has_excessive_repetition: bool = Field(..., description="True if character repetition exceeds threshold")

    # Shannon Entropy
    url_entropy: float = Field(..., description="Shannon entropy of full URL")
    hostname_entropy: float = Field(..., description="Shannon entropy of hostname")
    path_entropy: float = Field(..., description="Shannon entropy of path")
    query_entropy: float = Field(..., description="Shannon entropy of query string")

    # Punycode & Homoglyph indicators
    is_punycode: bool = Field(..., description="True if hostname uses Punycode xn--")
    is_idn: bool = Field(..., description="True if hostname contains non-ASCII Internationalized Domain Name characters")
    has_homoglyphs: bool = Field(..., description="True if mixed-script confusables or homoglyphs detected")
    homoglyph_details: List[str] = Field(default_factory=list, description="Descriptions of homoglyph anomalies detected")

    # Obfuscation & Delimiters
    is_encoded: bool = Field(..., description="True if URL percent-encoding (%XX) detected")
    is_double_encoded: bool = Field(..., description="True if double percent-encoding (%25XX) detected")
    encoded_char_count: int = Field(..., description="Count of percent-encoded sequences")
    has_at_symbol: bool = Field(..., description="True if @ symbol is present in host/authority")
    has_hex_obfuscation: bool = Field(..., description="True if hex IP or obfuscated hex present")
    has_misleading_delimiter: bool = Field(..., description="True if misleading delimiters present in host")


class Layer1LexicalAnalysisResult(BaseModel):
    """Result schema for Layer 1 Lexical Feature Extraction and Analysis."""
    component: str = "C1_URL_DOMAIN"
    layer: str = "Layer_1_Lexical_Feature_Extractor"
    status: str = "success"
    url: str
    score: float = Field(..., ge=0.0, le=100.0, description="Heuristic lexical risk score (0=safe, 100=high risk)")
    risk_level: str = Field(..., description="Risk label: Low Risk, Suspicious, Medium Risk, High Risk Scam")
    features: UrlLexicalFeatures
    risk_indicators: List[str] = Field(default_factory=list, description="List of detected risk factors")
    explanation: str = Field(..., description="Summary narrative explaining feature analysis results")
