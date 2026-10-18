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

    # Enhanced Features for FP/FN Reduction
    is_shortened_url: bool = Field(False, description="True if domain is a recognized URL shortener")
    base_url_entropy: float = Field(0.0, description="Shannon entropy of URL base (scheme + host + path)")
    has_tracking_param: bool = Field(False, description="True if marketing or analytics tracking query parameter is present")
    path_to_url_ratio: float = Field(0.0, description="Ratio of path length to full URL length")
    is_standard_port: bool = Field(True, description="True if standard port (80, 443, or default)")


class DomainRegistrationFeatures(BaseModel):
    """Structured registration and WHOIS/RDAP intelligence features."""
    domain_name: str = Field(..., description="Apex or target registered domain name")
    creation_date: Optional[str] = Field(None, description="ISO timestamp of initial registration")
    expiration_date: Optional[str] = Field(None, description="ISO timestamp of registration expiration")
    updated_date: Optional[str] = Field(None, description="ISO timestamp of last registry update")
    age_days: Optional[int] = Field(None, description="Domain age in days calculated from creation date")
    days_until_expiration: Optional[int] = Field(None, description="Days remaining until registration expiration")
    registrar: Optional[str] = Field(None, description="Accredited domain registrar name")
    registrant_country: Optional[str] = Field(None, description="Country code of registrant")
    dnssec_enabled: bool = Field(False, description="True if DNSSEC signatures are published in registry")
    is_nrd: bool = Field(False, description="True if domain is newly registered (<= NRD threshold days)")
    is_young_domain: bool = Field(False, description="True if domain was registered recently (<= NRD warning threshold)")
    privacy_protected: bool = Field(False, description="True if WHOIS privacy/proxy service is utilized")
    data_source: str = Field("unavailable", description="Data provider: 'rdap', 'whois', or 'unavailable'")
    is_data_available: bool = Field(False, description="True if registration data was successfully retrieved")


class DnsIntelligenceFeatures(BaseModel):
    """Structured DNS configuration and infrastructure features."""
    a_records: List[str] = Field(default_factory=list, description="Resolved IPv4 addresses")
    aaaa_records: List[str] = Field(default_factory=list, description="Resolved IPv6 addresses")
    mx_records: List[str] = Field(default_factory=list, description="Configured Mail Exchanger records")
    ns_records: List[str] = Field(default_factory=list, description="Authoritative Name Server hostnames")
    txt_records: List[str] = Field(default_factory=list, description="TXT resource records")
    has_mx_records: bool = Field(False, description="True if domain publishes at least one MX record")
    has_spf: bool = Field(False, description="True if SPF policy record is present")
    has_dmarc: bool = Field(False, description="True if DMARC record is published")
    min_ttl: Optional[int] = Field(None, description="Minimum DNS resource record TTL in seconds")
    ip_count: int = Field(0, description="Total number of IPv4 addresses resolved")
    is_fast_flux: bool = Field(False, description="True if fast-flux hosting indicators (short TTL + multiple IPs) detected")
    is_dynamic_dns: bool = Field(False, description="True if domain is hosted on known dynamic DNS provider")
    is_private_ip_resolved: bool = Field(False, description="True if domain resolves to private/internal IP space")
    dns_resolved: bool = Field(False, description="True if DNS queries returned valid address or record data")
    dns_indicators: List[str] = Field(default_factory=list, description="Specific DNS anomaly observations")


class DomainReputationFeatures(BaseModel):
    """Threat intelligence and infrastructure reputation indicators."""
    threat_feed_checked: bool = Field(False, description="True if threat feeds or reputation APIs were checked")
    is_known_threat: bool = Field(False, description="True if domain matches known threat intelligence feed")
    threat_type: Optional[str] = Field(None, description="Threat classification: malware, phishing, c2, etc.")
    confidence_score: float = Field(0.0, description="Reputation assessment confidence score (0.0 to 1.0)")
    reputation_source: Optional[str] = Field(None, description="Threat intelligence feed name or 'local_heuristic'")
    reputation_indicators: List[str] = Field(default_factory=list, description="Threat feed or reputation evidence findings")


class DomainIntelligenceReport(BaseModel):
    """Consolidated Domain Intelligence report covering Registration, DNS, and Reputation."""
    registration: DomainRegistrationFeatures
    dns: DnsIntelligenceFeatures
    reputation: DomainReputationFeatures
    domain_risk_score: float = Field(..., ge=0.0, le=100.0, description="Domain intelligence risk sub-score")
    domain_risk_indicators: List[str] = Field(default_factory=list, description="Observed domain risk indicators")


class DgaAnalysisFeatures(BaseModel):
    """Structured Domain Generation Algorithm (DGA) statistical features and indicators."""
    domain_name: str = Field(..., description="Apex or target domain name evaluated")
    label: str = Field(..., description="Specific domain label analyzed (SLD or subdomain)")
    label_length: int = Field(..., description="Character length of analyzed label")
    label_entropy: float = Field(..., description="Shannon entropy of the domain label")
    vowel_count: int = Field(..., description="Count of vowel characters")
    consonant_count: int = Field(..., description="Count of consonant characters")
    digit_count: int = Field(..., description="Count of numeric digits")
    vowel_ratio: float = Field(..., description="Ratio of vowels to total alphabetic characters")
    consonant_ratio: float = Field(..., description="Ratio of consonants to total alphabetic characters")
    digit_ratio: float = Field(..., description="Ratio of digits to label length")
    max_consecutive_consonants: int = Field(..., description="Maximum consecutive consonant sequence length")
    bigram_perplexity: float = Field(..., description="Bigram transition perplexity / improbability score")
    dga_score: float = Field(..., ge=0.0, le=1.0, description="DGA statistical likelihood score (0.0 to 1.0)")
    is_dga_suspected: bool = Field(False, description="True if label exhibits strong algorithmic generation characteristics")
    dga_family_hint: Optional[str] = Field(None, description="Suspected DGA architectural pattern or family hint")
    dga_indicators: List[str] = Field(default_factory=list, description="Observations distinguishing algorithmic patterns from benign words")


class RedirectHop(BaseModel):
    """Record of a single redirect step in a controlled resolution chain."""
    hop_number: int = Field(..., description="Zero-indexed hop count")
    url: str = Field(..., description="URL at this redirect step")
    domain: str = Field(..., description="Hostname at this redirect step")
    status_code: int = Field(..., description="HTTP status code received (e.g. 301, 302, 200)")
    resolved_ip: Optional[str] = Field(None, description="Safely verified destination IP address")
    is_cross_domain: bool = Field(False, description="True if destination hostname differs from previous step")
    location_header: Optional[str] = Field(None, description="Target location specified in HTTP header")


class RedirectChainFeatures(BaseModel):
    """Structured redirect chain resolution and URL shortener analysis features."""
    original_url: str = Field(..., description="Original input URL")
    final_url: str = Field(..., description="Terminal URL reached after redirect resolution")
    is_shortened: bool = Field(False, description="True if initial domain is a known URL shortener service")
    shortener_provider: Optional[str] = Field(None, description="Recognized URL shortener name if applicable")
    total_hops: int = Field(0, description="Total count of observed redirect hops")
    is_redirected: bool = Field(False, description="True if at least one redirect occurred")
    has_redirect_loop: bool = Field(False, description="True if a cyclic redirect loop was detected and aborted")
    has_cross_domain_redirect: bool = Field(False, description="True if chain crossed domain boundaries")
    has_excessive_redirects: bool = Field(False, description="True if hop count exceeds configured threshold")
    destination_domain_changed: bool = Field(False, description="True if final destination domain differs from origin")
    ssrf_blocked: bool = Field(False, description="True if chain was halted due to SSRF / private IP policy violation")
    error_message: Optional[str] = Field(None, description="Resolution failure or error message if aborted")
    chain_hops: List[RedirectHop] = Field(default_factory=list, description="Ordered list of individual redirect steps")
    redirect_indicators: List[str] = Field(default_factory=list, description="Evidence-based redirect risk indicators")


class ThreatInfrastructureReport(BaseModel):
    """Consolidated Threat Infrastructure report covering DGA and Redirect Chain analysis."""
    dga: DgaAnalysisFeatures
    redirect_chain: RedirectChainFeatures
    infrastructure_risk_score: float = Field(..., ge=0.0, le=100.0, description="Threat infrastructure risk sub-score")
    infrastructure_indicators: List[str] = Field(default_factory=list, description="Unified infrastructure observations")


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


class MlPredictionResult(BaseModel):
    """Machine learning classifier prediction and inference telemetry."""
    is_model_loaded: bool = Field(False, description="True if trained ML model is loaded and active")
    model_name: Optional[str] = Field(None, description="Active classifier algorithm name")
    malicious_probability: float = Field(0.0, description="Predicted probability of being malicious (0.0 to 1.0)")
    predicted_label: str = Field("legitimate", description="Predicted classification: 'legitimate' or 'malicious'")
    decision_threshold: float = Field(0.5, description="Calibrated decision threshold applied")
    confidence: float = Field(0.0, description="Confidence percentage")
    inference_time_ms: float = Field(0.0, description="Prediction latency in milliseconds")
    feature_count: int = Field(0, description="Total features evaluated by model")
    top_risk_features: List[str] = Field(default_factory=list, description="Primary features driving the prediction")
    risk_category: str = Field("low", description="Risk category: 'low', 'suspicious_warning', 'high'")
    explanation: str = Field("", description="Human-readable explanation of the model prediction and threshold evaluation")


class ContributingRiskFactor(BaseModel):
    """Specific evidence-backed factor contributing to the overall risk assessment."""
    factor_id: str = Field(..., description="Unique technical identifier for the contributing risk factor")
    title: str = Field(..., description="Human-readable title describing the observed factor")
    category: str = Field(..., description="Analysis channel (e.g. lexical, registration, dns, dga, ml, redirect)")
    impact_score: float = Field(..., description="Score contribution (+ points toward risk, - mitigating credits)")
    evidence: str = Field(..., description="Verifiable empirical evidence backing this observation")
    confidence: str = Field("medium", description="Confidence level: 'high', 'medium', or 'low'")
    epistemic_type: str = Field("heuristic", description="Epistemic tier: 'fact', 'heuristic', or 'prediction'")


class EpistemicEvidenceBreakdown(BaseModel):
    """Strict epistemological separation between observed facts, heuristics, and model predictions."""
    observed_facts: List[str] = Field(
        default_factory=list,
        description="Deterministic, empirically verified measurements (DNS records, registration dates, HTTP status)",
    )
    heuristic_indicators: List[str] = Field(
        default_factory=list,
        description="Rule-based expert indicators (entropy thresholds, keyword matches, confusable scripts)",
    )
    model_predictions: List[str] = Field(
        default_factory=list,
        description="Statistical model outputs (ML classifier malicious probability, DGA likelihood)",
    )


class ExplainableRiskAssessment(BaseModel):
    """Comprehensive explainable audit trail detailing multi-channel risk scoring."""
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Normalized multi-channel risk score (0-100)")
    classification: str = Field(..., description="Categorical risk classification (Low Risk, Suspicious, Medium Risk, High Risk Scam)")
    risk_level: str = Field(..., description="Standardized risk level compatible with gateway")
    verdict: str = Field("SAFE", description="Final operational verdict: SAFE, SUSPICIOUS, PHISHING, or MALICIOUS")
    engine_version: str = Field("c1-explainable-risk-v1.0.0", description="Scoring engine algorithm version")
    model_version: Optional[str] = Field(None, description="Active ML classifier version or algorithm")
    analysis_timestamp: str = Field(..., description="ISO 8601 UTC timestamp when scoring took place")
    active_weights: Dict[str, float] = Field(
        default_factory=dict,
        description="Dynamically renormalized weights across all observable channels (sums to 1.0)",
    )
    channel_scores: Dict[str, float] = Field(
        default_factory=dict,
        description="Normalized sub-scores (0-100) per intelligence channel",
    )
    contributing_factors: List[ContributingRiskFactor] = Field(
        default_factory=list,
        description="Ranked list of key factors driving score up or down",
    )
    epistemic_breakdown: EpistemicEvidenceBreakdown = Field(
        ...,
        description="Classification of findings into facts, heuristics, and statistical predictions",
    )
    analysis_limitations: List[str] = Field(
        default_factory=list,
        description="Explicit documentation of missing services, rate limits, or unscored channels",
    )


class CompleteUrlDomainAnalysisResult(BaseModel):
    """Integrated multi-layer result containing URL Lexical, Domain Intelligence, Threat Infrastructure, and ML."""
    component: str = "C1_URL_DOMAIN"
    layer: str = "Multi_Layer_URL_and_Domain_Intelligence"
    status: str = "success"
    url: str
    score: float = Field(..., ge=0.0, le=100.0, description="Overall consolidated risk score (0-100)")
    risk_level: str = Field(..., description="Risk label: Low Risk, Suspicious, Medium Risk, High Risk Scam")
    verdict: str = Field("SAFE", description="Final operational verdict: SAFE, SUSPICIOUS, PHISHING, or MALICIOUS")
    features: UrlLexicalFeatures = Field(..., description="Extracted lexical and structural features")
    domain_intelligence: DomainIntelligenceReport = Field(..., description="Domain registration, DNS, and reputation intelligence")
    threat_infrastructure: Optional[ThreatInfrastructureReport] = Field(None, description="DGA and redirect chain intelligence")
    ml_prediction: Optional[MlPredictionResult] = Field(None, description="Machine learning classifier inference result")
    risk_assessment: Optional[ExplainableRiskAssessment] = Field(None, description="Explainable multi-channel risk audit trail")
    risk_indicators: List[str] = Field(default_factory=list, description="Unified list of evidence-based risk indicators")
    explanation: str = Field(..., description="Summary narrative explaining analysis results and evidence")

