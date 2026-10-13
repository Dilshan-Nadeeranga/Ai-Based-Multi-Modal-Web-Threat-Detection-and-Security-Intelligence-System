"""Centralized configuration for the c1-url-domain-analyzer service."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

SERVICE_ROOT: Path = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Runtime configuration settings for C1 URL and Domain Analyzer."""

    model_config = SettingsConfigDict(
        env_file=SERVICE_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    service_name: str = "c1-url-domain-analyzer"
    log_level: str = "INFO"
    port: int = 8001
    host: str = "0.0.0.0"

    mongodb_uri: str = "mongodb://localhost:27017"
    mongodb_database: str = "url_domain_analyzer"

    # Domain Intelligence & Registration thresholds
    nrd_threshold_days: int = 30
    nrd_warning_threshold_days: int = 90
    dns_timeout_seconds: float = 3.0
    rdap_timeout_seconds: float = 5.0
    rdap_base_url: str = "https://rdap.org/domain"
    cache_ttl_seconds: int = 3600

    # Optional Threat Intelligence API Keys (Kept in env vars, never hardcoded)
    virustotal_api_key: str = ""
    threatfox_api_key: str = ""

    # Custom public DNS resolvers for reliable queries
    custom_dns_servers: list[str] = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

    # Dynamic DNS providers frequently abused by malicious infrastructure
    dynamic_dns_domains: set[str] = {
        "duckdns.org", "no-ip.com", "ddns.net", "zapto.org", "hopto.org",
        "bounceme.net", "myftp.org", "servebeer.com", "freeddns.org",
        "ngrok.io", "loca.lt", "pagekite.me"
    }

    # Threat-Infrastructure Analysis Settings
    max_redirect_hops: int = 8
    redirect_timeout_seconds: float = 4.0
    max_response_bytes: int = 16384
    allow_private_ips_for_test: bool = False

    # DGA Detection Thresholds
    dga_entropy_threshold: float = 3.6
    dga_vowel_ratio_min: float = 0.15
    dga_vowel_ratio_max: float = 0.65

    # Known URL Shortener Domains
    known_shorteners: set[str] = {
        "bit.ly", "tinyurl.com", "rebrand.ly", "t.co", "goo.gl", "ow.ly",
        "is.gd", "buff.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
        "bl.ink", "trib.al", "linktr.ee", "snip.ly", "clck.ru", "v.gd",
        "qr.net", "s.id", "t.ly", "rotf.lol", "short.io"
    }

    # Suspicious TLD list for lexical heuristic scoring
    suspicious_tlds: set[str] = {
        "zip", "mov", "top", "xyz", "work", "gq", "cf", "tk", "ml", "ga",
        "click", "link", "country", "kim", "science", "party", "review",
        "download", "racing", "date", "stream", "men", "win", "bid"
    }

    # High-risk security keywords in URLs
    suspicious_keywords: set[str] = {
        "login", "signin", "verify", "verification", "account", "update",
        "secure", "security", "banking", "bank", "confirm", "confirmation",
        "support", "service", "credential", "auth", "authorize", "token",
        "wallet", "password", "recovery", "checkout", "payment", "billing",
        "paypal", "appleid", "microsoft", "google", "meta", "netflix",
        "amazon", "facebook", "instagram", "chase", "wellsfargo"
    }

    # =========================================================================
    # Explainable Risk Scoring Engine: Configurable Weights & Thresholds
    # =========================================================================
    # RATIONALE & CALIBRATION NOTE:
    # These baseline weights represent empirical heuristic priors derived from
    # common phishing/threat vector profiles. They are NOT claimed to be
    # permanently optimal or scientifically validated; they are explicitly
    # configurable and designed for dynamic calibration against empirical validation data.
    # Total nominal sum of active baseline weights = 1.00.
    
    # 1. Lexical & Structural Analysis (Weight: 0.15)
    # Rationale: Path depth, query complexity, special symbols, and digit ratios provide
    # baseline syntax indicators, but legitimate URLs can also be complex.
    weight_lexical_structural: float = 0.15

    # 2. Entropy & Obfuscation Analysis (Weight: 0.10)
    # Rationale: Percent-encoding, double-encoding, hex IP formats, and excessive path entropy
    # indicate active evasion or obfuscation techniques.
    weight_entropy_obfuscation: float = 0.10

    # 3. Homoglyph & Lookalike Indicators (Weight: 0.10)
    # Rationale: Confusable scripts (Cyrillic/Latin), Punycode spoofing, and brand imitation
    # are targeted deception mechanisms with high scam specificity.
    weight_homoglyph_lookalike: float = 0.10

    # 4. Domain Registration Age & Registrar Metadata (Weight: 0.20)
    # Rationale: Newly registered domains (<=30 days) and young domains (<=90 days)
    # account for an overwhelming majority of disposable phishing infrastructure.
    # Long-established domains (>2 years) receive mitigating credit.
    weight_domain_registration: float = 0.20

    # 5. DNS & Infrastructure Reputation (Weight: 0.15)
    # Rationale: Fast-flux rotation, private RFC-1918 resolution, dynamic DNS,
    # and threat intelligence feed matches represent high-confidence infrastructure signals.
    weight_dns_reputation: float = 0.15

    # 6. DGA Classification (Weight: 0.05)
    # Rationale: Algorithmic label randomness (perplexity, vowel-consonant clustering)
    # is specific to malware C2 / botnet rendezvous. Lower weight for general web phishing.
    weight_dga: float = 0.05

    # 7. Shortened URLs & Redirect-Chain Indicators (Weight: 0.10)
    # Rationale: Cloaked shortener destinations, cross-domain redirect hops, loops,
    # and SSRF attempts conceal final destinations from user inspection.
    weight_shortener_redirect: float = 0.10

    # 8. Machine Learning Predictions (Weight: 0.15)
    # Rationale: Supervised classification (Random Forest / XGBoost) captures complex
    # non-linear multi-feature interactions, complementing deterministic rules.
    weight_machine_learning: float = 0.15

    # Configurable Risk Classification Thresholds (0.0 to 100.0)
    risk_threshold_low: float = 25.0       # Scores < 25.0 classified as "Low Risk"
    risk_threshold_medium: float = 50.0    # Scores 25.0 - 49.9 classified as "Suspicious"
    risk_threshold_high: float = 75.0      # Scores 50.0 - 74.9: "Medium Risk", >= 75.0: "High Risk Scam"

    # Engine metadata
    risk_engine_version: str = "c1-explainable-risk-v1.0.0"


@lru_cache
def get_settings() -> Settings:
    """Return process-wide settings singleton."""
    return Settings()

