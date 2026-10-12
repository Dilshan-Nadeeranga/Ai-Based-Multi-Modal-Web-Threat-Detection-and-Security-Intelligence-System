"""Project-wide constants (service name, threat classes, languages, modalities).

Shared (used across Parts 1-9).
"""

from __future__ import annotations

SERVICE_NAME = "c2"

THREAT_CLASSES: tuple[str, ...] = (
    "benign",
    "phishing",
    "fake_ecommerce",
    "crypto_scam",
    "malware_delivery",
)

LANGUAGES: tuple[str, ...] = ("en", "si", "ta")

MODALITIES: tuple[str, ...] = ("dom", "content", "behavior")

SOCIAL_ENGINEERING_INTENTS: tuple[str, ...] = (
    "urgency_threat",
    "fake_reward",
    "credential_request",
    "investment_lure",
    "fake_security_warning",
    "benign",
)
