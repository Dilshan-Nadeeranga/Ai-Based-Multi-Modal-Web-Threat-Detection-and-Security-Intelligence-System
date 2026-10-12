"""Project-wide constants that do not belong in a config file.

Shared (used across Parts 1-9).

Labels, languages, sources and intents are NOT here on purpose: they live in
configs/*.yaml and are read through c2_analyzer.config (get_labels(),
get_languages(), get_sources()) so each list is defined in exactly one place.
"""

from __future__ import annotations

SERVICE_NAME = "c2"

# The three analysis modalities of C2 (fixed by the system design, not tunable).
MODALITIES: tuple[str, ...] = ("dom", "content", "behavior")
