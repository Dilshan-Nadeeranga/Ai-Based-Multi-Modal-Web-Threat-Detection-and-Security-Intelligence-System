"""The DOM feature dictionary (configs/dom_features.yaml), loaded and checked once.

Part 3: DOM structural analysis.

Why: the feature list, its ORDER, types, reasons and evidence texts live in
one YAML file, so the vector, the CSV, the report, the inspector and the
thesis tables can never disagree. This module loads it, validates it
(unique names, known groups/types, evidence templates) and offers small
helpers: ``feature_names()``, ``specs()``, ``dictionary_hash()``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from c2_analyzer.config import load_yaml_config

FEATURE_TYPES = ("int", "float", "binary")
SEVERITIES = ("high", "medium", "info")


@dataclass(frozen=True)
class FeatureSpec:
    """One feature as declared in the dictionary."""

    name: str
    group: str
    type: str
    description: str
    source: str
    needs_page_url: bool = False
    evidence: dict[str, Any] | None = None  # {message, severity, min_value?}


@dataclass(frozen=True)
class FieldClass:
    """Detection rules for one input class (password, card, otp_pin, email, username)."""

    name: str
    types: frozenset[str]
    autocomplete: frozenset[str]
    patterns: tuple[re.Pattern, ...] = field(default_factory=tuple)
    exclude: tuple[re.Pattern, ...] = field(default_factory=tuple)  # vetoes a pattern match


@dataclass(frozen=True)
class Dictionary:
    feature_set_version: str
    groups: tuple[str, ...]
    features: tuple[FeatureSpec, ...]
    field_classes: tuple[FieldClass, ...]  # in priority order
    skip_types: frozenset[str]
    known_form_services: tuple[str, ...]
    offscreen_px: float
    never_visible_tags: frozenset[str]
    report: dict[str, Any]
    raw: dict[str, Any]  # the YAML as loaded (copied to feature_dictionary.json)


def _validate(raw: dict[str, Any]) -> None:
    groups = raw.get("groups") or []
    names: set[str] = set()
    for item in raw.get("features") or []:
        name = item.get("name")
        if not name or not re.fullmatch(r"[a-z][a-z0-9_]*", name):
            raise ValueError(f"dom_features.yaml: bad feature name {name!r}")
        if name in names:
            raise ValueError(f"dom_features.yaml: duplicate feature {name!r}")
        names.add(name)
        if item.get("group") not in groups:
            raise ValueError(f"dom_features.yaml: {name}: unknown group {item.get('group')!r}")
        if item.get("type") not in FEATURE_TYPES:
            raise ValueError(f"dom_features.yaml: {name}: type must be one of {FEATURE_TYPES}")
        if not str(item.get("description", "")).strip():
            raise ValueError(f"dom_features.yaml: {name}: description is required (viva)")
        evidence = item.get("evidence")
        if evidence is not None:
            if not evidence.get("message"):
                raise ValueError(f"dom_features.yaml: {name}: evidence needs a message")
            if evidence.get("severity", "info") not in SEVERITIES:
                raise ValueError(f"dom_features.yaml: {name}: severity must be {SEVERITIES}")
    if not names:
        raise ValueError("dom_features.yaml: no features")


@lru_cache
def load_dictionary() -> Dictionary:
    """Load + validate configs/dom_features.yaml (cached: it never changes while running)."""
    raw = load_yaml_config("dom_features")
    _validate(raw)
    rules = raw.get("field_rules") or {}
    classes = tuple(
        FieldClass(
            name=name,
            types=frozenset(t.lower() for t in spec.get("types") or []),
            autocomplete=frozenset(t.lower() for t in spec.get("autocomplete") or []),
            patterns=tuple(re.compile(p, re.IGNORECASE) for p in spec.get("patterns") or []),
            exclude=tuple(re.compile(p, re.IGNORECASE) for p in spec.get("exclude") or []),
        )
        for name, spec in (rules.get("classes") or {}).items()
    )
    hidden = raw.get("hidden_elements") or {}
    return Dictionary(
        feature_set_version=str(raw["feature_set_version"]),
        groups=tuple(raw["groups"]),
        features=tuple(
            FeatureSpec(
                name=item["name"],
                group=item["group"],
                type=item["type"],
                description=" ".join(str(item["description"]).split()),
                source=str(item.get("source", "")),
                needs_page_url=bool(item.get("needs_page_url", False)),
                evidence=item.get("evidence"),
            )
            for item in raw["features"]
        ),
        field_classes=classes,
        skip_types=frozenset(t.lower() for t in rules.get("skip_types") or []),
        known_form_services=tuple(d.lower() for d in raw.get("known_form_services") or []),
        offscreen_px=float(hidden.get("offscreen_px", 1000)),
        never_visible_tags=frozenset(hidden.get("never_visible_tags") or []),
        report=raw.get("report") or {},
        raw=raw,
    )


def feature_names() -> tuple[str, ...]:
    """Feature names in vector / CSV column order."""
    return tuple(spec.name for spec in load_dictionary().features)


def specs() -> dict[str, FeatureSpec]:
    """name -> FeatureSpec (in dictionary order)."""
    return {spec.name: spec for spec in load_dictionary().features}


@lru_cache
def dictionary_hash() -> str:
    """sha256 of the loaded dictionary - a stored result made with another one is redone."""
    text = json.dumps(load_dictionary().raw, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
