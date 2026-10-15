"""Load and check the Part 8 rule files (once per process).

Part 8: Behavioral intent mapping (sources -> sinks).

    configs/sources_sinks.yaml      sources, sinks, exfil endpoints, propagation, events, limits
    configs/behavior_patterns.yaml  patterns (variants: severity + message), content regexes
    configs/behavior_features.yaml  the intent vector (beh_v1)

Why YAML: the source / sink catalogue, the severities and the vector are the
parts a reviewer wants to read and tune without reading Python; the code that
needs real logic (taint propagation, trigger resolution) stays in Python.
Every Part 7 api id named here must exist in configs/js_rules.yaml (a typo
would silently disable a source). ``rules_hash()`` covers the three files, the
Part 3 field rules used to classify credential fields and ``ANALYZER_VERSION``:
a stored result made with other rules is redone by the batch.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from c2_analyzer.config import load_yaml_config
from c2_analyzer.js_analyzer.rules import load_rules as load_js_rules

# Bump when Part 8 CODE changes in a way that changes results (YAML changes are hashed).
ANALYZER_VERSION = "8.2"
SEVERITIES = ("low", "medium", "high", "critical")
SENSITIVITIES = ("low", "medium", "high")
FEATURE_TYPES = ("int", "float", "binary")
PATTERN_STATS = ("present", "count", "max_severity")
# sink apis matched by Part 8 itself (Part 7 has no detection id for them)
PART8_APIS = frozenset({"websocket.send"})
PATTERN_IDS = (
    "credential_access",
    "external_data_transmission",
    "credential_exfiltration",
    "keylogging",
    "forced_redirect",
    "clipboard_manipulation",
    "suspicious_download",
    "obfuscated_execution",
    "anti_analysis",
)


@dataclass(frozen=True)
class Endpoint:
    name: str
    host: str
    path: str
    kind: str  # collector | form_service


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    group: str
    type: str
    description: str
    pattern: dict[str, str] | None
    compute: str | None


@dataclass(frozen=True)
class BehaviorRules:
    sources: dict[str, dict[str, Any]]
    sinks: dict[str, dict[str, Any]]
    endpoints: tuple[Endpoint, ...]
    propagation: dict[str, Any]
    events: dict[str, frozenset[str]]
    limits: dict[str, Any]
    patterns: dict[str, dict[str, Any]]
    severity_scores: dict[str, int]
    risk_weights: dict[str, float]
    risk_cap: float
    crypto: tuple[tuple[str, re.Pattern], ...]
    clickfix: tuple[tuple[str, re.Pattern], ...]
    risky_extensions: frozenset[str]
    devtools_keys: dict[str, Any]
    selection_events: frozenset[str]
    feature_set_version: str
    groups: tuple[str, ...]
    features: tuple[FeatureSpec, ...]
    raw: dict[str, Any]

    def limit(self, name: str) -> Any:
        return self.limits[name]

    def sensitivity(self, source_id: str) -> str:
        return self.sources[source_id]["sensitivity"]

    def variant(self, pattern: str, variant: str) -> dict[str, Any]:
        return self.patterns[pattern]["variants"][variant]

    def factor(self, pattern: str, name: str) -> str:
        return str((self.patterns[pattern].get("factors") or {}).get(name, name))

    def endpoint_kind(self, name: str | None) -> str | None:
        return next((e.kind for e in self.endpoints if e.name == name), None)


def _regexes(items: dict[str, str] | None, where: str) -> tuple[tuple[str, re.Pattern], ...]:
    compiled = []
    for name, pattern in (items or {}).items():
        try:
            compiled.append((str(name), re.compile(pattern)))
        except re.error as error:
            raise ValueError(f"{where}: {name}: bad regex {pattern!r}: {error}") from None
    return tuple(compiled)


def _check_apis(names: list[str] | None, where: str, known: set[str]) -> None:
    for api in names or []:
        if api not in known and api not in PART8_APIS:
            raise ValueError(f"sources_sinks.yaml: {where}: unknown Part 7 api {api!r}")


def _validate_catalogue(raw: dict[str, Any]) -> None:
    known = set(load_js_rules().apis)
    for name, spec in (raw.get("sources") or {}).items():
        if spec.get("sensitivity") not in SENSITIVITIES:
            raise ValueError(
                f"sources_sinks.yaml: source {name}: sensitivity must be {SENSITIVITIES}"
            )
        if not str(spec.get("description", "")).strip():
            raise ValueError(f"sources_sinks.yaml: source {name}: description is required")
        _check_apis(spec.get("apis"), f"source {name}", known)
        _check_apis(spec.get("listener_apis"), f"source {name}", known)
    for item in raw.get("exfil_endpoints") or []:
        if item.get("kind", "collector") not in ("collector", "form_service"):
            raise ValueError(f"sources_sinks.yaml: endpoint {item}: kind collector | form_service")
    for name, spec in (raw.get("sinks") or {}).items():
        if not str(spec.get("description", "")).strip():
            raise ValueError(f"sources_sinks.yaml: sink {name}: description is required")
        _check_apis(spec.get("apis"), f"sink {name}", known)
    required = {
        "credential_input",
        "form_data_generic",
        "keystrokes",
        "cookie_read",
        "storage_read",
        "clipboard_read",
        "user_input",
        "page_url",
        "referrer",
        "fingerprint",
        "decoded_string",
    }
    missing = required - set(raw.get("sources") or {})
    if missing:
        raise ValueError(f"sources_sinks.yaml: sources missing: {sorted(missing)}")


def _validate_patterns(raw: dict[str, Any]) -> None:
    patterns = raw.get("patterns") or {}
    missing = set(PATTERN_IDS) - set(patterns)
    if missing:
        raise ValueError(f"behavior_patterns.yaml: patterns missing: {sorted(missing)}")
    for name, spec in patterns.items():
        for key in ("name", "description", "evidence"):
            if not str(spec.get(key, "")).strip():
                raise ValueError(f"behavior_patterns.yaml: {name}: {key} is required")
        for variant, item in (spec.get("variants") or {}).items():
            if item.get("severity") not in SEVERITIES:
                raise ValueError(
                    f"behavior_patterns.yaml: {name}.{variant}: severity must be {SEVERITIES}"
                )
            if not str(item.get("message", "")).strip():
                raise ValueError(f"behavior_patterns.yaml: {name}.{variant}: message is required")
        if not spec.get("variants"):
            raise ValueError(f"behavior_patterns.yaml: {name}: at least one variant")
    scores = raw.get("severity_scores") or {}
    if set(scores) != set(SEVERITIES):
        raise ValueError(f"behavior_patterns.yaml: severity_scores must define {SEVERITIES}")


def _validate_features(raw: dict[str, Any]) -> None:
    from c2_analyzer.behavior.intent_vector import COMPUTE  # the compute functions

    groups = raw.get("groups") or []
    names: set[str] = set()
    for item in raw.get("features") or []:
        name = item.get("name")
        if not name or not re.fullmatch(r"[a-z][a-z0-9_]*", name) or name in names:
            raise ValueError(f"behavior_features.yaml: bad or duplicate feature name {name!r}")
        names.add(name)
        if item.get("group") not in groups:
            raise ValueError(f"behavior_features.yaml: {name}: unknown group {item.get('group')!r}")
        if item.get("type") not in FEATURE_TYPES:
            raise ValueError(f"behavior_features.yaml: {name}: type must be one of {FEATURE_TYPES}")
        if not str(item.get("description", "")).strip():
            raise ValueError(f"behavior_features.yaml: {name}: description is required (viva)")
        if ("pattern" in item) == ("compute" in item):
            raise ValueError(
                f"behavior_features.yaml: {name}: needs exactly one of pattern / compute"
            )
        if "pattern" in item:
            spec = item["pattern"] or {}
            if spec.get("id") not in PATTERN_IDS or spec.get("stat") not in PATTERN_STATS:
                raise ValueError(f"behavior_features.yaml: {name}: bad pattern spec {spec}")
        elif item["compute"] not in COMPUTE:
            raise ValueError(f"behavior_features.yaml: {name}: unknown compute {item['compute']!r}")
    if not names:
        raise ValueError("behavior_features.yaml: no features")


@lru_cache
def load_behavior_rules() -> BehaviorRules:
    """Load + validate the three YAML files (cached: they never change while running)."""
    catalogue = load_yaml_config("sources_sinks")
    patterns = load_yaml_config("behavior_patterns")
    features = load_yaml_config("behavior_features")
    _validate_catalogue(catalogue)
    _validate_patterns(patterns)
    _validate_features(features)
    events = catalogue.get("events") or {}
    risk = patterns.get("risk_score") or {}
    return BehaviorRules(
        sources=catalogue["sources"],
        sinks=catalogue.get("sinks") or {},
        endpoints=tuple(
            Endpoint(
                name=str(item["name"]),
                host=str(item["host"]).lower(),
                path=str(item.get("path", "")),
                kind=str(item.get("kind", "collector")),
            )
            for item in catalogue.get("exfil_endpoints") or []
        ),
        propagation=catalogue.get("propagation") or {},
        events={key: frozenset(values or []) for key, values in events.items()},
        limits=catalogue.get("limits") or {},
        patterns=patterns["patterns"],
        severity_scores={k: int(v) for k, v in patterns["severity_scores"].items()},
        risk_weights={k: float(v) for k, v in (risk.get("weights") or {}).items()},
        risk_cap=float(risk.get("cap", 100)),
        crypto=_regexes(patterns.get("crypto_address_patterns"), "crypto_address_patterns"),
        clickfix=_regexes(patterns.get("clickfix_patterns"), "clickfix_patterns"),
        risky_extensions=frozenset(
            str(ext).lower().lstrip(".") for ext in patterns.get("risky_download_extensions") or []
        ),
        devtools_keys=patterns.get("devtools_keys") or {},
        selection_events=frozenset(patterns.get("selection_events") or []),
        feature_set_version=str(features["feature_set_version"]),
        groups=tuple(features["groups"]),
        features=tuple(
            FeatureSpec(
                name=item["name"],
                group=item["group"],
                type=item["type"],
                description=" ".join(str(item["description"]).split()),
                pattern=item.get("pattern"),
                compute=item.get("compute"),
            )
            for item in features["features"]
        ),
        raw={
            "sources_sinks": catalogue,
            "behavior_patterns": patterns,
            "behavior_features": features,
        },
    )


def feature_names() -> tuple[str, ...]:
    """Intent-vector names in vector / CSV column order."""
    return tuple(spec.name for spec in load_behavior_rules().features)


@lru_cache
def rules_hash() -> str:
    """sha256 of the three YAML files + Part 3's field rules + ANALYZER_VERSION."""
    field_rules = load_yaml_config("dom_features").get("field_rules")
    payload = {
        "rules": load_behavior_rules().raw,
        "field_rules": field_rules,
        "analyzer": ANALYZER_VERSION,
    }
    text = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
