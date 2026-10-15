"""Load and check configs/js_rules.yaml and configs/js_features.yaml (once per process).

Part 7: Static JavaScript intent analyzer.

Why: the API catalogue (ids, categories, lexical fallback patterns), the lists
(aliases, CDNs, free hosting, library signatures), the safety limits and the
feature vector live in YAML so the detectors, the vector, the report and the
inspector all use the same names. ``rules_hash()`` covers both files, the
analyzer version and the parser version: a stored result made with other
rules or another grammar is redone by the batch.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from c2_analyzer.config import load_yaml_config

# Bump when detector CODE changes in a way that changes results (YAML changes are hashed).
ANALYZER_VERSION = "7.1"
ACCESS = ("call", "read", "write", "assign", "construct", "listener")
FEATURE_TYPES = ("int", "float")


@dataclass(frozen=True)
class LexicalRule:
    api: str
    pattern: re.Pattern
    access: str


@dataclass(frozen=True)
class Library:
    name: str
    banner: tuple[re.Pattern, ...]
    marker: tuple[re.Pattern, ...]
    src: tuple[re.Pattern, ...]
    max_chars: int


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    group: str
    type: str
    description: str
    count: dict[str, Any] | None
    compute: str | None


@dataclass(frozen=True)
class Rules:
    rules_version: str
    categories: dict[str, dict[str, Any]]
    apis: dict[str, dict[str, Any]]  # api id -> {category, description}
    lexical: tuple[LexicalRule, ...]
    lists: dict[str, Any]
    libraries: tuple[Library, ...]
    banner_chars: int
    limits: dict[str, Any]
    feature_set_version: str
    groups: tuple[str, ...]
    features: tuple[FeatureSpec, ...]
    raw: dict[str, Any]

    def category(self, api: str) -> str:
        return self.apis[api]["category"]

    def limit(self, name: str) -> Any:
        return self.limits[name]


def _compile(
    patterns: list[str] | None, where: str, ignore_case: bool = True
) -> tuple[re.Pattern, ...]:
    """Library signatures ignore case; lexical API patterns do not (JavaScript is
    case-sensitive: ``function(`` is not ``Function(``)."""
    compiled = []
    for pattern in patterns or []:
        try:
            compiled.append(re.compile(pattern, re.IGNORECASE if ignore_case else 0))
        except re.error as error:
            raise ValueError(f"js_rules.yaml: {where}: bad regex {pattern!r}: {error}") from None
    return tuple(compiled)


def _validate_features(raw: dict[str, Any], apis: dict, categories: dict) -> None:
    groups = raw.get("groups") or []
    names: set[str] = set()
    for item in raw.get("features") or []:
        name = item.get("name")
        if not name or not re.fullmatch(r"[a-z][a-z0-9_]*", name) or name in names:
            raise ValueError(f"js_features.yaml: bad or duplicate feature name {name!r}")
        names.add(name)
        if item.get("group") not in groups:
            raise ValueError(f"js_features.yaml: {name}: unknown group {item.get('group')!r}")
        if item.get("type") not in FEATURE_TYPES:
            raise ValueError(f"js_features.yaml: {name}: type must be one of {FEATURE_TYPES}")
        if not str(item.get("description", "")).strip():
            raise ValueError(f"js_features.yaml: {name}: description is required (viva)")
        if ("count" in item) == ("compute" in item):
            raise ValueError(f"js_features.yaml: {name}: needs exactly one of count / compute")
        count = item.get("count") or {}
        for api in count.get("apis") or []:
            if api not in apis:
                raise ValueError(f"js_features.yaml: {name}: unknown api {api!r}")
        for category in count.get("categories") or []:
            if category not in categories:
                raise ValueError(f"js_features.yaml: {name}: unknown category {category!r}")
        for access in count.get("access") or []:
            if access not in ACCESS:
                raise ValueError(f"js_features.yaml: {name}: unknown access {access!r}")
    if not names:
        raise ValueError("js_features.yaml: no features")


@lru_cache
def load_rules() -> Rules:
    """Load + validate both YAML files (cached: they never change while running)."""
    raw = load_yaml_config("js_rules")
    feature_raw = load_yaml_config("js_features")
    categories = raw.get("categories") or {}
    apis: dict[str, dict[str, Any]] = {}
    lexical: list[LexicalRule] = []
    for api, spec in (raw.get("apis") or {}).items():
        if spec.get("category") not in categories:
            raise ValueError(f"js_rules.yaml: {api}: unknown category {spec.get('category')!r}")
        apis[api] = {"category": spec["category"], "description": spec.get("description", "")}
        for entry in spec.get("lexical") or []:
            if entry.get("access") not in ACCESS:
                raise ValueError(f"js_rules.yaml: {api}: lexical access must be one of {ACCESS}")
            (pattern,) = _compile([entry["pattern"]], api, ignore_case=False)
            lexical.append(LexicalRule(api, pattern, entry["access"]))
    lists = raw.get("lists") or {}
    for event, api in (lists.get("listener_events") or {}).items():
        if api not in apis:
            raise ValueError(f"js_rules.yaml: listener_events.{event}: unknown api {api!r}")
    settings = raw.get("library_settings") or {}
    default_chars = int(settings.get("default_snippet_chars", 4000))
    libraries = tuple(
        Library(
            name=item["name"],
            banner=_compile(item.get("banner"), item["name"]),
            marker=_compile(item.get("marker"), item["name"]),
            src=_compile(item.get("src"), item["name"]),
            max_chars=int(item.get("max_chars", default_chars)),
        )
        for item in raw.get("libraries") or []
    )
    _validate_features(feature_raw, apis, categories)
    return Rules(
        rules_version=str(raw.get("rules_version", "")),
        categories=categories,
        apis=apis,
        lexical=tuple(lexical),
        lists=lists,
        libraries=libraries,
        banner_chars=int(settings.get("banner_chars", 3000)),
        limits=raw.get("limits") or {},
        feature_set_version=str(feature_raw["feature_set_version"]),
        groups=tuple(feature_raw["groups"]),
        features=tuple(
            FeatureSpec(
                name=item["name"],
                group=item["group"],
                type=item["type"],
                description=" ".join(str(item["description"]).split()),
                count=item.get("count"),
                compute=item.get("compute"),
            )
            for item in feature_raw["features"]
        ),
        raw={"js_rules": raw, "js_features": feature_raw},
    )


def feature_names() -> tuple[str, ...]:
    """Feature names in vector / CSV column order."""
    return tuple(spec.name for spec in load_rules().features)


@lru_cache
def rules_hash() -> str:
    """sha256 of both YAML files + analyzer and parser versions (stored results are redone
    when it changes)."""
    from c2_analyzer.js_analyzer.ast_parser import parser_version

    payload = {
        "rules": load_rules().raw,
        "analyzer": ANALYZER_VERSION,
        "parser": parser_version(),
    }
    text = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
