"""Fixed-order numeric JavaScript feature vector (configs/js_features.yaml, js_v1).

Part 7: Static JavaScript intent analyzer.

Why: later ML (Part 8's intent vector, Part 9's fusion, a JS-only ablation
baseline) needs the SAME columns in the SAME order for every page. The
dictionary in js_features.yaml defines them; this module fills them:
- ``count`` features count PAGE-OWN detections (``in_library`` excluded)
  matching all filters of the spec (apis, categories, access, external URL,
  credential hint);
- ``compute`` features are the small functions below (script / external
  script / obfuscation statistics).
Every feature is always present and finite (0 / 0.0 when nothing applies).
"""

from __future__ import annotations

import math
from collections.abc import Callable

from c2_analyzer.js_analyzer.rules import FeatureSpec, Rules
from c2_analyzer.schemas.js import Detection, ExternalScriptInfo, ScriptInfo

MIN_STATS_CHARS = 200  # entropy / escape ratio of tiny scripts says nothing


def _own(scripts: list[ScriptInfo]) -> list[ScriptInfo]:
    return [s for s in scripts if s.library is None and s.parser != "skipped"]


def _with_stats(scripts: list[ScriptInfo]) -> list[ScriptInfo]:
    return [s for s in _own(scripts) if s.obfuscation is not None]


def _sized(scripts: list[ScriptInfo]) -> list[ScriptInfo]:
    return [s for s in _with_stats(scripts) if s.obfuscation.chars >= MIN_STATS_CHARS]


COMPUTE: dict[
    str, Callable[[list[ScriptInfo], list[ExternalScriptInfo], list[Detection]], float]
] = {
    "inline_script_count": lambda s, e, d: sum(x.source == "inline" for x in s),
    "library_script_count": lambda s, e, d: sum(x.library is not None for x in s),
    "event_handler_count": lambda s, e, d: sum(x.source == "event_handler" for x in s),
    "javascript_url_count": lambda s, e, d: sum(x.source == "javascript_url" for x in s),
    "page_own_js_chars": lambda s, e, d: sum(x.analyzed_chars for x in _own(s)),
    "external_script_count": lambda s, e, d: len(e),
    "third_party_script_count": lambda s, e, d: sum(x.is_external for x in e),
    "known_cdn_script_count": lambda s, e, d: sum(x.known_cdn for x in e),
    "external_script_suspicious_host_count": lambda s, e, d: sum(x.suspicious_host for x in e),
    "third_party_script_no_integrity_count": lambda s, e, d: sum(
        x.is_external and not x.has_integrity for x in e
    ),
    "max_script_entropy": lambda s, e, d: max(
        (x.obfuscation.entropy for x in _sized(s)), default=0.0
    ),
    "max_string_literal_length": lambda s, e, d: max(
        (x.obfuscation.max_string_length for x in _with_stats(s)), default=0
    ),
    "max_escape_ratio": lambda s, e, d: max(
        (x.obfuscation.escape_ratio for x in _sized(s)), default=0.0
    ),
    "obfuscation_signature_count": lambda s, e, d: sum(
        len(x.obfuscation.signatures) for x in _with_stats(s)
    ),
    "minified_script_count": lambda s, e, d: sum(x.obfuscation.minified for x in _with_stats(s)),
    "parse_failure_ratio": lambda s, e, d: (
        round(sum(x.parser == "lexical" for x in s) / analysed, 4)
        if (analysed := sum(x.parser != "skipped" for x in s))
        else 0.0
    ),
    "truncated_script_count": lambda s, e, d: sum(x.truncated for x in s),
    "api_category_count": lambda s, e, d: len({x.category for x in d if not x.in_library}),
}


def matches(spec: dict, detection: Detection) -> bool:
    """Does a page-own detection satisfy every filter of a ``count`` spec?"""
    if detection.in_library:
        return False
    if spec.get("apis") and detection.api not in spec["apis"]:
        return False
    if spec.get("categories") and detection.category not in spec["categories"]:
        return False
    if spec.get("access") and detection.access not in spec["access"]:
        return False
    if spec.get("external") and not (detection.args and detection.args.url_is_external):
        return False
    if spec.get("credential") and not detection.credential_hint:
        return False
    return True


def _value(spec: FeatureSpec, scripts, external, detections) -> float | int:
    if spec.count is not None:
        value = sum(1 for detection in detections if matches(spec.count, detection))
    else:
        value = COMPUTE[spec.compute](scripts, external, detections)
    if spec.type == "int":
        return int(value)
    value = float(value)
    return round(value, 4) if math.isfinite(value) else 0.0


def build_features(
    rules: Rules,
    scripts: list[ScriptInfo],
    external: list[ExternalScriptInfo],
    detections: list[Detection],
) -> dict[str, float | int]:
    """name -> value in dictionary order (``detections`` = the FULL list, before any cut)."""
    missing = [
        spec.compute for spec in rules.features if spec.compute and spec.compute not in COMPUTE
    ]
    if missing:
        raise ValueError(f"js_features.yaml: no compute function for {missing}")
    return {spec.name: _value(spec, scripts, external, detections) for spec in rules.features}
