"""Behavioral intent vector + risk score (task 11).

Part 8: Behavioral intent mapping (sources -> sinks).

Why a fixed vector: the behavior-only baseline (ablation study) and Part 9's
fusion need the SAME columns in the SAME order for every page.
configs/behavior_features.yaml (beh_v1) defines them:
- per pattern: present (0/1), count (occurrences behind its findings) and
  max_severity (0 none, 1 low, 2 medium, 3 high, 4 critical);
- flow statistics and a few specific signals (compute functions below);
- ``behavior_risk_score`` 0-100 = sum over patterns of the weight of that
  pattern's highest severity (behavior_patterns.yaml ``risk_score``: critical
  50, high 25, medium 10, low 3), capped at 100. Two critical patterns = 100;
  one high + one medium = 35. It is DESCRIPTIVE (an easy-to-read summary of
  the findings for reports and the inspector), not the final verdict - Part 9
  decides that.
Every value is always present and finite.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass

from c2_analyzer.schemas.behavior import Finding, Flow

CONFIDENCE_SCORE = {"low": 1, "medium": 2, "high": 3}
OUTBOUND_SINKS = frozenset(
    {"network_external", "network_unknown", "redirect_external", "window_open"}
)


@dataclass
class VectorInput:
    findings: list[Finding]
    flows: list[Flow]
    risk_score: float


def _data_flows(flows: list[Flow]) -> list[Flow]:
    return [flow for flow in flows if flow.source_id != "decoded_string"]


def _variants(findings: list[Finding], pattern: str, *variants: str) -> bool:
    return any(f.pattern_id == pattern and f.variant in variants for f in findings)


COMPUTE: dict[str, Callable[[VectorInput], float]] = {
    "tainted_flow_count": lambda v: len(_data_flows(v.flows)),
    "external_tainted_flow_count": lambda v: sum(
        bool(flow.sink_is_external) for flow in _data_flows(v.flows)
    ),
    "credential_flow_to_external": lambda v: int(
        any(
            flow.source_id in ("credential_input", "form_data_generic")
            and flow.sink_id in OUTBOUND_SINKS
            and flow.sink_is_external is not False
            for flow in v.flows
        )
        or _variants(v.findings, "credential_exfiltration", "form_action", "form_data_external")
    ),
    "flow_to_known_exfil_endpoint": lambda v: int(
        any(flow.sink_is_known_exfil_endpoint for flow in _data_flows(v.flows))
    ),
    "encoded_flow_count": lambda v: sum(flow.encoded for flow in _data_flows(v.flows)),
    "max_flow_confidence": lambda v: max(
        (CONFIDENCE_SCORE[flow.confidence] for flow in _data_flows(v.flows)), default=0
    ),
    "auto_redirect_external": lambda v: int(
        _variants(v.findings, "forced_redirect", "automatic", "meta_refresh")
    ),
    "clipboard_crypto_address": lambda v: int(
        _variants(v.findings, "clipboard_manipulation", "crypto_hijack", "crypto_on_click")
    ),
    "clickfix_command": lambda v: int(_variants(v.findings, "clipboard_manipulation", "clickfix")),
    "risky_auto_download": lambda v: int(
        _variants(v.findings, "suspicious_download", "auto_risky")
    ),
    "decode_to_exec": lambda v: int(
        _variants(
            v.findings,
            "obfuscated_execution",
            "decode_to_exec",
            "decode_to_html",
            "decode_to_html_dynamic",
            "lexical",
        )
    ),
    "behavior_risk_score": lambda v: v.risk_score,
}


def risk_score(findings: list[Finding], weights: dict[str, float], cap: float) -> float:
    """Sum of each pattern's highest-severity weight, capped (see the module docstring)."""
    best: dict[str, Finding] = {}
    for finding in findings:
        current = best.get(finding.pattern_id)
        if current is None or finding.severity_score > current.severity_score:
            best[finding.pattern_id] = finding
    total = sum(weights.get(f.severity, 0.0) for f in best.values())
    return float(min(total, cap))


def build_vector(rules, findings: list[Finding], flows: list[Flow], score: float) -> dict:
    """The intent vector in behavior_features.yaml order (always complete and finite)."""
    data = VectorInput(findings, flows, score)
    vector: dict[str, float | int] = {}
    for spec in rules.features:
        if spec.pattern is not None:
            own = [f for f in findings if f.pattern_id == spec.pattern["id"]]
            stat = spec.pattern["stat"]
            if stat == "present":
                value = int(bool(own))
            elif stat == "count":
                value = sum(f.count for f in own)
            else:
                value = max((f.severity_score for f in own), default=0)
        else:
            value = COMPUTE[spec.compute](data)
        if spec.type in ("int", "binary"):
            value = int(value)
        else:
            value = round(float(value), 4)
        if not math.isfinite(float(value)):
            raise ValueError(f"behavior feature {spec.name} is not finite")
        vector[spec.name] = value
    return vector


def top_lines(findings: list[Finding], limit: int = 5) -> list[str]:
    """<= 5 human-readable lines (most severe first) for Part 9's explanation."""
    return [f"[{f.severity.upper()}] {f.name}: {f.message}" for f in findings[:limit]]
