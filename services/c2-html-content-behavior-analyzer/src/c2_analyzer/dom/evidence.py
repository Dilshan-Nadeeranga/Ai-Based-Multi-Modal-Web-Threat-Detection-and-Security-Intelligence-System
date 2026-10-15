"""Human-readable evidence for the important non-zero features.

Part 3: DOM structural analysis.

Why: a number like ``password_form_external_action = 1`` is clear to a model
but not to a user, supervisor or examiner. For every feature that has an
``evidence`` template in configs/dom_features.yaml and a non-zero value
(at least ``min_value`` for ratios), one item is produced:

    {"feature": "password_form_external_action",
     "message": "Password form submits to external domain submit-form.com",
     "severity": "high", "value": 1,
     "details": {"action": "https://submit-form.com/...", "domain": "submit-form.com"}}

Messages are filled from the template with the value and the details the
feature group collected. URLs and field values come from Part 2 already
PII-masked; nothing here un-masks them. Evidence describes facts - the
decision is made later (Part 4 / Part 9).
"""

from __future__ import annotations

from typing import Any

from c2_analyzer.dom.dictionary import specs
from c2_analyzer.schemas.dom import EvidenceItem

SEVERITY_ORDER = {"high": 0, "medium": 1, "info": 2}


class _Template(dict):
    """format_map helper: a missing {name} shows as "?" instead of raising."""

    def __missing__(self, key: str) -> str:
        return "?"


def _show(value: Any) -> Any:
    if isinstance(value, float):
        return f"{value:g}"
    if value is None or value == "" or value == []:
        return "?"
    return value


def build_evidence(
    features: dict[str, float | int], details: dict[str, dict]
) -> list[EvidenceItem]:
    """Evidence items, most severe first (dictionary order within one severity)."""
    items = []
    for name, spec in specs().items():
        template = spec.evidence
        value = features.get(name, 0)
        if not template or not value or value < float(template.get("min_value", 0)):
            continue
        extra = details.get(name, {})
        fields = _Template({key: _show(v) for key, v in extra.items()})
        fields["value"] = _show(value)
        items.append(
            EvidenceItem(
                feature=name,
                message=str(template["message"]).format_map(fields),
                severity=template.get("severity", "info"),
                value=value,
                details={key: v for key, v in extra.items() if v not in (None, "", [], {})},
            )
        )
    return sorted(items, key=lambda item: SEVERITY_ORDER[item.severity])
