"""Behavioral patterns (tasks 4-10): what the page's code is trying to do.

Part 8: Behavioral intent mapping (sources -> sinks).

Each pattern is defined in configs/behavior_patterns.yaml (name, plain-English
description, the evidence it needs, variants with severity + message
template). This module decides which variant applies and collects the
evidence. Rules of thumb (viva):
- a pattern needs a CONNECTION (a flow, or code + trigger), never one API:
  fetch alone, a credential read alone, a redirect after a click are normal;
- credential_access is context only (low): validation scripts read fields;
- credential_exfiltration (critical): credential / form data -> another site,
  a run-time-built address (high), a redirect URL, or a form action changed to
  another site; factors: known data-collection endpoint, encoded data, a
  submit handler that calls preventDefault() (stop the real submit, send the
  data elsewhere - the classic kit);
- keylogging: keystrokes -> any network sink (critical) / storage (medium);
- forced_redirect: an external redirect with no user action (load, timer,
  top-level code), right after reading credentials, with history
  manipulation, a meta refresh to another site, or only after browser checks
  (cloaking, medium);
- clipboard_manipulation: a ClickFix command (critical), a wallet address put
  in the clipboard without a click / in a copy listener (critical) or on a
  click (high), a copy listener rewriting clipboardData, clipboard -> network;
- suspicious_download: a risky file type downloaded from code; no click ->
  high; content decoded in the page -> one level up;
- obfuscated_execution: decoded string -> eval / Function / document.write /
  innerHTML (high); Part 7 obfuscation signature or very high entropy + eval
  in the same script (medium); minified code alone never counts;
- anti_analysis (extra): right-click / DevTools keys / debugger traps /
  DevTools size checks / selection blocking (low, several = medium).
Library code never produces a finding (library scripts are not indexed).
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from c2_analyzer.behavior.code_index import ScriptCtx
from c2_analyzer.behavior.dataflow import RawFlow
from c2_analyzer.behavior.rules import PATTERN_IDS, BehaviorRules
from c2_analyzer.behavior.sources_sinks import Catalogue, PageFields, SinkRef, SourceRef
from c2_analyzer.behavior.triggers import TriggerResolver
from c2_analyzer.js_analyzer import syntax as sx
from c2_analyzer.schemas.behavior import EvidenceItem, Finding, Flow
from c2_analyzer.schemas.js import JsAnalysisResult

CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}
SEVERITY_ORDER = ("low", "medium", "high", "critical")
CREDENTIAL_SOURCES = frozenset({"credential_input", "form_data_generic"})
NETWORK_SINKS = frozenset({"network_external", "network_unknown", "network_internal"})
REDIRECT_APIS = frozenset(
    {"location.href", "location.assign", "location.replace", "meta_refresh", "history.pushState"}
)
NOT_TRANSMISSION = frozenset(
    {"credential_input", "form_data_generic", "keystrokes", "clipboard_read", "decoded_string"}
)
LOOPS = frozenset({"for_statement", "for_in_statement", "while_statement", "do_statement"})
F12 = re.compile(r"\b123\b|['\"]F12['\"]")
CTRL_SHIFT = re.compile(r"\b(?:73|74|67|75)\b|['\"][IJCKijck]['\"]")
CTRL_U = re.compile(r"\b85\b|['\"][Uu]['\"]")


class _Values(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def bump(severity: str, levels: int = 1) -> str:
    """``levels`` up (critical stays critical) or down (low stays low)."""
    index = SEVERITY_ORDER.index(severity) + levels
    return SEVERITY_ORDER[max(0, min(index, len(SEVERITY_ORDER) - 1))]


@dataclass
class PageFacts:
    """Everything the patterns look at for one page."""

    rules: BehaviorRules
    js: JsAnalysisResult
    contexts: dict[int, ScriptCtx]
    catalogue: Catalogue
    flows: list[tuple[Flow, RawFlow]]
    fields: PageFields
    findings: list[Finding] = field(default_factory=list)


class PatternMatcher:
    def __init__(self, facts: PageFacts, triggers: TriggerResolver | None = None) -> None:
        self.facts = facts
        self.triggers = triggers
        self.rules = facts.rules
        self.scores = facts.rules.severity_scores
        settings = facts.rules.patterns["obfuscated_execution"]
        self.active_content = re.compile(str(settings.get("active_content") or r"<\s*script"))
        self.max_exec_steps = int(settings.get("max_exec_chain_steps", 6))

    # ---- helpers ------------------------------------------------------------------

    def add(
        self,
        pattern: str,
        variant: str,
        values: dict[str, Any],
        *,
        confidence: str,
        evidence: list[EvidenceItem],
        count: int = 1,
        script_index: int | None = None,
        factors: list[str] | None = None,
        flow_ids: list[int] | None = None,
        severity: str | None = None,
    ) -> None:
        spec = self.rules.variant(pattern, variant)
        severity = severity or spec["severity"]
        message = str(spec["message"]).format_map(_Values({k: v for k, v in values.items()}))
        self.facts.findings.append(
            Finding(
                pattern_id=pattern,
                name=str(self.rules.patterns[pattern]["name"]),
                variant=variant,
                severity=severity,
                severity_score=self.scores[severity],
                confidence=confidence,
                message=message,
                count=count,
                script_index=script_index,
                factors=factors or [],
                flow_ids=flow_ids or [],
                evidence=evidence,
            )
        )

    @staticmethod
    def flow_evidence(flow: Flow) -> list[EvidenceItem]:
        return [
            EvidenceItem(
                kind="flow_step",
                ref=flow.id,
                script_index=step.script_index,
                line=step.line,
                column=step.column,
                code=step.code,
                note=f"{step.step}" + (f": {step.note}" if step.note else ""),
            )
            for step in flow.path
        ]

    @staticmethod
    def source_evidence(source: SourceRef, note: str | None = None) -> EvidenceItem:
        return EvidenceItem(
            kind="source",
            ref=source.id,
            script_index=source.ctx.index if source.ctx is not None else None,
            line=source.line,
            column=source.column,
            code=source.code,
            note=note or f"{source.source_id}" + (f": {source.detail}" if source.detail else ""),
        )

    @staticmethod
    def sink_evidence(sink: SinkRef, note: str | None = None) -> EvidenceItem:
        trigger = f" ({sink.trigger.reason})" if sink.trigger is not None else ""
        return EvidenceItem(
            kind="sink" if sink.ctx is not None else "html",
            ref=sink.id,
            script_index=sink.ctx.index if sink.ctx is not None else None,
            line=sink.line or None,
            column=sink.column or None,
            code=sink.code,
            note=note or f"{sink.sink_id}: {sink.api}{trigger}",
        )

    @staticmethod
    def destination(sink: SinkRef) -> str:
        if sink.endpoint:
            return f"{sink.endpoint} ({sink.url_domain or sink.url})"
        if sink.is_external is None:
            return "an address built at run time"
        if sink.is_external:
            return sink.url_domain or sink.url or "another site"
        return (
            f"the page's own site ({sink.url_domain})" if sink.url_domain else "the page's own site"
        )

    @staticmethod
    def best_confidence(flows: list[Flow]) -> str:
        return max((f.confidence for f in flows), key=lambda c: CONFIDENCE_ORDER[c], default="low")

    @staticmethod
    def trigger_text(sink: SinkRef) -> str:
        return sink.trigger.reason if sink.trigger is not None else "trigger unknown"

    def describe_sources(self, sources: list[SourceRef]) -> str:
        parts = []
        for source in sources:
            if source.source_id == "credential_input":
                text = (source.detail or source.code).split(" = ")[0].split(" (")[0]
                parts.append(text if source.api != "FormData" else f"the form ({text})")
            elif source.source_id == "form_data_generic":
                parts.append(f"the form ({(source.detail or '').split(':')[0] or 'FormData'})")
            else:
                parts.append((source.detail or source.source_id).split(" = ")[0])
        unique = list(dict.fromkeys(parts))
        kind = sources[0].source_id if sources else ""
        label = {
            "credential_input": "credentials",
            "form_data_generic": "form data",
            "keystrokes": "keystrokes",
            "cookie_read": "cookies",
            "storage_read": "stored data",
            "clipboard_read": "clipboard content",
            "user_input": "input values",
            "page_url": "the page address",
            "referrer": "the referrer",
            "fingerprint": "browser fingerprint data",
        }.get(kind, kind)
        shown = ", ".join(unique[:3]) + (" ..." if len(unique) > 3 else "")
        return f"{label} ({shown})" if shown else label

    def _group_by_sink(
        self, flows: list[tuple[Flow, RawFlow]]
    ) -> dict[int, list[tuple[Flow, RawFlow]]]:
        groups: dict[int, list[tuple[Flow, RawFlow]]] = defaultdict(list)
        for item in flows:
            groups[item[1].sink.id].append(item)
        return groups

    @staticmethod
    def _primary(items: list[tuple[Flow, RawFlow]]) -> tuple[Flow, RawFlow]:
        """The flow to show as THE chain: a password first, then the most confident, shortest."""

        def rank(item: tuple[Flow, RawFlow]):
            flow, raw = item
            password = "password" in (raw.source.detail or "").lower()
            return (not password, -CONFIDENCE_ORDER[flow.confidence], len(flow.path))

        return min(items, key=rank)

    def _chain(self, items: list[tuple[Flow, RawFlow]]) -> list[EvidenceItem]:
        primary = self._primary(items)
        evidence = self.flow_evidence(primary[0])
        for flow, raw in items:
            if flow.id != primary[0].id:
                evidence.append(
                    self.source_evidence(
                        raw.source, f"also sent: {raw.source.detail or raw.source.code}"
                    )
                )
        return evidence[:20]

    def _submit_hijack(self, sink: SinkRef) -> bool:
        if sink.ctx is None or sink.node is None or sink.trigger is None:
            return False
        if sink.trigger.event != "submit":
            return False
        return any(
            sink.ctx.key(f) in sink.ctx.prevent_default for f in sink.ctx.function_chain(sink.node)
        )

    # ---- task 4 -------------------------------------------------------------------

    def credential_access(self) -> None:
        sources = [s for s in self.facts.catalogue.sources if s.source_id == "credential_input"]
        if not sources:
            return
        fields = list(
            dict.fromkeys((s.detail or s.code).split(" (")[0].split(" = ")[0] for s in sources)
        )
        shown = ", ".join(fields[:4]) + (f" and {len(fields) - 4} more" if len(fields) > 4 else "")
        confidence = "high" if any(s.confidence == "high" for s in sources) else "low"
        self.add(
            "credential_access",
            "read",
            {"count": len(sources), "fields": shown},
            confidence=confidence,
            count=len(sources),
            evidence=[self.source_evidence(s) for s in sources[:6]],
        )

    # ---- tasks 5 + 6 --------------------------------------------------------------

    def exfiltration(self) -> None:
        credential, keys, other, clipboard = [], [], [], []
        for flow, raw in self.facts.flows:
            source_id, sink = raw.source.source_id, raw.sink
            if source_id in CREDENTIAL_SOURCES:
                credential.append((flow, raw))
            elif source_id == "keystrokes":
                keys.append((flow, raw))
            elif source_id == "clipboard_read":
                clipboard.append((flow, raw))
            elif source_id not in NOT_TRANSMISSION and sink.sink_id == "network_external":
                other.append((flow, raw))
        self._credential_flows(credential)
        self._keylogging(keys)
        self._transmission(other)
        self._clipboard_flows(clipboard)
        self._form_actions()

    def _credential_flows(self, items: list[tuple[Flow, RawFlow]]) -> None:
        for sink_id, group in self._group_by_sink(items).items():
            sink = self.facts.catalogue.sinks[sink_id]
            has_credential = [i for i in group if i[1].source.source_id == "credential_input"]
            redirect = sink.api in REDIRECT_APIS or sink.api == "window.open"
            if has_credential:
                group = has_credential
                if sink.endpoint:
                    variant = "known_endpoint"
                elif sink.sink_id == "network_external":
                    variant = "external"
                elif redirect and sink.is_external:
                    variant = "redirect_url"
                elif sink.sink_id == "network_unknown":
                    variant = "unknown_destination"
                else:
                    continue  # own site / storage: a normal login post, not exfiltration
            else:
                if sink.sink_id == "network_external" or sink.endpoint:
                    variant = "form_data_external"
                else:
                    continue
            flows = [flow for flow, _ in group]
            factors = []
            if sink.endpoint:
                factors.append(
                    self.rules.factor("credential_exfiltration", "known_endpoint").format(
                        endpoint=sink.endpoint
                    )
                )
            encodings = sorted({e for flow in flows for e in flow.encodings})
            if encodings:
                factors.append(
                    self.rules.factor("credential_exfiltration", "encoded").format(
                        encodings=", ".join(encodings)
                    )
                )
            if self._submit_hijack(sink):
                factors.append(self.rules.factor("credential_exfiltration", "submit_hijack"))
            if variant == "unknown_destination":
                factors.append(self.rules.factor("credential_exfiltration", "unknown_destination"))
            severity = None
            identity_only = has_credential and not any(raw.source.secret for _, raw in group)
            kind = self.rules.endpoint_kind(sink.endpoint)
            if identity_only and kind != "collector":
                # email / name to a form backend is what contact forms do: two levels lower
                levels = -2 if kind == "form_service" else -1
                base = self.rules.variant("credential_exfiltration", variant)["severity"]
                severity = bump(base, levels)
                factors.append(self.rules.factor("credential_exfiltration", "identity_only"))
            confidence = self.best_confidence(flows)
            if (sink.endpoint or len(factors) >= 2) and confidence == "low":
                confidence = "medium"
            self.add(
                "credential_exfiltration",
                variant,
                {
                    "source": self.describe_sources([raw.source for _, raw in group]),
                    "destination": (
                        (sink.url_domain or sink.url or "")
                        if variant == "known_endpoint"
                        else self.destination(sink)
                    ),
                    "endpoint": sink.endpoint or "",
                    "sink_api": sink.api,
                    "sink_line": sink.line,
                },
                confidence=confidence,
                count=len(group),
                script_index=sink.ctx.index if sink.ctx is not None else None,
                factors=factors,
                flow_ids=[flow.id for flow in flows],
                evidence=self._chain(group),
                severity=severity,
            )

    def _form_actions(self) -> None:
        credential_classes = set(self.rules.sources["credential_input"].get("field_classes") or [])
        for sink in self.facts.catalogue.sinks:
            if sink.sink_id != "form_action_external":
                continue
            selector = sink.detection.selector if sink.detection is not None else None
            classes = self.facts.fields.form_classes(selector) if selector else None
            if classes is None:
                credential = self.facts.fields.any_credential_form(credential_classes)
                fields = "the credential fields" if credential else "every field"
            else:
                found = sorted(c for c in classes if c in credential_classes)
                credential = bool(found)
                fields = "/".join(found) if found else "every field"
            submits = [
                s
                for s in self.facts.catalogue.sinks
                if s.sink_id == "form_submit" and s.ctx is sink.ctx
            ]
            evidence = [self.sink_evidence(sink)] + [self.sink_evidence(s) for s in submits[:2]]
            factors = []
            if sink.endpoint:
                factors.append(
                    self.rules.factor("credential_exfiltration", "known_endpoint").format(
                        endpoint=sink.endpoint
                    )
                )
            values = {
                "destination": self.destination(sink),
                "sink_line": sink.line,
                "sink_api": sink.api,
                "fields": fields,
                "source": f"the form ({selector or 'form.action changed'})",
            }
            self.add(
                "credential_exfiltration",
                "form_action" if credential else "form_data_external",
                values,
                confidence="low" if sink.confidence == "low" else ("high" if submits else "medium"),
                script_index=sink.ctx.index if sink.ctx is not None else None,
                factors=factors,
                evidence=evidence,
            )

    def _keylogging(self, items: list[tuple[Flow, RawFlow]]) -> None:
        for sink_id, group in self._group_by_sink(items).items():
            sink = self.facts.catalogue.sinks[sink_id]
            if sink.sink_id in NETWORK_SINKS or sink.api == "image_beacon":
                variant = "network"
            elif sink.sink_id == "storage_write":
                variant = "storage"
            else:
                continue
            flows = [flow for flow, _ in group]
            self.add(
                "keylogging",
                variant,
                {
                    "destination": self.destination(sink),
                    "sink_api": sink.api,
                    "sink_line": sink.line,
                },
                confidence=self.best_confidence(flows),
                count=len(group),
                script_index=sink.ctx.index if sink.ctx is not None else None,
                flow_ids=[flow.id for flow in flows],
                evidence=self._chain(group),
            )

    def _transmission(self, items: list[tuple[Flow, RawFlow]]) -> None:
        groups: dict[tuple[str, int], list[tuple[Flow, RawFlow]]] = defaultdict(list)
        for item in items:
            groups[(item[1].source.source_id, item[1].sink.id)].append(item)
        for (source_id, sink_id), group in groups.items():
            sink = self.facts.catalogue.sinks[sink_id]
            sensitive = self.rules.sensitivity(source_id) in ("high", "medium")
            flows = [flow for flow, _ in group]
            self.add(
                "external_data_transmission",
                "sensitive" if sensitive else "low_sensitivity",
                {
                    "source": self.describe_sources([raw.source for _, raw in group]),
                    "destination": self.destination(sink),
                    "sink_api": sink.api,
                    "sink_line": sink.line,
                },
                confidence=self.best_confidence(flows),
                count=len(group),
                script_index=sink.ctx.index if sink.ctx is not None else None,
                flow_ids=[flow.id for flow in flows],
                evidence=self._chain(group),
            )

    # ---- task 7 -------------------------------------------------------------------

    def _checks_before(self, sink: SinkRef) -> list[str]:
        """Fingerprint / referrer reads in the redirect's function, before it (cloaking)."""
        if sink.ctx is None or sink.node is None:
            return []
        function = sink.ctx.function_of(sink.node)
        start = function.start_byte if function is not None else 0
        checks = []
        for source in self.facts.catalogue.sources:
            if source.ctx is not sink.ctx or source.node is None:
                continue
            if source.source_id not in ("fingerprint", "referrer"):
                continue
            if start <= source.node.start_byte < sink.node.start_byte:
                if sink.ctx.function_of(source.node) == function or function is None:
                    checks.append(source.detail or source.source_id)
        return list(dict.fromkeys(checks))

    def _after_credentials(self, sink: SinkRef) -> bool:
        if sink.ctx is None or sink.node is None:
            return False
        chain = sink.ctx.function_chain(sink.node)
        if not chain:
            return False
        outer = chain[-1]
        for source in self.facts.catalogue.sources:
            if (
                source.source_id != "credential_input"
                or source.ctx is not sink.ctx
                or source.node is None
            ):
                continue
            if (
                outer.start_byte <= source.node.start_byte
                and source.node.end_byte <= outer.end_byte
            ):
                return True
        return False

    def forced_redirect(self) -> None:
        history = any(
            ctx.calls.get("history") or ctx.calls.get("popstate")
            for ctx in self.facts.contexts.values()
        )
        for sink in self.facts.catalogue.sinks:
            if sink.sink_id != "redirect_external":
                continue
            destination = self.destination(sink)
            base = {
                "destination": destination,
                "sink_line": sink.line,
                "trigger": self.trigger_text(sink),
            }
            if sink.api == "meta_refresh_tag":
                self.add(
                    "forced_redirect",
                    "meta_refresh",
                    {**base, "delay": sink.note or "0"},
                    confidence="high",
                    evidence=[self.sink_evidence(sink, "meta refresh in the HTML")],
                )
                continue
            checks = self._checks_before(sink)
            factors = []
            if checks:
                factors.append(
                    self.rules.factor("forced_redirect", "cloaking").format(
                        checks=", ".join(checks)
                    )
                )
            if history:
                factors.append(self.rules.factor("forced_redirect", "history"))
            auto = sink.trigger is not None and sink.trigger.kind == "auto"
            if self._after_credentials(sink):
                variant = "after_credentials"
            elif auto:
                variant = "automatic"
            elif history and sink.trigger is not None and sink.trigger.kind != "user":
                variant = "history_hijack"
            elif checks:
                variant = "cloaking"
            else:
                continue  # a redirect the user asked for (click handler)
            evidence = [self.sink_evidence(sink)]
            if checks:
                evidence = [
                    self.source_evidence(s, f"check: {s.detail}")
                    for s in self.facts.catalogue.sources
                    if s.ctx is sink.ctx
                    and (s.detail or s.source_id) in checks
                    and s.node is not None
                ][:3] + evidence
            self.add(
                "forced_redirect",
                variant,
                {**base, "checks": ", ".join(checks)},
                confidence="low" if sink.confidence == "low" else ("high" if auto else "medium"),
                script_index=sink.ctx.index if sink.ctx is not None else None,
                factors=factors,
                evidence=evidence,
            )

    # ---- task 8 -------------------------------------------------------------------

    def _strings(self, sink: SinkRef) -> list[str]:
        """Candidate clipboard contents: literal / constant data arguments; for
        execCommand('copy') the strings of the surrounding function (the selected text)."""
        ctx = sink.ctx
        if ctx is None or ctx.lexical or sink.node is None:
            return (
                [sink.detection.args.literal_value]
                if sink.detection and sink.detection.args and sink.detection.args.literal_value
                else []
            )
        values = []
        for node in sink.data_nodes:
            node, _ = sx.unwrap(node)
            if node is None:
                continue
            literal, _ = sx.literal_prefix(node)
            if literal is not None:
                values.append(literal)
            elif node.type == "identifier":
                values += [
                    value for value, _ in ctx.const_values(ctx.resolve(sx.text(node, 60), node))
                ]
        if not values:
            function = ctx.function_of(sink.node)
            start = function.start_byte if function is not None else 0
            end = function.end_byte if function is not None else len(ctx.src)
            values = [value for node, value in ctx.strings if start <= node.start_byte < end]
        return values[:50]

    def clipboard(self) -> None:
        for sink in self.facts.catalogue.sinks:
            if sink.sink_id != "clipboard_write":
                continue
            strings = self._strings(sink)
            event = sink.trigger.event if sink.trigger is not None else None
            kind = sink.trigger.kind if sink.trigger is not None else "unknown"
            in_copy = event in ("copy", "cut")
            base = {
                "sink_line": sink.line,
                "trigger": self.trigger_text(sink),
                "sink_api": sink.api,
            }
            evidence = [self.sink_evidence(sink)]
            confidence = "low" if sink.confidence == "low" else "high"
            clickfix = next(
                (
                    name
                    for value in strings
                    for name, regex in self.rules.clickfix
                    if regex.search(value)
                ),
                None,
            )
            if clickfix:
                self.add(
                    "clipboard_manipulation",
                    "clickfix",
                    {**base, "kind": clickfix},
                    confidence=confidence,
                    evidence=evidence,
                    script_index=sink.ctx.index if sink.ctx else None,
                )
                continue
            crypto = next(
                (
                    name
                    for value in strings
                    for name, regex in self.rules.crypto
                    if regex.match(value.strip())
                ),
                None,
            )
            if crypto:
                variant = "crypto_hijack" if (kind == "auto" or in_copy) else "crypto_on_click"
                self.add(
                    "clipboard_manipulation",
                    variant,
                    {**base, "kind": crypto},
                    confidence=confidence,
                    evidence=evidence,
                    script_index=sink.ctx.index if sink.ctx else None,
                )
                continue
            if sink.api == "clipboardData.setData" and in_copy:
                self.add(
                    "clipboard_manipulation",
                    "copy_rewrite",
                    base,
                    confidence=confidence,
                    evidence=evidence,
                    script_index=sink.ctx.index if sink.ctx else None,
                )

    def _clipboard_flows(self, items: list[tuple[Flow, RawFlow]]) -> None:
        for sink_id, group in self._group_by_sink(items).items():
            sink = self.facts.catalogue.sinks[sink_id]
            if sink.sink_id not in NETWORK_SINKS:
                continue
            flows = [flow for flow, _ in group]
            self.add(
                "clipboard_manipulation",
                "clipboard_exfiltration",
                {
                    "destination": self.destination(sink),
                    "sink_api": sink.api,
                    "sink_line": sink.line,
                },
                confidence=self.best_confidence(flows),
                count=len(group),
                script_index=sink.ctx.index if sink.ctx is not None else None,
                flow_ids=[flow.id for flow in flows],
                evidence=self._chain(group),
            )

    # ---- task 9 -------------------------------------------------------------------

    def _extension(self, value: str | None) -> str | None:
        if not value:
            return None
        path = value.split("?")[0].split("#")[0].rstrip("/")
        name = path.rsplit("/", 1)[-1]
        if "." not in name:
            return None
        return name.rsplit(".", 1)[-1].lower()[:10]

    def download(self) -> None:
        risky = self.rules.risky_extensions
        decoded_sinks = {
            raw.sink.id
            for _, raw in self.facts.flows
            if raw.source.source_id == "decoded_string" and raw.sink.sink_id == "download"
        }
        by_script: dict[int, list[SinkRef]] = defaultdict(list)
        for sink in self.facts.catalogue.sinks:
            if sink.ctx is None:
                continue
            if sink.sink_id == "download":
                by_script[sink.ctx.index].append(sink)
            elif sink.api in (
                "location.href",
                "location.assign",
                "location.replace",
                "window.open",
            ):
                if self._extension(sink.url) in risky:
                    by_script[sink.ctx.index].append(sink)
        for script, sinks in by_script.items():
            ctx = self.facts.contexts.get(script)
            files: list[str] = []
            for sink in sinks:
                files += self._strings(sink) if sink.api == "download_attribute" else []
                if sink.api == "msSaveBlob" and sink.node is not None:
                    args = sx.named_args(sink.node)
                    if len(args) > 1:
                        literal, _ = sx.literal_prefix(args[1])
                        files += [literal] if literal else []
                if sink.url:
                    files.append(sink.url)
            if ctx is not None and not ctx.lexical:
                files += [value for _, value in ctx.href_assigns]
            risky_files = [f for f in files if self._extension(f) in risky]
            decoded = any(s.id in decoded_sinks for s in sinks)
            if not risky_files and not decoded:
                continue
            triggers = [s.trigger for s in sinks if s.trigger is not None]
            if ctx is not None and not ctx.lexical:
                for node in ctx.calls.get("click", []):
                    triggers.append(self._resolver_trigger(ctx, node))
            auto = next((t for t in triggers if t is not None and t.kind == "auto"), None)
            trigger = auto or next((t for t in triggers if t is not None), None)
            factors = []
            if decoded:
                factors.append(self.rules.factor("suspicious_download", "decoded"))
            if auto is not None:
                factors.append(
                    self.rules.factor("suspicious_download", "auto").format(trigger=auto.reason)
                )
            if risky_files:
                name = risky_files[0].rsplit("/", 1)[-1].split("?")[0][:80]
                variant = "auto_risky" if auto is not None else "user_risky"
                severity = self.rules.variant("suspicious_download", variant)["severity"]
                severity = bump(severity) if decoded else severity
                values = {"file": name, "extension": self._extension(name)}
            elif auto is not None:
                variant, severity, values = "decoded_blob", None, {}
            else:
                continue
            main = sinks[0]
            self.add(
                "suspicious_download",
                variant,
                {
                    **values,
                    "trigger": trigger.reason if trigger else "trigger unknown",
                    "sink_line": main.line,
                },
                confidence="low" if all(s.confidence == "low" for s in sinks) else "high",
                count=len(sinks),
                script_index=script,
                factors=factors,
                severity=severity,
                evidence=[self.sink_evidence(s) for s in sinks[:5]],
            )

    def _resolver_trigger(self, ctx: ScriptCtx, node: Any):
        return self.triggers.for_node(ctx, node) if self.triggers is not None else None

    # ---- task 10 ------------------------------------------------------------------

    def obfuscation(self) -> None:
        settings = self.rules.patterns["obfuscated_execution"]
        covered: set[int] = set()
        decoded = [
            (flow, raw)
            for flow, raw in self.facts.flows
            if raw.source.source_id == "decoded_string"
            and raw.sink.sink_id in ("code_execution", "html_injection")
        ]
        for sink_id, group in self._group_by_sink(decoded).items():
            sink = self.facts.catalogue.sinks[sink_id]
            lexical = all(raw.lexical for _, raw in group)
            severity, active = None, ""
            if lexical:
                variant = "lexical"
            elif sink.sink_id == "code_execution":
                variant = "decode_to_exec"
                if min(len(flow.path) for flow, _ in group) > self.max_exec_steps:
                    severity = "medium"  # through a long chain of calls: imprecise
            else:
                # decoded HTML: only high when the decoded literal contains active content
                previews = [raw.source.preview for _, raw in group]
                hits = [self.active_content.search(p) for p in previews if p]
                hits = [hit for hit in hits if hit]
                if hits:
                    variant, active = "decode_to_html", f"'{hits[0].group()[:30]}'"
                    group = [
                        item
                        for item in group
                        if item[1].source.preview
                        and self.active_content.search(item[1].source.preview)
                    ]
                elif any(p is None for p in previews):
                    variant = "decode_to_html_dynamic"
                    group = [item for item in group if item[1].source.preview is None]
                else:
                    continue  # decoded CSS / plain markup (plugins do this): not obfuscation
            flows = [flow for flow, _ in group]
            decoders = ", ".join(dict.fromkeys(raw.source.api for _, raw in group))
            self.add(
                "obfuscated_execution",
                variant,
                {
                    "decoder": decoders,
                    "executor": sink.api,
                    "sink_line": sink.line,
                    "active": active,
                },
                confidence="low" if lexical else self.best_confidence(flows),
                count=len(group),
                script_index=sink.ctx.index if sink.ctx is not None else None,
                flow_ids=[flow.id for flow in flows],
                evidence=self._chain(group),
                severity=severity,
            )
            if sink.ctx is not None:
                covered.add(sink.ctx.index)
        scripts = {s.index: s for s in self.facts.js.scripts}
        for sink in self.facts.catalogue.sinks:
            if sink.sink_id != "code_execution" or sink.ctx is None or sink.ctx.index in covered:
                continue
            info = scripts.get(sink.ctx.index)
            stats = info.obfuscation if info is not None else None
            if stats is None:
                continue
            signatures = list(stats.signatures)
            if stats.entropy >= float(settings.get("high_entropy", 5.5)) and stats.chars >= int(
                settings.get("high_entropy_min_chars", 2000)
            ):
                signatures.append(f"entropy {stats.entropy:.2f}")
            if not signatures:
                continue
            covered.add(sink.ctx.index)
            self.add(
                "obfuscated_execution",
                "packed_eval",
                {"signatures": ", ".join(signatures), "executor": sink.api, "sink_line": sink.line},
                confidence="low" if sink.confidence == "low" else "medium",
                script_index=sink.ctx.index,
                evidence=[
                    EvidenceItem(
                        kind="script",
                        script_index=sink.ctx.index,
                        code=f"{info.origin}: {', '.join(signatures)}",
                        note="Part 7 obfuscation statistics",
                    ),
                    self.sink_evidence(sink),
                ],
            )

    # ---- extra: anti-analysis -------------------------------------------------------

    def anti_analysis(self) -> None:
        techniques: dict[str, list[EvidenceItem]] = {}

        def note(name: str, item: EvidenceItem) -> None:
            techniques.setdefault(name, []).append(item)

        for ctx in self.facts.contexts.values():
            for detection in ctx.detections:
                if detection.api == "contextmenu_listener" and not detection.in_library:
                    note("right-click blocked", self._detection_item(ctx, detection))
            if ctx.unit.source == "event_handler" and ctx.unit.attribute in (
                "onselectstart",
                "ondragstart",
            ):
                note(
                    "text selection blocked",
                    EvidenceItem(
                        kind="script",
                        script_index=ctx.index,
                        code=ctx.code(ctx.tree.root_node) if ctx.tree else ctx.unit.text[:120],
                        note=ctx.unit.origin,
                    ),
                )
            if ctx.lexical:
                continue
            for node in ctx.calls.get("selection", []):
                note("text selection blocked", self._node_item(ctx, node, "selection"))
            for node in ctx.devtools_checks:
                note("DevTools size check", self._node_item(ctx, node, "outer - inner size"))
            for node in ctx.debugger_nodes:
                looped = self._in_loop_or_timer(ctx, node)
                if looped:
                    note("debugger trap", self._node_item(ctx, node, looped))
        for detection_ctx, function, _param, _selector in self.facts.catalogue.key_callbacks:
            text = (
                sx.text(function, 20000)
                if function is not None
                else detection_ctx.unit.text[:20000]
            )
            keys = []
            if F12.search(text):
                keys.append("F12")
            if "ctrlKey" in text and "shiftKey" in text and CTRL_SHIFT.search(text):
                keys.append("Ctrl+Shift+I/J/C")
            if "ctrlKey" in text and CTRL_U.search(text):
                keys.append("Ctrl+U")
            if keys and (
                "preventDefault" in text or "return false" in text or "returnValue" in text
            ):
                node = function if function is not None else None
                item = (
                    self._node_item(detection_ctx, node, ", ".join(keys))
                    if node is not None
                    else EvidenceItem(
                        kind="script",
                        script_index=detection_ctx.index,
                        code=detection_ctx.unit.text[:120],
                        note=", ".join(keys),
                    )
                )
                note("DevTools keys blocked", item)
        if not techniques:
            return
        names = list(techniques)
        self.add(
            "anti_analysis",
            "several" if len(names) > 1 else "one",
            {"techniques": ", ".join(names), "count": len(names)},
            confidence="high",
            count=len(names),
            evidence=[items[0] for items in techniques.values()][:6],
        )

    def _in_loop_or_timer(self, ctx: ScriptCtx, node: Any) -> str | None:
        current = node.parent
        for _ in range(200):
            if current is None:
                return None
            if current.type in LOOPS:
                return "debugger inside a loop"
            if current.type in sx.FUNCTION_TYPES:
                parent = current.parent
                if parent is not None and parent.type == "arguments" and parent.parent is not None:
                    callee = sx.raw_path(sx.field(parent.parent, "function")) or []
                    if callee and callee[-1] in ("setInterval", "setTimeout"):
                        return f"debugger in a {callee[-1]} callback"
            current = current.parent
        return None

    def _node_item(self, ctx: ScriptCtx, node: Any, note: str) -> EvidenceItem:
        line, column = ctx.position(node)
        return EvidenceItem(
            kind="detection",
            script_index=ctx.index,
            line=line,
            column=column,
            code=ctx.code(node),
            note=note,
        )

    @staticmethod
    def _detection_item(ctx: ScriptCtx, detection) -> EvidenceItem:
        return EvidenceItem(
            kind="detection",
            script_index=ctx.index,
            line=detection.line,
            column=detection.column,
            code=detection.snippet[:120],
            note=detection.api,
        )

    # ---- all ----------------------------------------------------------------------

    def run(self) -> list[Finding]:
        self.credential_access()
        self.exfiltration()
        self.forced_redirect()
        self.clipboard()
        self.download()
        self.obfuscation()
        self.anti_analysis()
        order = {pattern: i for i, pattern in enumerate(PATTERN_IDS)}
        self.facts.findings.sort(
            key=lambda f: (-f.severity_score, -CONFIDENCE_ORDER[f.confidence], order[f.pattern_id])
        )
        return self.facts.findings
