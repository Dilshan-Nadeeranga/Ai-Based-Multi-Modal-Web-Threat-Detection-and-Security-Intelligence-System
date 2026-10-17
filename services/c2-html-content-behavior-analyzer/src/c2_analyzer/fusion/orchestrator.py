"""End-to-end analysis of one page: fetch -> Part 2 -> 3 -> 5A -> 6A -> 7 -> 8 -> 9A fusion.

Part 9: Batch B-1 - end-to-end URL analysis engine.

``Orchestrator.analyze`` runs every part through its PUBLIC function (nothing is
re-implemented here) on ONE parsed page, then fuses the arms with the saved 9A model and
applies the verdict policy (fusion/verdict.py).

Graceful degradation (viva): the parts are independent analyzers of the same page. If
one raises (a hostile page can break any parser) or its model is missing, that modality
is marked ``failed`` / ``skipped`` with the reason, the late-fusion weights are
renormalized over the arms that DID answer, the thresholds calibrated for exactly that
arm subset are used, and the response says ``degraded: true``. Only when no arm answers
and no evidence-floor rule fires is there no verdict (status "error").

Models are loaded once (``ServingModels.load``, at API start-up in a background thread)
and shared by all requests; XLM-R is optional (XLMR_ENABLED, CPU). Each step is timed
(``timings_ms``) and checks the request's time budget before it starts.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import numpy as np

from c2_analyzer import __version__
from c2_analyzer.behavior.baseline import BEHAVIOR_SOURCE
from c2_analyzer.behavior.baseline import fingerprint as behavior_fingerprint
from c2_analyzer.behavior.pipeline import map_behavior
from c2_analyzer.classifiers.dom_baseline.common import BaselineConfig, load_bundles
from c2_analyzer.classifiers.dom_baseline.predict import best_model, predict_features
from c2_analyzer.config import get_settings
from c2_analyzer.content.extractor import extract_content
from c2_analyzer.dataset.page_view import parse_page
from c2_analyzer.dataset.quality import check_page
from c2_analyzer.dom.dictionary import dictionary_hash
from c2_analyzer.dom.pipeline import extract_dom_features
from c2_analyzer.fusion.aggregator import (
    behavior_findings,
    content_findings,
    dom_findings,
    rank,
    safe_evidence,
)
from c2_analyzer.fusion.calibration import fuse_arms, fusion_fingerprint, is_exact, subset_weights
from c2_analyzer.fusion.common import ARM_ORDER, FusionConfig
from c2_analyzer.fusion.live_fetch import LiveFetcher, analyze_config
from c2_analyzer.fusion.model import load_bundle, restore
from c2_analyzer.fusion.strategies import FusionInputs
from c2_analyzer.fusion.verdict import FloorHit, VerdictPolicy, decide, floor_hits, subset_key
from c2_analyzer.js_analyzer.pipeline import analyze_js
from c2_analyzer.nlp.inference import TextModels
from c2_analyzer.preprocessing.loader import from_string
from c2_analyzer.preprocessing.pipeline import preprocess
from c2_analyzer.schemas.analysis import (
    SCHEMA_VERSION,
    AnalysisFinding,
    AnalysisInput,
    AnalysisRequest,
    AnalysisResponse,
    ArmResult,
    Explanation,
    FeatureDriver,
    Modalities,
    ModalityResult,
    ReadyResponse,
)
from c2_analyzer.utils.pii import mask_url

ARM_MODALITY = {
    "dom": "dom",
    "behavior": "behavior",
    "text_tfidf": "content",
    "text_xlmr": "content",
}
TEXT_MODEL_ARM = {"tfidf_logreg": "text_tfidf", "xlmr": "text_xlmr"}


class BudgetExceeded(Exception):
    """The request ran out of time; ``response`` holds what was finished."""

    def __init__(self, response: AnalysisResponse) -> None:
        super().__init__(response.status_reason)
        self.response = response


class _OutOfTime(Exception):
    pass


# ---- the loaded models ----------------------------------------------------------------------


@dataclass
class ServingModels:
    """Everything loaded once and shared by all requests (read-only after load)."""

    version: str
    xlmr_enabled: bool
    fusion_config: FusionConfig
    policy: VerdictPolicy
    fusion_bundle: dict | None = None
    fusion_model: Any = None
    dom_bundles: dict = field(default_factory=dict)
    behavior_bundles: dict = field(default_factory=dict)
    text: TextModels | None = None
    arm_status: dict[str, str | None] = field(default_factory=dict)  # arm -> None (ok) / reason
    problems: list[str] = field(default_factory=list)  # anything that blocks verdicts
    warnings: list[str] = field(default_factory=list)
    load_ms: float = 0.0

    @classmethod
    def load(
        cls,
        version: str | None = None,
        xlmr_enabled: bool | None = None,
        text: TextModels | None = None,
    ) -> ServingModels:
        started = time.perf_counter()
        version = version or str(analyze_config()["serving_version"])
        enabled = get_settings().xlmr_enabled if xlmr_enabled is None else xlmr_enabled
        models = cls(version, enabled, FusionConfig.load(), VerdictPolicy.load())
        models._load_fusion()
        models._load_tabular("dom", BaselineConfig.load(), dictionary_hash())
        models._load_tabular(
            "behavior", BaselineConfig.load(BEHAVIOR_SOURCE), behavior_fingerprint()
        )
        models.text = text or TextModels.from_config(version)
        for name, reason in models.text.warm_up(xlmr=enabled).items():
            models.arm_status[TEXT_MODEL_ARM[name]] = reason
        models._check_arm_versions()
        models.load_ms = round((time.perf_counter() - started) * 1000, 1)
        return models

    def _load_fusion(self) -> None:
        bundle = load_bundle(self.fusion_config.models_dir(self.version))
        if bundle is None:
            self.problems.append(f"no fusion model for {self.version} (run run_ablation.py)")
            return
        self.fusion_bundle, self.fusion_model = bundle, restore(bundle)
        calibration = self.policy.calibration
        if calibration.get("fusion_fingerprint") != fusion_fingerprint(bundle):
            self.problems.append(
                "configs/verdict.yaml thresholds were calibrated for another fusion model - run "
                f"scripts/calibrate_verdict.py --version {self.version}"
            )
        missing = [
            subset_key(arms)
            for arms in ([bundle["arms"]] + [[a] for a in bundle["arms"]])
            if subset_key(arms) not in self.policy.thresholds
        ]
        if missing:
            self.problems.append(f"no verdict thresholds for {', '.join(missing)}")

    def _load_tabular(self, arm: str, config: BaselineConfig, current_hash: str) -> None:
        try:
            bundles = load_bundles(config, self.version)
        except Exception as error:  # noqa: BLE001 - a broken file = this arm unavailable
            self.arm_status[arm] = f"model not available: {type(error).__name__}"
            return
        if not bundles:
            self.arm_status[arm] = f"model not available: no {arm} model for {self.version}"
            return
        if next(iter(bundles.values()))["dictionary_hash"] != current_hash:
            self.arm_status[arm] = "model not available: trained on another feature set - retrain"
            return
        if arm == "dom":
            self.dom_bundles = bundles
        else:
            self.behavior_bundles = bundles
        self.arm_status[arm] = None

    def _check_arm_versions(self) -> None:
        """Warn when an arm model was retrained after the fusion model was fitted."""
        if not self.fusion_bundle:
            return
        card_path = self.fusion_config.models_dir(self.version) / "model_card.json"
        try:
            import json

            card = json.loads(card_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        for arm, bundles in (("dom", self.dom_bundles), ("behavior", self.behavior_bundles)):
            expected = card.get("arm_models", {}).get(arm, {}).get("model_trained_at")
            best = self.best_bundle(bundles)
            if expected and best and best.get("trained_at") != expected:
                self.warnings.append(
                    f"{arm} model was retrained after the fusion model - re-run run_ablation.py"
                )

    def predict_tabular(self, arm: str, features: dict):
        """Part 4 / Part 8 arm on one feature dict (Part 4's ``predict_features``)."""
        if arm == "dom":
            bundles, current = self.dom_bundles, dictionary_hash()
        else:
            bundles, current = self.behavior_bundles, behavior_fingerprint()
        return predict_features(
            features, bundles, version=self.version, dictionary_hash=current, top=3
        )

    @staticmethod
    def best_bundle(bundles: dict) -> dict | None:
        """The bundle predict_features uses (best mean CV macro-F1, Part 4's rule)."""
        return bundles[best_model(bundles)] if bundles else None

    @property
    def labels(self) -> list[str]:
        return list(self.fusion_bundle["labels"]) if self.fusion_bundle else []

    @property
    def fusion_arms(self) -> list[str]:
        return list(self.fusion_bundle["arms"]) if self.fusion_bundle else []

    def versions(self) -> dict[str, str | None]:
        def tabular(bundles: dict) -> str | None:
            best = self.best_bundle(bundles)
            return f"{best['model']}@{best['trained_at']}" if best else None

        info = self.text.model_info() if self.text else {}
        xlmr = info.get("xlmr")
        tfidf = info.get("tfidf_logreg")
        fusion = self.fusion_bundle
        return {
            "analyzer": __version__,
            "schema": SCHEMA_VERSION,
            "dataset": self.version,
            "dom": tabular(self.dom_bundles),
            "behavior": tabular(self.behavior_bundles),
            "text_tfidf": f"tfidf_logreg@{tfidf['trained_at']}" if tfidf else None,
            "text_xlmr": f"xlm-roberta-base fine-tuned (seed {xlmr['seed']})" if xlmr else None,
            "fusion": f"{fusion['strategy']}@{fusion.get('trained_at')}" if fusion else None,
            "verdict_thresholds": self.policy.calibration.get("created_at"),
        }

    def ready(self) -> ReadyResponse:
        arms = {
            arm: {"loaded": self.arm_status.get(arm) is None, "reason": self.arm_status.get(arm)}
            for arm in ARM_ORDER
        }
        usable = [arm for arm, s in arms.items() if s["loaded"]]
        reason = "; ".join(self.problems) or (None if usable else "no model arm is loaded")
        return ReadyResponse(
            ready=not self.problems and bool(usable),
            reason=reason,
            xlmr_enabled=self.xlmr_enabled,
            arms=arms,
            model_versions=self.versions(),
            load_ms=self.load_ms,
        )


# ---- one request -------------------------------------------------------------------------


@dataclass
class _Run:
    """State of one analysis (collected step by step, then turned into the response)."""

    request: AnalysisRequest
    deadline: float
    started: float = field(default_factory=time.perf_counter)
    timings: dict[str, float] = field(default_factory=dict)
    input: AnalysisInput | None = None
    findings: list[AnalysisFinding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    modality: dict[str, ModalityResult] = field(default_factory=dict)
    arms: dict[str, ArmResult] = field(default_factory=dict)
    arm_proba: dict[str, np.ndarray] = field(default_factory=dict)
    drivers: list[FeatureDriver] = field(default_factory=list)
    dom_features: dict[str, float] | None = None
    dom_evidence: dict[str, str] = field(default_factory=dict)
    behavior_keys: list[tuple[str, str, str | None]] | None = None
    download_kind: str | None = None
    page_language: str | None = None
    last_step: str = ""

    def step(self, name: str, function: Callable[[], Any]) -> tuple[Any, str | None]:
        """Run one step: (result, None) or (None, "ErrorType: message"). Times it."""
        if time.perf_counter() > self.deadline:
            raise _OutOfTime(name)
        self.last_step = name
        started = time.perf_counter()
        try:
            return function(), None
        except Exception as error:  # noqa: BLE001 - one part must not fail the request
            return None, f"{type(error).__name__}: {str(error)[:200]}"
        finally:
            self.timings[name] = round((time.perf_counter() - started) * 1000, 1)


class Orchestrator:
    """Holds the loaded models (+ the live fetcher) and analyzes one page per call."""

    def __init__(self, models: ServingModels, fetcher: LiveFetcher | None = None) -> None:
        self.models = models
        self._fetcher = fetcher
        self._fetcher_lock = threading.Lock()
        config = analyze_config()
        self.budget = float(config["time_budget_seconds"])
        self.max_findings = int(config["response"]["max_findings"])
        self.evidence_chars = int(config["response"]["max_evidence_chars"])
        self.inconclusive_flags = set(config["inconclusive_quality_flags"])
        self.language_warnings = dict(config.get("language_warnings", {}))

    @classmethod
    def load(cls, xlmr_enabled: bool | None = None) -> Orchestrator:
        return cls(ServingModels.load(xlmr_enabled=xlmr_enabled))

    @property
    def fetcher(self) -> LiveFetcher:
        with self._fetcher_lock:
            if self._fetcher is None:
                self._fetcher = LiveFetcher()
            return self._fetcher

    # ---- public ---------------------------------------------------------------------

    def analyze(self, request: AnalysisRequest, budget: float | None = None) -> AnalysisResponse:
        """Analyze one page. Raises BudgetExceeded (with the partial result) on timeout."""
        run = _Run(request, deadline=time.perf_counter() + (budget or self.budget))
        try:
            return self._analyze(run)
        except _OutOfTime as late:
            response = self._response(
                run,
                status="error",
                reason=f"time budget of {budget or self.budget:g} s exceeded before step "
                f"'{late.args[0]}' - partial result",
            )
            raise BudgetExceeded(response) from None

    # ---- pipeline ---------------------------------------------------------------------

    def _analyze(self, run: _Run) -> AnalysisResponse:
        request = run.request
        if request.mode == "url":
            outcome, error = run.step("fetch", lambda: self.fetcher.fetch(request.url))
            if error:
                return self._no_page(run, "error", f"fetch failed: {error}")
            run.input = AnalysisInput(
                mode="url",
                submitted_url=mask_url(request.url),
                final_url=outcome.masked_final_url,
                redirect_hosts=outcome.redirect_hosts,
                http_status=outcome.http_status,
                content_type=outcome.content_type,
            )
            self._fetch_findings(run, outcome)
            if outcome.status in ("blocked", "unreachable"):
                return self._no_page(run, "unreachable", outcome.reason)
            if outcome.status == "download":
                # No page, but the evidence floor (fetch.executable_download) decides.
                run.download_kind = outcome.download_kind
                return self._no_page(run, "ok", outcome.reason)
            if outcome.status == "not_html":
                return self._no_page(run, "inconclusive", outcome.reason)
            html, page_url = outcome.html or "", outcome.final_url or request.url
        else:
            html, page_url = request.html or "", request.url
            run.input = AnalysisInput(mode="html", submitted_url=mask_url(request.url))
        run.input.html_bytes = len(html.encode("utf-8", errors="ignore"))

        def parse():
            raw = from_string(html, page_url)
            return raw, preprocess(raw)

        parsed, error = run.step("preprocess", parse)
        if error:
            return self._no_page(run, "error", f"the HTML could not be parsed ({error})")
        raw, page = parsed

        def quality():
            view = parse_page(raw.html, page_url)
            return check_page(view, raw.html, "unknown"), view.has_password_field

        checked, _ = run.step("quality", quality)
        flag, asks_password = checked or ("ok", False)

        self._dom(run, page, raw.html)
        self._content(run, page, raw.html)
        self._behavior(run, page)

        status, reason = "ok", None
        if flag in self.inconclusive_flags and asks_password:
            # Parking / suspended-hosting / challenge placeholders never ask for a password,
            # but phishing lures say "your account has been suspended" all the time.
            run.warnings.append(
                f"The page text matches Part 1's '{flag}' placeholder wording, but it asks for "
                "a password, so it is analyzed as a real page."
            )
        elif flag in self.inconclusive_flags:
            status = "inconclusive"
            reason = f"the page looks like a {flag.replace('_', ' ')} page (Part 1 quality check)"
            run.warnings.append(
                f"Inconclusive: {reason} - it is probably not the content the URL normally "
                "serves (static fetch, no JavaScript)."
            )
        return self._finish(run, status, reason)

    def _no_page(self, run: _Run, status: str, reason: str | None) -> AnalysisResponse:
        """No HTML to analyze (unreachable / download / not HTML / parse error)."""
        why = {"unreachable": "the page could not be fetched", "error": "analysis failed"}.get(
            status, f"no web page to analyze ({reason})"
        )
        for name in ("dom", "content", "behavior"):
            run.modality[name] = ModalityResult(status="skipped", reason=why)
        return self._finish(run, status, reason)

    # ---- modalities ----------------------------------------------------------------------

    def _tabular_arm(self, run: _Run, arm: str, features: dict):
        status = self.models.arm_status.get(arm)
        display = self.models.fusion_config.arm_display(arm)
        if status is not None:
            run.arms[arm] = ArmResult(arm=arm, display=display, status="skipped", reason=status)
            return None
        prediction, error = run.step(
            f"{arm}_model", lambda: self.models.predict_tabular(arm, features)
        )
        if error:
            run.arms[arm] = ArmResult(arm=arm, display=display, status="failed", reason=error)
            return None
        self._set_arm(run, arm, display, prediction.probabilities)
        for c in prediction.contributions:
            run.drivers.append(
                FeatureDriver(
                    arm=arm,
                    feature=c.feature,
                    value=float(c.value),
                    contribution=float(c.contribution),
                    text=safe_evidence(c.text, 240) or c.feature,
                )
            )
        return prediction

    def _set_arm(self, run: _Run, arm: str, display: str, probabilities: dict) -> None:
        labels = self.models.labels
        vector = np.array([float(probabilities.get(label, 0.0)) for label in labels])
        if not np.isfinite(vector).all() or vector.sum() <= 0:
            run.arms[arm] = ArmResult(
                arm=arm, display=display, status="failed", reason="invalid probabilities"
            )
            return
        vector = vector / vector.sum()
        run.arm_proba[arm] = vector
        run.arms[arm] = ArmResult(
            arm=arm,
            display=display,
            status="ok",
            predicted=labels[int(vector.argmax())],
            probabilities={
                label: round(float(p), 6) for label, p in zip(labels, vector, strict=True)
            },
        )

    def _dom(self, run: _Run, page, html: str) -> None:
        result, error = run.step("dom_features", lambda: extract_dom_features(page, html))
        if error:
            run.modality["dom"] = ModalityResult(status="failed", reason=error)
            run.arms["dom"] = ArmResult(
                arm="dom", display="DOM-only", status="skipped", reason="no DOM features"
            )
            return
        run.dom_features = dict(result.features)
        findings, run.dom_evidence = dom_findings(result, self.evidence_chars)
        run.findings.extend(findings)
        prediction = self._tabular_arm(run, "dom", result.features)
        strong = [f for f in findings if f.severity == "high"]
        summary = f"{len(findings)} structural finding(s) ({len(strong)} high)"
        if prediction is not None:
            summary += f"; DOM model: {_vote(prediction)}"
        if result.errors:
            summary += f"; {len(result.errors)} feature group(s) failed"
        run.modality["dom"] = ModalityResult(
            status="ok",
            summary=summary,
            top_evidence=[f.title for f in findings[:3]],
            arms=[run.arms["dom"]],
        )

    def _content(self, run: _Run, page, html: str) -> None:
        text, error = run.step("content", lambda: extract_content(page, html))
        if error:
            run.modality["content"] = ModalityResult(status="failed", reason=error)
            for arm in ("text_tfidf", "text_xlmr"):
                run.arms[arm] = ArmResult(
                    arm=arm,
                    display=self.models.fusion_config.arm_display(arm),
                    status="skipped",
                    reason="no page text",
                )
            return
        run.page_language = text.language.language
        warning = self.language_warnings.get(run.page_language)
        if warning:
            run.warnings.append(warning)
        outputs, error = (None, "text models not loaded")
        if self.models.text is not None:
            outputs, error = run.step(
                "text_models",
                lambda: self.models.text.predict_many(
                    [text.page_text], xlmr=self.models.xlmr_enabled
                )[0],
            )
        text_arms: dict[str, dict] = {}
        notes = []
        for name, arm in TEXT_MODEL_ARM.items():
            display = self.models.fusion_config.arm_display(arm)
            output = next((o for o in outputs or [] if o.model == name), None)
            if output is None:
                run.arms[arm] = ArmResult(arm=arm, display=display, status="failed", reason=error)
                continue
            if not output.available:
                state = "skipped" if "disabled" in (output.reason or "") else "failed"
                run.arms[arm] = ArmResult(
                    arm=arm, display=display, status=state, reason=output.reason
                )
                continue
            self._set_arm(run, arm, display, output.probabilities or {})
            if run.arms[arm].status == "ok":
                text_arms[arm] = run.arms[arm].model_dump() | {"display": display}
            if output.truncated:
                notes.append(f"{display} input truncated ({output.input_tokens} tokens)")
        findings = content_findings(text, text_arms, self.evidence_chars)
        run.findings.extend(findings)
        votes = "; ".join(
            f"{a['display']}: {a['predicted']} {a['probabilities'][a['predicted']]:.0%}"
            for a in text_arms.values()
        )
        summary = (
            f"language {run.page_language} ({text.language.confidence:.0%}); "
            f"{text.page_text_chars} chars of model text"
            + (f"; {votes}" if votes else "")
            + (f"; {', '.join(notes)}" if notes else "")
        )
        run.modality["content"] = ModalityResult(
            status="ok",
            summary=summary,
            top_evidence=[f.evidence or f.title for f in findings[:3]],
            arms=[run.arms["text_tfidf"], run.arms["text_xlmr"]],
        )

    def _behavior(self, run: _Run, page) -> None:
        js, error = run.step("js_analysis", lambda: analyze_js(page))
        behavior = None
        if not error:
            behavior, error = run.step("behavior", lambda: map_behavior(page, js))
        if error:
            run.modality["behavior"] = ModalityResult(status="failed", reason=error)
            run.arms["behavior"] = ArmResult(
                arm="behavior", display="Behavior-only", status="skipped", reason="no JS analysis"
            )
            return
        findings, run.behavior_keys = behavior_findings(behavior, self.evidence_chars)
        run.findings.extend(findings)
        features = {**js.features, **behavior.intent_vector}
        prediction = self._tabular_arm(run, "behavior", features)
        summary = (
            f"{behavior.summary.scripts_analyzed + behavior.summary.scripts_lexical} script(s), "
            f"{behavior.summary.flows_total} source->sink flow(s), {len(findings)} finding(s); "
            f"behavior risk {behavior.behavior_risk_score:.0f}"
        )
        if prediction is not None:
            summary += f"; behavior model: {_vote(prediction)}"
        run.modality["behavior"] = ModalityResult(
            status="ok",
            summary=summary,
            top_evidence=[f.detail for f in findings[:3]],
            arms=[run.arms["behavior"]],
        )

    def _fetch_findings(self, run: _Run, outcome) -> None:
        if outcome.status == "download":
            run.findings.append(
                AnalysisFinding(
                    id="fetch.executable_download",
                    modality="fetch",
                    severity="critical",
                    title=f"URL serves a {outcome.download_kind} file instead of a webpage",
                    detail="Opening this link downloads a program / archive rather than "
                    "showing a page - a typical malware delivery link. C2 did not download it.",
                    evidence=safe_evidence(_host(outcome.final_url), self.evidence_chars),
                )
            )
        elif outcome.status == "blocked":
            run.findings.append(
                AnalysisFinding(
                    id="fetch.blocked",
                    modality="fetch",
                    severity="medium",
                    title="Fetch refused: the URL leads to a private / internal address",
                    detail="C2 never requests addresses inside a private network (SSRF "
                    f"protection): {outcome.reason}.",
                    evidence=safe_evidence(_host(outcome.submitted_url), self.evidence_chars),
                )
            )
        elif outcome.status == "unreachable":
            run.findings.append(
                AnalysisFinding(
                    id="fetch.unreachable",
                    modality="fetch",
                    severity="info",
                    title="The page could not be fetched",
                    detail=f"{outcome.reason}. Scam pages are often taken down quickly; no "
                    "verdict is given for a page C2 could not see.",
                    evidence=safe_evidence(_host(outcome.submitted_url), self.evidence_chars),
                )
            )
        elif outcome.status == "not_html":
            run.findings.append(
                AnalysisFinding(
                    id="fetch.not_html",
                    modality="fetch",
                    severity="info",
                    title="The URL does not serve a web page",
                    detail=f"{outcome.reason}.",
                    evidence=safe_evidence(outcome.content_type, self.evidence_chars),
                )
            )
        hosts = list(dict.fromkeys(outcome.redirect_hosts))
        if len(hosts) > 1:
            run.findings.append(
                AnalysisFinding(
                    id="fetch.cross_host_redirect",
                    modality="fetch",
                    severity="low",
                    title=f"Redirected across {len(hosts)} hosts",
                    detail="The link forwards the visitor through other sites before the page "
                    "(common in scam links that hide the final address).",
                    evidence=safe_evidence(" -> ".join(hosts), self.evidence_chars),
                )
            )

    # ---- fusion + verdict ----------------------------------------------------------------

    def _fuse(self, run: _Run):
        """(probabilities dict, arms used, thresholds) or (None, [], full thresholds)."""
        models = self.models
        full = None
        if models.fusion_model is not None and not models.problems:
            full = models.policy.for_arms(models.fusion_arms)
        used = [arm for arm in models.fusion_arms if arm in run.arm_proba]
        if not used or full is None:
            return None, [], full
        inputs = FusionInputs(
            arms=used,
            probs={arm: run.arm_proba[arm][None, :] for arm in used},
            labels=models.labels,
            text_arms=[arm for arm in used if models.fusion_config.is_text(arm)],
        )
        fused = fuse_arms(models.fusion_model, inputs, used)[0]
        if not is_exact(models.fusion_model, used):
            run.warnings.append(
                f"The {models.fusion_bundle['strategy']} fusion cannot drop an arm exactly: the "
                "remaining arms were averaged."
            )
        weights = subset_weights(models.fusion_model, used)
        for arm, weight in weights.items():
            run.arms[arm].fusion_weight = round(weight, 4)
        probabilities = {
            label: round(float(p), 6) for label, p in zip(models.labels, fused, strict=True)
        }
        return probabilities, used, models.policy.for_arms(used)

    def _finish(self, run: _Run, status: str, reason: str | None) -> AnalysisResponse:
        models = self.models
        probabilities, used, thresholds = None, [], None
        if status in ("ok", "inconclusive"):
            fused, error = run.step("fusion", lambda: self._fuse(run))
            if error:
                run.warnings.append(f"Fusion failed ({error}).")
            else:
                probabilities, used, thresholds = fused
        hits = floor_hits(
            models.policy.rules,
            dom_features=run.dom_features,
            dom_evidence=run.dom_evidence,
            behavior_findings=run.behavior_keys,
            download_kind=run.download_kind,
        )
        decision = None
        if status in ("ok", "inconclusive") and not models.problems:
            decision = decide(probabilities, thresholds, hits)
        if status == "inconclusive" and not hits:
            # The page is probably not the real content (parking page, bot challenge, not
            # HTML): a model-only verdict would be noise. Rule evidence still counts.
            decision = None
        elif status == "inconclusive" and decision is not None:
            status, reason = "ok", None
            run.warnings.append(
                "The page looks like a placeholder (Part 1 quality check), but rule evidence "
                "that is reliable on its own fired - a verdict is given."
            )
        if status == "ok" and decision is None:
            status = "error"
            reason = "; ".join(models.problems) or "no model arm answered for this page"
        if hits:
            self._floor_findings(run, hits, decision)
        if models.problems and status in ("ok", "inconclusive"):
            run.warnings.append("Verdict unavailable: " + "; ".join(models.problems))
        response = self._response(run, status, reason, probabilities, used, thresholds, decision)
        return response

    def _floor_findings(self, run: _Run, hits: list[FloorHit], decision) -> None:
        ids = set()
        for hit in hits:
            rule = hit.rule
            if rule.kind == "dom_feature":
                ids.add(f"dom.{rule.features[0]}")
            elif rule.kind == "behavior_pattern":
                ids.update(
                    f"behavior.{rule.pattern}.{variant}" for variant in rule.variants or ("",)
                )
            else:
                ids.add("fetch.executable_download")
        for finding in run.findings:
            if finding.id in ids:
                finding.raises_verdict = True
        if decision is not None and decision.source == "evidence_floor":
            titles = "; ".join(hit.rule.title for hit in hits)
            run.findings.append(
                AnalysisFinding(
                    id="fusion.evidence_floor",
                    modality="fusion",
                    severity="high",
                    title="Verdict raised to Suspicious by rule evidence",
                    detail=f"The models alone said {decision.fusion_verdict}, but rule evidence "
                    f"that is reliable on its own fired: {titles}.",
                    evidence=", ".join(hit.rule.id for hit in hits),
                    raises_verdict=True,
                )
            )

    def _response(
        self,
        run: _Run,
        status: str,
        reason: str | None,
        probabilities: dict | None = None,
        used: list[str] | None = None,
        thresholds=None,
        decision=None,
    ) -> AnalysisResponse:
        models = self.models
        used = used or []
        for name in ("dom", "content", "behavior"):
            run.modality.setdefault(name, ModalityResult(status="skipped", reason="not reached"))
        for arm in ARM_ORDER:
            run.arms.setdefault(
                arm,
                ArmResult(
                    arm=arm,
                    display=models.fusion_config.arm_display(arm),
                    status="skipped",
                    reason="not reached",
                ),
            )
        for name, modality in run.modality.items():  # refresh arm copies (weights were set)
            arms = [arm for arm, m in ARM_MODALITY.items() if m == name]
            if modality.arms:
                modality.arms = [run.arms[arm] for arm in arms]
        # An arm the fusion model expects but that did not answer for this page (XLM-R
        # switched off by configuration is a deployment choice, not a degradation).
        disabled = {"text_xlmr"} if not models.xlmr_enabled else set()
        failed = [arm for arm in models.fusion_arms if arm not in used and arm not in disabled]
        degraded = status in ("ok", "inconclusive") and bool(used) and bool(failed)
        if degraded:
            run.warnings.append(
                "Degraded: "
                + ", ".join(models.fusion_config.arm_display(a) for a in failed)
                + " did not answer; the verdict uses the other arms with thresholds calibrated "
                "for them."
            )
        if (
            not models.xlmr_enabled
            and status in ("ok", "inconclusive")
            and "text_xlmr" in models.fusion_arms
        ):
            run.warnings.append(
                "XLM-R is disabled on this server (XLMR_ENABLED=false): the text arm is TF-IDF "
                "only; thresholds are calibrated for the arms used."
            )
        explanation = Explanation(arms_used=used)
        if probabilities is not None and decision is not None:
            explained = decision.threat_class if decision.verdict != "Legitimate" else "benign"
            index = models.labels.index(explained) if explained in models.labels else 0
            weights = subset_weights(models.fusion_model, used)
            contributions = {
                arm: round(weights[arm] * float(run.arm_proba[arm][index]), 4) for arm in used
            }
            weight_of = {arm: weights.get(arm, 0.0) for arm in ARM_ORDER}
            drivers = sorted(
                run.drivers,
                key=lambda d: -abs(d.contribution) * weight_of.get(d.arm, 0.0),
            )[:5]
            explanation = Explanation(
                verdict_source=decision.source,
                explained_class=explained,
                method="renormalized late-fusion weight x arm probability",
                arm_contributions=contributions,
                driving_arm=max(contributions, key=contributions.get) if contributions else None,
                top_features=drivers,
                evidence_floor_rules=decision.supported_by,
                arms_used=used,
                thresholds=thresholds.as_dict() if thresholds else {},
            )
        elif decision is not None:  # rules only (e.g. an .exe URL)
            explanation = Explanation(
                verdict_source=decision.source,
                explained_class=decision.threat_class,
                evidence_floor_rules=decision.supported_by,
            )
        if decision is not None and probabilities is not None:
            shown = "benign" if decision.fusion_verdict == "Legitimate" else decision.threat_class
            p = probabilities.get(shown, 0)
            run.findings.append(
                AnalysisFinding(
                    id="fusion.verdict",
                    modality="fusion",
                    severity={"Malicious": "high", "Suspicious": "medium"}.get(
                        decision.fusion_verdict, "info"
                    ),
                    title=f"Fused models: {decision.fusion_verdict} " f"({shown} {p:.0%})",
                    detail=f"{len(used)} model arm(s) combined; P(benign) = "
                    f"{probabilities.get('benign', 0):.2f} (Malicious below "
                    f"{thresholds.malicious:.2f}, Suspicious below {thresholds.suspicious:.2f}).",
                )
            )
        kept, omitted = rank(run.findings, self.max_findings)
        run.timings["total"] = round((time.perf_counter() - run.started) * 1000, 1)
        return AnalysisResponse(
            analysis_id=uuid.uuid4().hex,
            request_id=run.request.request_id,
            schema_version=SCHEMA_VERSION,
            analyzed_at=datetime.now().astimezone(),
            source=run.request.source,
            input=run.input or AnalysisInput(mode=run.request.mode),
            status=status,
            status_reason=reason,
            verdict=decision.verdict if decision else None,
            threat_class=decision.threat_class if decision else None,
            risk_score=decision.risk_score if decision else None,
            class_probabilities=probabilities or {},
            page_language=run.page_language,
            findings=kept,
            findings_total=len(run.findings),
            findings_omitted=omitted,
            modalities=Modalities(
                dom=run.modality["dom"],
                content=run.modality["content"],
                behavior=run.modality["behavior"],
            ),
            explanation=explanation,
            degraded=degraded,
            warnings=list(dict.fromkeys(run.warnings + models.warnings)),
            model_versions=models.versions(),
            timings_ms=run.timings,
        )


def _vote(prediction) -> str:
    """'phishing 84%' for a DomPrediction."""
    return f"{prediction.predicted} {prediction.probabilities[prediction.predicted]:.0%}"


def _host(url: str | None) -> str | None:
    from urllib.parse import urlsplit

    return (urlsplit(url).hostname or None) if url else None
