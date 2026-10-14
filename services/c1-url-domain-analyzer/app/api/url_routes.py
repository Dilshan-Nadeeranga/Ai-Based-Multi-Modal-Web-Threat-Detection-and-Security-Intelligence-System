"""API routes for URL feature extraction, domain intelligence, and threat infrastructure."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from app.analyzers.dga_analyzer import DgaAnalyzer
from app.analyzers.domain_intelligence import DomainIntelligenceAnalyzer
from app.analyzers.lexical_analyzer import UrlLexicalAnalyzer
from app.analyzers.redirect_analyzer import ControlledRedirectResolver
from app.analyzers.threat_infrastructure import ThreatInfrastructureAnalyzer
from app.config import get_settings
from app.database import save_scan_result
from app.schemas.url_schema import (
    CompleteUrlDomainAnalysisResult,
    DgaAnalysisFeatures,
    DomainIntelligenceReport,
    ExplainableRiskAssessment,
    MlPredictionResult,
    RedirectChainFeatures,
    ThreatInfrastructureReport,
    UrlAnalysisRequest,
    UrlLexicalFeatures,
)
from app.ml.model_service import get_ml_service

router = APIRouter(tags=["URL, Domain & Threat Infrastructure Intelligence"])


lexical_analyzer = UrlLexicalAnalyzer()
domain_intelligence_analyzer = DomainIntelligenceAnalyzer()
dga_analyzer = DgaAnalyzer()
redirect_resolver = ControlledRedirectResolver()
threat_infra_analyzer = ThreatInfrastructureAnalyzer()
ml_service = get_ml_service()


@router.post(
    "/analyze-url",
    response_model=CompleteUrlDomainAnalysisResult,
    summary="Full Multi-Layer Analysis (Gateway endpoint)",
)
@router.post(
    "/api/v1/analyze-url",
    response_model=CompleteUrlDomainAnalysisResult,
    summary="Full Multi-Layer Analysis (v1 API)",
)
async def analyze_url(payload: UrlAnalysisRequest) -> CompleteUrlDomainAnalysisResult:
    """Analyze a URL without executing or rendering destination webpages.

    Integrates:
    - Layer 1: Lexical URL Features
    - Layer 2: Domain Intelligence (RDAP/WHOIS age, DNS infrastructure, reputation)
    - Layer 3: Threat Infrastructure (DGA statistical analysis, URL shorteners, controlled redirect chains)
    """
    if not payload.url or not payload.url.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL field cannot be empty.",
        )

    result = await domain_intelligence_analyzer.analyze_full(payload.url)

    # Optionally persist result if database is connected
    save_scan_result(result.model_dump())

    return result


@router.post(
    "/api/v1/domain-intelligence",
    response_model=DomainIntelligenceReport,
    summary="Extract Domain Intelligence (RDAP/WHOIS, DNS, and Threat Reputation)",
)
async def analyze_domain_only(payload: UrlAnalysisRequest) -> DomainIntelligenceReport:
    """Analyze domain registration, DNS records, and infrastructure reputation only."""
    if not payload.url or not payload.url.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL field cannot be empty.",
        )

    features = lexical_analyzer.extract_features(payload.url)
    target_domain = features.registered_domain or features.hostname or payload.url.strip()

    return await domain_intelligence_analyzer.analyze_domain(target_domain)


@router.post(
    "/api/v1/dga-analysis",
    response_model=DgaAnalysisFeatures,
    summary="Analyze Domain Generation Algorithm (DGA) statistical features",
)
async def analyze_dga_only(payload: UrlAnalysisRequest) -> DgaAnalysisFeatures:
    """Evaluate DGA entropy, vowel-consonant ratios, and algorithmic likelihood on domain label."""
    if not payload.url or not payload.url.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL field cannot be empty.",
        )

    features = lexical_analyzer.extract_features(payload.url)
    target_domain = features.registered_domain or features.hostname or payload.url.strip()

    return dga_analyzer.analyze(target_domain)


@router.post(
    "/api/v1/redirect-analysis",
    response_model=RedirectChainFeatures,
    summary="Controlled HTTP redirect chain resolution and URL shortener analysis",
)
async def analyze_redirect_only(payload: UrlAnalysisRequest) -> RedirectChainFeatures:
    """Trace HTTP redirect hops with strict SSRF validation and hop limits."""
    if not payload.url or not payload.url.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL field cannot be empty.",
        )

    return await redirect_resolver.resolve(payload.url)


@router.post(
    "/api/v1/threat-infrastructure",
    response_model=ThreatInfrastructureReport,
    summary="Consolidated Threat Infrastructure report (DGA + Redirect Chains)",
)
async def analyze_threat_infrastructure_only(payload: UrlAnalysisRequest) -> ThreatInfrastructureReport:
    """Evaluate DGA algorithmic generation and controlled redirect infrastructure."""
    if not payload.url or not payload.url.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL field cannot be empty.",
        )

    features = lexical_analyzer.extract_features(payload.url)
    target_domain = features.registered_domain or features.hostname or payload.url.strip()

    return await threat_infra_analyzer.analyze(payload.url, target_domain)


@router.post(
    "/api/v1/extract-features",
    response_model=UrlLexicalFeatures,
    summary="Extract raw URL lexical features dictionary for ML pipelines",
)
async def extract_features(payload: UrlAnalysisRequest) -> UrlLexicalFeatures:
    """Extract raw structured features from URL for machine learning model pipelines."""
    if not payload.url or not payload.url.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL field cannot be empty.",
        )

    return lexical_analyzer.extract_features(payload.url)


@router.post(
    "/api/v1/ml-predict",
    response_model=MlPredictionResult,
    summary="Direct Machine Learning classifier prediction",
)
async def ml_predict(payload: UrlAnalysisRequest) -> MlPredictionResult:
    """Classify a URL using the loaded machine learning model without running full multi-layer scans."""
    if not payload.url or not payload.url.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL field cannot be empty.",
        )

    return ml_service.predict(payload.url)


@router.get(
    "/api/v1/ml-model-status",
    summary="Get active ML model metadata and operational status",
)
async def ml_model_status():
    """Retrieve metadata, active algorithm, decision threshold, and performance metrics of the loaded model."""
    return {
        "is_model_loaded": ml_service.is_loaded,
        "model_dir": str(ml_service.model_dir),
        "metadata": ml_service.metadata,
    }


@router.post(
    "/api/v1/explain-risk",
    response_model=ExplainableRiskAssessment,
    summary="Direct Explainable Multi-Channel Risk Assessment",
)
async def explain_risk_assessment(payload: UrlAnalysisRequest) -> ExplainableRiskAssessment:
    """Execute full multi-layer scan and return detailed explainable risk scoring breakdown."""
    if not payload.url or not payload.url.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL field cannot be empty.",
        )

    full_res = await domain_intelligence_analyzer.analyze_full(payload.url)
    if full_res.risk_assessment is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Risk assessment engine failed to compute audit trail.",
        )
    return full_res.risk_assessment


@router.get(
    "/api/v1/scoring-weights",
    summary="Retrieve configurable risk scoring weights, rationale, and thresholds",
)
async def get_scoring_weights():
    """Retrieve nominal scoring configuration weights, rationales, and classification thresholds."""
    settings = get_settings()
    return {
        "engine_version": settings.risk_engine_version,
        "calibration_status": "Empirical prior baseline (Configurable; calibrated on benchmark validation datasets)",
        "nominal_weights": {
            "lexical_structural": {
                "weight": settings.weight_lexical_structural,
                "rationale": "Evaluates URL syntax, path depth, query complexity, and sensitive keyword presence with logarithmic saturation.",
            },
            "entropy_obfuscation": {
                "weight": settings.weight_entropy_obfuscation,
                "rationale": "Identifies percent-encoding evasion (%25XX), authority @ masking, hex/octal IPs, and elevated Shannon entropy.",
            },
            "homoglyph_lookalike": {
                "weight": settings.weight_homoglyph_lookalike,
                "rationale": "Detects confusable script lookalikes (Cyrillic/Latin) and Punycode spoofing targeting high-value brands.",
            },
            "domain_registration": {
                "weight": settings.weight_domain_registration,
                "rationale": "Evaluates domain age (NRD <= 30d penalty vs >2yr mitigating credit), registrar metadata, and DNSSEC validation.",
            },
            "dns_reputation": {
                "weight": settings.weight_dns_reputation,
                "rationale": "Flags fast-flux DNS turnover, private RFC-1918 resolution, dynamic DNS hosting, and threat feed matches.",
            },
            "dga": {
                "weight": settings.weight_dga,
                "rationale": "Measures domain label statistical randomness, consonant clustering, and bigram perplexity for botnet C2 detection.",
            },
            "shortener_redirect": {
                "weight": settings.weight_shortener_redirect,
                "rationale": "Traces cloaked URL shorteners, cross-domain redirection chains, cyclic loops, and SSRF violation attempts.",
            },
            "machine_learning": {
                "weight": settings.weight_machine_learning,
                "rationale": "Inputs 47-dimensional feature vectors into supervised classifier (Random Forest/XGBoost) for non-linear pattern recognition.",
            },
        },
        "thresholds": {
            "low_risk": {
                "max_score": settings.risk_threshold_low,
                "label": "Low Risk",
                "action": "Permit traffic; no critical indicators observed.",
            },
            "suspicious": {
                "min_score": settings.risk_threshold_low,
                "max_score": settings.risk_threshold_medium,
                "label": "Suspicious",
                "action": "Exercise caution; elevated lexical or young domain signals present.",
            },
            "medium_risk": {
                "min_score": settings.risk_threshold_medium,
                "max_score": settings.risk_threshold_high,
                "label": "Medium Risk",
                "action": "Elevated threat likelihood; multiple correlated suspicious factors.",
            },
            "high_risk": {
                "min_score": settings.risk_threshold_high,
                "max_score": 100.0,
                "label": "High Risk Scam",
                "action": "Block / warn user; confirmed malicious infrastructure, phishing synergy, or threat feed hit.",
            },
        },
    }

