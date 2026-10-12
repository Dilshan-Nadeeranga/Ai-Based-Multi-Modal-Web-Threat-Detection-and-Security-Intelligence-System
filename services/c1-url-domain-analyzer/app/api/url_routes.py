"""API routes for URL feature extraction, domain intelligence, and threat infrastructure."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from app.analyzers.dga_analyzer import DgaAnalyzer
from app.analyzers.domain_intelligence import DomainIntelligenceAnalyzer
from app.analyzers.lexical_analyzer import UrlLexicalAnalyzer
from app.analyzers.redirect_analyzer import ControlledRedirectResolver
from app.analyzers.threat_infrastructure import ThreatInfrastructureAnalyzer
from app.database import save_scan_result
from app.schemas.url_schema import (
    CompleteUrlDomainAnalysisResult,
    DgaAnalysisFeatures,
    DomainIntelligenceReport,
    RedirectChainFeatures,
    ThreatInfrastructureReport,
    UrlAnalysisRequest,
    UrlLexicalFeatures,
)

router = APIRouter(tags=["URL, Domain & Threat Infrastructure Intelligence"])

lexical_analyzer = UrlLexicalAnalyzer()
domain_intelligence_analyzer = DomainIntelligenceAnalyzer()
dga_analyzer = DgaAnalyzer()
redirect_resolver = ControlledRedirectResolver()
threat_infra_analyzer = ThreatInfrastructureAnalyzer()


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
