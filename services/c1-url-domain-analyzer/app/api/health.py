"""Health check router for C1 service."""

from __future__ import annotations

from fastapi import APIRouter
from app import database

router = APIRouter(tags=["Health"])


@router.get("/health", summary="Health check")
@router.get("/api/v1/health", summary="Versioned health check")
def health() -> dict:
    """Return operational health status of C1 microservice."""
    return {
        "status": "ok",
        "service": "c1-url-domain-analyzer",
        "component": "C1_URL_DOMAIN",
        "mongodb_connected": database.ping(),
    }
