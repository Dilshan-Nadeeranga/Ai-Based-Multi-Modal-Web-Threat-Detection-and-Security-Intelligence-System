"""FastAPI entry point: ``uvicorn app.main:app --reload --port 8003``."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app import __version__
from app.api import capture_routes, dataset_routes, health_routes, preprocessing_routes
from app.api.responses import error_response, service_error_response
from app.config import Settings, get_settings
from app.exceptions import ServiceError
from app.services.capture_service import WebCaptureService
from app.services.dataset_service import DatasetService
from app.services.image_pipeline import ImagePipeline
from app.services.statistics_service import StatisticsService

logger = logging.getLogger(__name__)


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=level.upper(),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


def create_app(
    settings: Settings | None = None,
    pipeline: ImagePipeline | None = None,
    capture_service: WebCaptureService | None = None,
) -> FastAPI:
    """Application factory; tests inject their own settings/pipeline/capture service."""
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    app = FastAPI(
        title="ScamTrace - Social Media & Web Visual Threat Analyzer",
        description="OCR and image preprocessing, multimodal dataset preparation and destination web capture.",
        version=__version__,
    )
    app.state.pipeline = pipeline or ImagePipeline.from_settings(settings)
    app.state.dataset_service = DatasetService(settings)
    app.state.statistics_service = StatisticsService(settings)
    app.state.capture_service = capture_service or WebCaptureService(settings)

    @app.exception_handler(RequestValidationError)
    async def _request_validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        fields = sorted({str(err["loc"][-1]) for err in exc.errors() if err.get("loc")})
        missing = all(err.get("type") == "missing" for err in exc.errors())
        message = (
            f"Missing required field(s): {', '.join(fields)}."
            if missing
            else f"Invalid request field(s): {', '.join(fields)}."
        )
        return error_response(422, "INVALID_REQUEST", message)

    @app.exception_handler(ServiceError)
    async def _service_error_handler(_: Request, exc: ServiceError) -> JSONResponse:
        return service_error_response(exc)

    @app.exception_handler(Exception)
    async def _unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled error on %s %s", request.method, request.url.path)
        return error_response(500, "INTERNAL_ERROR", "An internal error occurred.")

    app.include_router(health_routes.router)
    app.include_router(preprocessing_routes.router)
    app.include_router(dataset_routes.router)
    app.include_router(capture_routes.router)
    return app


app = create_app()
