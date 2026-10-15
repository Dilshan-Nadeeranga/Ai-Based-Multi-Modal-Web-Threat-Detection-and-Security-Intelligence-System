"""FastAPI app. Run: python scripts/run_api.py  (or uvicorn c2_analyzer.api.main:app --port 8002)

Part 9: Preliminary tri-modal output (fusion + FastAPI).

``create_app`` builds the app for one environment:
- always: ``GET /health``, ``POST /api/v1/preprocess`` (Part 2), the Part 9 stubs;
- only when APP_ENV=development: the developer inspector (``/inspector``) and
  its ``/api/v1/dev/...`` endpoints. They are not registered at all otherwise,
  so a deployed service answers 404 for them (nothing to misconfigure later).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from c2_analyzer import __version__
from c2_analyzer.api.routes import router
from c2_analyzer.api.security import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from c2_analyzer.config import get_settings, load_yaml_config
from c2_analyzer.constants import SERVICE_NAME
from c2_analyzer.utils.url import domain_method

DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    # Load tldextract's bundled suffix list now (~0.4 s), not inside the first request.
    domain_method()
    yield


def create_app(app_env: str | None = None) -> FastAPI:
    """Build the app. ``app_env`` defaults to APP_ENV from the environment / .env."""
    env = (app_env or get_settings().app_env).strip().lower()
    max_body = int(
        load_yaml_config("config").get("api", {}).get("max_body_bytes", DEFAULT_MAX_BODY_BYTES)
    )
    app = FastAPI(
        title="C2 HTML Content & Behavior Analyzer",
        version=__version__,
        description=(
            "Component C2 of ScamTrace. Never fetches a live URL and never runs page "
            f"JavaScript. Environment: **{env}**"
            + (
                " - developer inspector at [/inspector](/inspector)."
                if env == "development"
                else "."
            )
        ),
        lifespan=lifespan,
    )
    app.state.app_env = env
    # Starlette runs the last added middleware first: size check, then headers.
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=max_body)

    @app.get("/health", tags=["health"])
    def health() -> dict[str, str]:
        """Liveness probe."""
        return {"status": "ok", "service": SERVICE_NAME}

    app.include_router(router)
    if env == "development":
        from c2_analyzer.api.dev_routes import inspector_router
        from c2_analyzer.api.dev_routes import router as dev_router

        app.include_router(dev_router)
        app.include_router(inspector_router)
    return app


app = create_app()
