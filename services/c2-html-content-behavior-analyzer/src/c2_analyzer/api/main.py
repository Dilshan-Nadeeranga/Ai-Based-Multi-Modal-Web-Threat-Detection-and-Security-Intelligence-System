"""FastAPI app. Run: python scripts/run_api.py  (or uvicorn c2_analyzer.api.main:app --port 8002)

Part 9: Preliminary tri-modal output (fusion + FastAPI).

``create_app`` builds the app for one environment:
- always: ``GET /health`` (liveness), ``GET /ready`` (models loaded + versions), the
  public part endpoints and ``POST /api/v1/analyze`` (Part 9 B-1);
- only when APP_ENV=development: the developer inspector (``/inspector``) and
  its ``/api/v1/dev/...`` endpoints. They are not registered at all otherwise,
  so a deployed service answers 404 for them (nothing to misconfigure later).

CORS (Part 9 B-1): only the origins listed in CORS_ORIGINS (the team frontend) may call
the API from a browser, only with GET / POST and a JSON body; nothing else is exposed.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware

from c2_analyzer import __version__
from c2_analyzer.api.dependencies import get_engine
from c2_analyzer.api.routes import router
from c2_analyzer.api.security import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from c2_analyzer.config import get_settings, load_yaml_config
from c2_analyzer.constants import SERVICE_NAME
from c2_analyzer.schemas.analysis import ReadyResponse
from c2_analyzer.utils.url import domain_method

DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Load tldextract's bundled suffix list now (~0.4 s), not inside the first request.
    domain_method()
    # Part 9 B-1: load every model once, in the background (GET /ready reports progress).
    if app.state.warm_up:
        resolve_engine(app).start()
    yield


def resolve_engine(app: FastAPI):
    """The engine, honouring test overrides of ``get_engine``."""
    return app.dependency_overrides.get(get_engine, get_engine)()


def create_app(app_env: str | None = None, warm_up: bool = True) -> FastAPI:
    """Build the app. ``app_env`` defaults to APP_ENV from the environment / .env.

    ``warm_up=False`` skips loading the models at start-up (they load on first use)."""
    settings = get_settings()
    env = (app_env or settings.app_env).strip().lower()
    max_body = int(
        load_yaml_config("config").get("api", {}).get("max_body_bytes", DEFAULT_MAX_BODY_BYTES)
    )
    app = FastAPI(
        title="C2 HTML Content & Behavior Analyzer",
        version=__version__,
        description=(
            "Component C2 of ScamTrace. Never runs page JavaScript; only "
            "`POST /api/v1/analyze` in url mode fetches a page (static, SSRF-guarded). "
            f"Environment: **{env}**"
            + (
                " - developer inspector at [/inspector](/inspector)."
                if env == "development"
                else "."
            )
        ),
        lifespan=lifespan,
    )
    app.state.app_env = env
    app.state.warm_up = warm_up
    # Starlette runs the last added middleware first: CORS, size check, then headers.
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=max_body)
    if settings.cors_origin_list:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origin_list,
            allow_methods=["GET", "POST"],
            allow_headers=["Content-Type"],
            allow_credentials=False,
            max_age=600,
        )

    @app.get("/health", tags=["health"])
    def health() -> dict[str, str]:
        """Liveness probe."""
        return {"status": "ok", "service": SERVICE_NAME}

    @app.get(
        "/ready",
        tags=["health"],
        response_model=ReadyResponse,
        responses={503: {"description": "models still loading or not usable"}},
    )
    def ready() -> Response:
        """Readiness probe: 200 once every model is loaded (with versions), else 503."""
        engine = resolve_engine(app)
        orchestrator = engine.peek()
        if orchestrator is None:
            if not engine.loading and engine.error is None:
                engine.start()  # e.g. started without warm-up: begin now
            answer = ReadyResponse(
                ready=False,
                loading=engine.error is None,
                reason=engine.error or "models are loading",
                xlmr_enabled=settings.xlmr_enabled,
            )
        else:
            answer = orchestrator.models.ready()
        return Response(
            answer.model_dump_json(),
            status_code=200 if answer.ready else 503,
            media_type="application/json",
        )

    app.include_router(router)
    if env == "development":
        from c2_analyzer.api.dev_routes import inspector_router
        from c2_analyzer.api.dev_routes import router as dev_router

        app.include_router(dev_router)
        app.include_router(inspector_router)
    return app


app = create_app()
