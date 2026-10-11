"""FastAPI entry point for Intelligent URL and Domain Analyzer (Component C1).

Run with:
    uvicorn main:app --reload --port 8001
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import database
from app.api import health, url_routes
from app.config import get_settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Service lifecycle setup and teardown."""
    db_connected = database.init_db()
    if db_connected:
        logger.info("Database initialized successfully.")
    else:
        logger.info("Running in standalone memory mode (No active MongoDB database).")
    yield
    database.close_db()


app = FastAPI(
    title="Intelligent URL and Domain Analyzer (C1)",
    description=(
        "Multi-Layer URL & Domain Intelligence Framework (Phase 1 Layer 1: Feature Extraction Engine). "
        "Static inspection only — no target webpage is executed or rendered."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(url_routes.router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.host, port=settings.port, reload=True)
