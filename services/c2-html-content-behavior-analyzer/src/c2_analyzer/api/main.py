"""FastAPI app. Run: uvicorn c2_analyzer.api.main:app --port 8002

Part 9: Preliminary tri-modal output (fusion + FastAPI).
"""

from __future__ import annotations

from fastapi import FastAPI

from c2_analyzer import __version__
from c2_analyzer.api.routes import router
from c2_analyzer.constants import SERVICE_NAME

app = FastAPI(title="C2 HTML Content & Behavior Analyzer", version=__version__)
app.include_router(router)


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok", "service": SERVICE_NAME}
