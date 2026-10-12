"""Start the C2 FastAPI service with uvicorn.

Part 9: Preliminary tri-modal output (fusion + FastAPI).
"""

from __future__ import annotations

import argparse

import uvicorn

from c2_analyzer.config import get_settings


def main() -> None:
    settings = get_settings()
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default=settings.api_host)
    parser.add_argument("--port", type=int, default=settings.api_port)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()
    uvicorn.run("c2_analyzer.api.main:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
