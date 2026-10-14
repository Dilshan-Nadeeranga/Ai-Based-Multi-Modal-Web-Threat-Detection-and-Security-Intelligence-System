"""Start the C2 FastAPI service with uvicorn (developer inspector included in development).

Part 9: Preliminary tri-modal output (fusion + FastAPI).

Why: one command that starts the API the safe way. It binds to 127.0.0.1
(this computer only) unless --host says otherwise, because in development
the inspector serves dataset samples. The port comes from API_PORT in .env
(default 8002, so it does not clash with C3 on 8003 and C4 on 8000), the
environment from APP_ENV in .env.
"""

from __future__ import annotations

import argparse
import os

import uvicorn

from c2_analyzer.config import get_settings, project_root

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def main() -> None:
    # .env is read from the current folder: start from the service folder so it is
    # found no matter where the script was launched from.
    os.chdir(project_root())
    settings = get_settings()
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1", help="default 127.0.0.1 (local only)")
    parser.add_argument("--port", type=int, default=settings.api_port, help="default API_PORT")
    parser.add_argument("--reload", action="store_true", help="restart when the code changes")
    args = parser.parse_args()

    env = settings.app_env.strip().lower()
    shown_host = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
    base = f"http://{shown_host}:{args.port}"
    print(f"C2 API - APP_ENV={env}")
    if env == "development":
        print(f"  Inspector:  {base}/inspector")
    else:
        print("  Inspector:  disabled (only when APP_ENV=development)")
    print(f"  Swagger:    {base}/docs")
    print(f"  Health:     {base}/health")
    if env == "development" and args.host not in LOOPBACK:
        print(
            f"WARNING: --host {args.host} exposes the developer endpoints (dataset samples) "
            "to the network. Use 127.0.0.1 unless you really need this."
        )
    uvicorn.run("c2_analyzer.api.main:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
