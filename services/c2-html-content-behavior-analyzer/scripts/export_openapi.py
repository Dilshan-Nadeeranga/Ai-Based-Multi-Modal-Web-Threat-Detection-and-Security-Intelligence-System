"""Part 9 B-1: export the public OpenAPI contract for the frontend / backend teammates.

Part 9: Batch B-1 - end-to-end URL analysis engine.
Thin CLI wrapper.

    python scripts/export_openapi.py             # -> docs/openapi.json

Exports the PRODUCTION app (no developer-inspector routes) so the file is exactly what a
deployed C2 offers. Human-readable contract + examples: docs/api_contract.md.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from c2_analyzer.api.main import create_app
from c2_analyzer.config import project_root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", type=Path, default=project_root() / "docs" / "openapi.json")
    args = parser.parse_args(argv)
    schema = create_app("production", warm_up=False).openapi()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(schema, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {args.out} ({len(schema['paths'])} paths)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
