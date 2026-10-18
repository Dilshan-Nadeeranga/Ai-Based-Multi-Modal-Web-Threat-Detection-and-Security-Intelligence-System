"""Export the dashboard's Demo-mode fixtures from REAL C2 output (Part 9 B-2, PP1 safety net).

Part 9: Batch B-2 - read APIs for the team frontend.

Why: the C2 pages in frontend/scamtrace-dashboard must work in the presentation even
without the C2 service or Wi-Fi. Instead of hand-written JSON, this script runs the real
API in-process (production app, real models, html mode = nothing fetched; the unreachable
example uses a reserved ``.invalid`` host, so no request leaves the machine) and saves the
answers. Every URL / domain is DEFANGED (``defang_analysis``) before it is written, so the
fixtures never hold a clickable scam link.

  python scripts/export_ui_fixtures.py --out <dashboard>/src/features/c2/fixtures
  (<dashboard> = ../../frontend/scamtrace-dashboard)

Needs the trained v0.3 models and, for the feed / history / stats fixtures, demo scans in
the results database (python scripts/demo_ingest.py).
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from fastapi.testclient import TestClient

from c2_analyzer.api.dependencies import get_ingest_service
from c2_analyzer.api.dev_data import DevDataset
from c2_analyzer.api.main import create_app
from c2_analyzer.config import project_root
from c2_analyzer.ingest.service import IngestService
from c2_analyzer.store.repository import ResultsStore
from c2_analyzer.utils.defang import defang_analysis

# (fixture name, sample id, why it is in the demo)
PAGES = [
    ("benign_sinhala", "c2_benign_000118", "Sinhala news page - Legitimate + language caveat"),
    ("phishing_zimbra", "c2_phishing_000081", "Zimbra webmail phishing - evidence floor fired"),
    ("crypto_scam", None, "crypto investment scam (first Malicious crypto_scam test page)"),
]
UNREACHABLE_URL = "https://c2-demo-unreachable.invalid/login"


def write(path: Path, data) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"  wrote {path.name} ({path.stat().st_size // 1024} KB)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True, help="fixtures folder")
    parser.add_argument("--version", default="v0.3")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    os.chdir(project_root())

    app = create_app("production", warm_up=False)
    client = TestClient(app)  # read APIs: the real results database (demo scans)
    # /analyze stores every check in the history - the fixture analyses must not
    # end up there, so they go to a throw-away in-memory store.
    scratch = create_app("production", warm_up=False)
    scratch.dependency_overrides[get_ingest_service] = lambda: IngestService(
        ResultsStore(":memory:")
    )
    analyzer = TestClient(scratch)
    dataset = DevDataset.from_settings()
    manifest = dataset.manifest(args.version)

    def analyze(body: dict) -> dict:
        response = analyzer.post("/api/v1/analyze", json=body)
        response.raise_for_status()
        return defang_analysis(response.json())

    analyses = {}
    for name, sample_id, why in PAGES:
        if sample_id is None:  # pick the first test crypto page the engine calls Malicious
            split = dataset.split_of
            candidates = manifest.loc[manifest["label"] == "crypto_scam", "sample_id"]
            for candidate in candidates:
                if split(args.version, candidate) != "test":
                    continue
                html, url = dataset.raw_html(args.version, candidate)
                result = analyze({"html": html, "url": url, "source": "user"})
                if result["verdict"] == "Malicious":
                    sample_id, analyses[name] = candidate, result
                    break
        else:
            html, url = dataset.raw_html(args.version, sample_id)
            analyses[name] = analyze({"html": html, "url": url, "source": "user"})
        result = analyses[name]
        result["request_id"] = sample_id
        print(f"{name}: {sample_id} -> {result['verdict'] or result['status']} ({why})")
    analyses["unreachable"] = analyze({"url": UNREACHABLE_URL, "source": "user"})
    print(f"unreachable: {analyses['unreachable']['status']}")
    write(out / "analyses.json", analyses)

    scans = client.get("/api/v1/scans", params={"limit": 200, "source": "threatradar_push"})
    items = scans.json()["items"]
    write(out / "scans.json", {"items": items, "next_cursor": None})
    details = {}
    for item in items:
        detail = client.get(f"/api/v1/scans/{item['id']}")
        if detail.status_code == 200:
            details[str(item["id"])] = detail.json()
    write(out / "scan_details.json", details)
    write(
        out / "stats.json",
        {
            w: client.get("/api/v1/stats/overview", params={"window": w}).json()
            for w in ("24h", "7d")
        },
    )
    write(out / "research.json", client.get("/api/v1/research/summary").json())
    ready = client.get("/ready")
    write(out / "ready.json", ready.json())
    print(f"done -> {out}")


if __name__ == "__main__":
    main()
