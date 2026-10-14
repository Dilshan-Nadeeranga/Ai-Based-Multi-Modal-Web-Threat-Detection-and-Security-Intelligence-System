"""Developer inspector tests: dev dataset endpoints on a tiny temporary dataset,
the safe preview's headers, the inspector page, and the XSS rule (static grep).

Why: the inspector looks at real scam pages. These tests pin the two things
that must never break: it shows the same data the pipeline stored, and it
never turns page content into live HTML (no HTML-parsing sinks in the JS, a
script-free safe preview with a strict CSP, no file access outside data/).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from c2_analyzer.api.dependencies import get_dev_dataset
from c2_analyzer.api.dev_data import DevDataset
from c2_analyzer.api.dev_routes import STATIC_DIR
from c2_analyzer.api.main import create_app
from c2_analyzer.dataset.manifest import MANIFEST_COLUMNS
from c2_analyzer.preprocessing.batch import save_page
from c2_analyzer.preprocessing.loader import from_bytes
from c2_analyzer.preprocessing.pipeline import preprocess
from c2_analyzer.utils.hashing import sha256_file

SAMPLES = Path(__file__).parent / "fixtures" / "sample_pages"
VERSION = "v0.1"
# sample_id, label, language, fixture, stored by "Part 2"?
ROWS = [
    ("c2_benign_000001", "benign", "en", "benign_simple.html", True),
    ("c2_phishing_000001", "phishing", "en", "phishing_external_form.html", True),
    ("c2_phishing_000002", "phishing", "si", "sinhala_urgency.html", True),
    ("c2_phishing_000003", "phishing", "en", "js_exfiltration.html", False),  # not processed
]
BANNED_SINKS = [
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
    "eval(",
    "new Function",
]  # (attributes like src/href/srcdoc are refused at runtime by el() in inspector.js)


@pytest.fixture
def dataset(tmp_path: Path) -> DevDataset:
    """A frozen version with 4 samples; 3 have stored ParsedPage JSON."""
    raw, manifests, parsed = tmp_path / "raw", tmp_path / "manifests", tmp_path / "parsed"
    records = []
    for sample_id, label, language, fixture, stored in ROWS:
        target = raw / label / f"{sample_id}.html"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((SAMPLES / fixture).read_bytes())
        records.append(
            {
                "sample_id": sample_id,
                "label": label,
                "language": language,
                "cluster_id": f"cl_{len(records) + 1:06d}",
                "sha256": sha256_file(target),
                "file_path": f"{label}/{sample_id}.html",
            }
        )
        if stored:
            raw_html = from_bytes(
                target.read_bytes(), sample_id=sample_id, dataset_version=VERSION, label=label
            )
            (parsed / VERSION).mkdir(parents=True, exist_ok=True)
            save_page(preprocess(raw_html), parsed / VERSION, sample_id)
    manifests.mkdir()
    pd.DataFrame(records, columns=MANIFEST_COLUMNS).to_csv(
        manifests / f"dataset_{VERSION}.csv", index=False
    )
    info = {
        "version": VERSION,
        "created_at": "2026-10-12T21:25:42+05:30",
        "total": len(records),
        "counts_per_label": {"benign": 1, "phishing": 3},
        "counts_per_language": {"en": 3, "si": 1},
        "notes": "test",
    }
    (manifests / f"dataset_{VERSION}.json").write_text(json.dumps(info), encoding="utf-8")
    return DevDataset(manifests, parsed, raw, metadata_csv=tmp_path / "metadata.csv")


@pytest.fixture
def client(dataset: DevDataset) -> TestClient:
    app = create_app("development")
    app.dependency_overrides[get_dev_dataset] = lambda: dataset
    return TestClient(app)


def ids(response) -> list[str]:
    assert response.status_code == 200, response.text
    return [row["sample_id"] for row in response.json()]


# ---- versions and sample list ----------------------------------------------------------


def test_versions(client):
    versions = client.get("/api/v1/dev/versions").json()
    assert [v["version"] for v in versions] == [VERSION]
    assert versions[0]["total"] == 4 and versions[0]["processed"] == 3
    assert versions[0]["counts_per_label"]["phishing"] == 3


def test_samples_list_reads_stored_facts(client):
    rows = {row["sample_id"]: row for row in client.get("/api/v1/dev/samples").json()}
    assert list(rows) == [row[0] for row in ROWS]  # manifest order, newest version by default
    phishing = rows["c2_phishing_000001"]
    assert phishing["title"] == "Sign in - Secure Banking"
    assert phishing["has_form"] and phishing["has_password"]
    assert phishing["external_form_action"] and phishing["processed"]
    assert rows["c2_phishing_000002"]["title"] == "ගිණුම් අනතුරු ඇඟවීම"
    assert rows["c2_benign_000001"]["has_form"] is False
    unprocessed = rows["c2_phishing_000003"]
    assert unprocessed["processed"] is False and unprocessed["title"] is None


def test_samples_filters(client):
    url = "/api/v1/dev/samples"
    assert ids(client.get(url, params={"version": VERSION, "label": "benign"})) == [
        "c2_benign_000001"
    ]
    assert ids(client.get(url, params={"language": "si"})) == ["c2_phishing_000002"]
    assert ids(client.get(url, params={"q": "SECURE bank"})) == ["c2_phishing_000001"]
    assert ids(client.get(url, params={"q": "000003"})) == ["c2_phishing_000003"]
    assert ids(client.get(url, params={"q": "ගිණුම්"})) == ["c2_phishing_000002"]
    assert ids(client.get(url, params={"has_password": "true"})) == ["c2_phishing_000001"]
    assert ids(client.get(url, params={"external_form_action": "true"})) == ["c2_phishing_000001"]
    assert len(ids(client.get(url, params={"has_password": "false"}))) == 3
    assert ids(client.get(url, params={"label": "crypto_scam"})) == []


def test_samples_list_picks_up_a_rerun(client, dataset):
    """The summary cache is keyed by file mtime/size, so a new Part 2 run shows up."""
    assert client.get("/api/v1/dev/samples", params={"q": "renamed"}).json() == []
    path = dataset.parsed_root / VERSION / "c2_benign_000001.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["title"] = "Renamed bakery page"
    path.write_text(json.dumps(data), encoding="utf-8")
    assert ids(client.get("/api/v1/dev/samples", params={"q": "renamed"})) == ["c2_benign_000001"]


def test_unknown_or_invalid_version_is_404(client):
    for version in ("v9.9", "../manifests", "latest"):
        response = client.get("/api/v1/dev/samples", params={"version": version})
        assert response.status_code == 404, version


# ---- parsed page ------------------------------------------------------------------------


def test_parsed_returns_the_stored_json(client, dataset):
    response = client.get(
        "/api/v1/dev/samples/c2_phishing_000001/parsed", params={"version": VERSION}
    )
    assert response.status_code == 200
    assert response.headers["x-parsed-source"] == "stored"
    stored = (dataset.parsed_root / VERSION / "c2_phishing_000001.json").read_text("utf-8")
    assert response.json() == json.loads(stored)


def test_parsed_processes_on_the_fly_without_saving(client, dataset, tmp_path):
    response = client.get("/api/v1/dev/samples/c2_phishing_000003/parsed")
    assert response.status_code == 200
    assert response.headers["x-parsed-source"] == "on-the-fly"
    page = response.json()
    assert page["meta"]["sample_id"] == "c2_phishing_000003"
    assert page["meta"]["dataset_version"] == VERSION
    assert page["title"] == "Account Login" and page["scripts_inline"]
    # read-only: nothing was written (no JSON, and metadata.csv was not created)
    assert not (dataset.parsed_root / VERSION / "c2_phishing_000003.json").exists()
    assert not (tmp_path / "metadata.csv").exists()


@pytest.mark.parametrize(
    "sample_id",
    ["c2_phishing_999999", "not-an-id", "..%2F..%2Fsecret", "c2_benign_000001.json"],
)
def test_parsed_unknown_or_invalid_sample_is_404(client, sample_id):
    assert client.get(f"/api/v1/dev/samples/{sample_id}/parsed").status_code == 404


def test_raw_path_outside_data_raw_is_refused(client, dataset):
    manifest = dataset.manifests / f"dataset_{VERSION}.csv"
    frame = pd.read_csv(manifest, dtype=str)
    frame.loc[frame["sample_id"] == "c2_phishing_000003", "file_path"] = "../manifests/x.csv"
    frame.to_csv(manifest, index=False)
    assert client.get("/api/v1/dev/samples/c2_phishing_000003/parsed").status_code == 404
    assert client.get("/api/v1/dev/samples/c2_phishing_000003/safe-preview").status_code == 404


# ---- safe preview -----------------------------------------------------------------------


def test_safe_preview_headers_and_no_script(client):
    response = client.get("/api/v1/dev/samples/c2_phishing_000003/safe-preview")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    csp = response.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "style-src 'unsafe-inline'" in csp
    assert "script-src" not in csp  # no script source allowed at all
    assert response.headers["x-content-type-options"] == "nosniff"
    body = response.text.lower()
    assert "<script" not in body and "exfil" not in body and " on" + "submit=" not in body
    assert "sanitized preview" in body


def test_safe_preview_unknown_sample_is_404(client):
    assert client.get("/api/v1/dev/samples/c2_phishing_999999/safe-preview").status_code == 404
    response = client.get(
        "/api/v1/dev/samples/c2_phishing_000001/safe-preview", params={"version": "v9.9"}
    )
    assert response.status_code == 404


# ---- inspector page ----------------------------------------------------------------------


def test_inspector_page_and_script_are_served(client):
    page = client.get("/inspector")
    assert page.status_code == 200 and page.headers["content-type"].startswith("text/html")
    assert "script-src 'self'" in page.headers["content-security-policy"]
    assert page.headers["x-content-type-options"] == "nosniff"
    assert '<script src="/inspector/inspector.js"' in page.text
    script = client.get("/inspector/inspector.js")
    assert script.status_code == 200
    assert "javascript" in script.headers["content-type"]


def read_static(name: str) -> str:
    return (STATIC_DIR / name).read_text(encoding="utf-8")


@pytest.mark.parametrize("name", ["inspector.html", "inspector.js"])
@pytest.mark.parametrize("sink", BANNED_SINKS)
def test_no_html_parsing_sinks(name, sink):
    """The XSS rule: page data is rendered as text only (see the top of inspector.js)."""
    assert sink not in read_static(name), f"{sink!r} found in {name}"


def test_html_has_strict_csp_and_no_inline_script():
    html = read_static("inspector.html")
    assert (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; frame-src 'self'"
    ) in html
    assert re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", html) == []  # every script is external
    assert "http://" not in html and "https://" not in html  # no CDN: works offline
    assert "SECURITY RULE" in html


def test_js_has_no_external_urls_and_a_tab_registry():
    js = read_static("inspector.js")
    assert "http://" not in js and "https://" not in js
    assert "SECURITY RULE" in js and "function registerTab" in js
    for future in ("Part 3", "Part 5–6", "Part 7–8", "Part 9"):
        assert future in js
