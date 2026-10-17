"""API tests: /health, the public Part 2 endpoint POST /api/v1/preprocess, the
5 MB body limit, security headers, Swagger, and that dev routes exist only in
development.

Why: /api/v1/preprocess stays for the Part 9 integration, so its contract
(same JSON as the stored ParsedPage) and its protections are pinned here.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from c2_analyzer.api.main import create_app
from c2_analyzer.preprocessing.pipeline import preprocess_html
from c2_analyzer.schemas.parsed_page import ParsedPage

SAMPLE_FILES = [
    "benign_simple.html",
    "js_exfiltration.html",
    "mixed_page.html",
    "phishing_external_form.html",
    "sinhala_urgency.html",
    "tamil_page.html",
]
MB = 1024 * 1024


@pytest.fixture
def dev_client() -> TestClient:
    return TestClient(create_app("development"))


@pytest.fixture
def prod_client() -> TestClient:
    return TestClient(create_app("production"))


def _without_timing(data: dict) -> dict:
    data = dict(data, meta=dict(data["meta"]))
    data["meta"].pop("processing_ms")
    data["meta"].pop("step_ms")
    return data


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "c2"}


# ---- POST /api/v1/preprocess ---------------------------------------------------------


@pytest.mark.parametrize("name", SAMPLE_FILES)
def test_preprocess_fixture_returns_parsed_page(dev_client, load_page, name):
    html = load_page(name)
    response = dev_client.post(
        "/api/v1/preprocess", json={"html": html, "url": "https://bank.example/login"}
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    page = ParsedPage.model_validate(response.json())
    assert page.meta.page_url == "https://bank.example/login"
    # exactly what the pipeline (and preprocess_html.py) produces, with the JSON aliases
    expected = preprocess_html(html, "https://bank.example/login").model_dump(
        mode="json", by_alias=True
    )
    assert _without_timing(response.json()) == _without_timing(expected)


def test_preprocess_facts_and_multilingual_text(dev_client, load_page):
    phishing = dev_client.post(
        "/api/v1/preprocess",
        json={"html": load_page("phishing_external_form.html"), "url": "https://bank.example/"},
    ).json()
    assert phishing["forms"][0]["is_external_action"] is True
    assert any(field["type"] == "password" for field in phishing["forms"][0]["inputs"])

    sinhala = dev_client.post(
        "/api/v1/preprocess", json={"html": load_page("sinhala_urgency.html")}
    ).json()
    assert sinhala["title"] == "ගිණුම් අනතුරු ඇඟවීම"
    assert sinhala["meta"]["page_url"] is None  # url is optional


def test_preprocess_works_in_production_too(prod_client):
    response = prod_client.post("/api/v1/preprocess", json={"html": "<p>hi</p>", "url": None})
    assert response.status_code == 200
    assert response.json()["visible_text"] == "hi"


def test_preprocess_rejects_bad_bodies(dev_client):
    assert dev_client.post("/api/v1/preprocess", json={"url": "x"}).status_code == 422
    assert dev_client.post("/api/v1/preprocess", content=b"not json").status_code == 422


def test_preprocess_oversize_body_is_413(dev_client):
    response = dev_client.post("/api/v1/preprocess", json={"html": "a" * (5 * MB + 10)})
    assert response.status_code == 413
    assert "5 MB" in response.json()["detail"]
    assert response.headers["x-content-type-options"] == "nosniff"


def test_oversize_chunked_body_without_length_is_413(dev_client):
    """A client can stream a body without Content-Length; the bytes are counted too."""

    def chunks():
        yield b'{"html": "'
        for _ in range(6):
            yield b"a" * MB
        yield b'"}'

    response = dev_client.post(
        "/api/v1/preprocess", content=chunks(), headers={"content-type": "application/json"}
    )
    assert response.status_code == 413


def test_body_just_under_the_limit_is_accepted(dev_client):
    html = "<p>" + "a" * (5 * MB - 100) + "</p>"
    response = dev_client.post("/api/v1/preprocess", json={"html": html})
    assert response.status_code == 200


def test_security_headers_on_every_response(dev_client):
    for response in (dev_client.get("/health"), dev_client.get("/no-such-page")):
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "no-referrer"


def test_legacy_gateway_stub_unchanged(dev_client):
    # /api/v1/analyze is implemented in Part 9 B-1 (tests/test_analyze.py); the gateway's
    # old /analyze-html stays a 501 stub until the gateway switches to /api/v1/analyze.
    assert dev_client.post("/analyze-html").status_code == 501


# ---- dev routes only in development ---------------------------------------------------

DEV_PATHS = [
    "/inspector",
    "/inspector/inspector.js",
    "/api/v1/dev/versions",
    "/api/v1/dev/samples?version=v0.1",
    "/api/v1/dev/samples/c2_phishing_000001/parsed?version=v0.1",
    "/api/v1/dev/samples/c2_phishing_000001/safe-preview",
]


@pytest.mark.parametrize("env", ["production", "staging", "test"])
@pytest.mark.parametrize("path", DEV_PATHS)
def test_dev_routes_404_outside_development(env, path):
    client = TestClient(create_app(env))
    assert client.get(path).status_code == 404


def test_dev_routes_hidden_from_openapi_in_production(prod_client):
    paths = prod_client.get("/openapi.json").json()["paths"]
    assert "/api/v1/preprocess" in paths
    assert not any(path.startswith("/api/v1/dev") for path in paths)


# ---- Swagger -----------------------------------------------------------------------


def test_docs_show_endpoints_with_examples(dev_client):
    assert dev_client.get("/docs").status_code == 200
    spec = dev_client.get("/openapi.json").json()
    for path in (
        "/health",
        "/api/v1/preprocess",
        "/api/v1/dev/versions",
        "/api/v1/dev/samples",
        "/api/v1/dev/samples/{sample_id}/parsed",
        "/api/v1/dev/samples/{sample_id}/safe-preview",
    ):
        assert path in spec["paths"], path
    request_schema = spec["components"]["schemas"]["PreprocessRequest"]
    assert request_schema["examples"][0]["url"] == "https://bank.example/login"
    assert "413" in spec["paths"]["/api/v1/preprocess"]["post"]["responses"]
    assert "/inspector" not in spec["paths"]  # the page itself is not an API endpoint
