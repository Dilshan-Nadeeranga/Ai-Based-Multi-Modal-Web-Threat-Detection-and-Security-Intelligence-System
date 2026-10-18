import json

from app.services.social_analysis_service import AnalysisInputError


class FakeSocialService:
    def __init__(self, settings, fail=False):
        self.settings = settings
        self.fail = fail
        self.calls = []

    def analyze(self, *, platform, post_text, image_file, image_filename, embedded_url, on_step=None):
        self.calls.append({"platform": platform, "post_text": post_text, "image": image_file.read() if image_file else None,
                           "image_filename": image_filename, "embedded_url": embedded_url})
        if self.fail:
            raise AnalysisInputError("Provide post text, a post image or an embedded URL.")
        on_step({"key": "ocr", "status": "running", "duration_ms": 0})
        on_step({"key": "ocr", "status": "done", "duration_ms": 12})
        return {"success": True, "pipeline": [{"key": "ocr", "status": "done", "duration_ms": 12}]}


def lines(response):
    return [json.loads(line) for line in response.text.splitlines() if line.strip()]


def test_stream_reports_steps_then_result(client, settings):
    service = FakeSocialService(settings)
    client.app.state.social_service = service
    response = client.post("/api/v1/social/analyze/stream", data={"platform": "facebook", "post_text": "hello"},
                           files={"image": ("post.png", b"image-bytes", "image/png")})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    events = lines(response)
    assert [e["type"] for e in events] == ["step", "step", "result"]
    assert [e["step"]["status"] for e in events[:2]] == ["running", "done"]
    assert events[-1]["result"]["success"] is True
    assert service.calls[0]["image"] == b"image-bytes" and service.calls[0]["image_filename"] == "post.png"


def test_stream_reports_service_errors(client, settings):
    client.app.state.social_service = FakeSocialService(settings, fail=True)
    events = lines(client.post("/api/v1/social/analyze/stream", data={"platform": "facebook"}))
    assert events == [{"type": "error", "error": {"code": "INVALID_ANALYSIS_INPUT",
                                                  "message": "Provide post text, a post image or an embedded URL.",
                                                  "status": 400}}]
