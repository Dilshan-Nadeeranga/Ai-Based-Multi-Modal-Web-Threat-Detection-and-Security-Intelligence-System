"""scripts/capture_webpages.py with a fake browser and resolver (no network)."""

from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

from app.services import capture_service
from tests.capture_fakes import FakeCapturer, fake_resolver

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import capture_webpages  # noqa: E402


@pytest.fixture
def fake(monkeypatch) -> FakeCapturer:
    browser = FakeCapturer()
    monkeypatch.setattr(capture_service, "PlaywrightCapturer", lambda settings, policy: browser)
    monkeypatch.setattr(socket, "getaddrinfo", fake_resolver)
    return browser


def _run(settings, *args: str) -> int:
    return capture_webpages.main(["--data-dir", str(settings.data_dir), "--delay", "0", *args])


def test_capture_legitimate_samples(dataset_settings, dataset_service, make_request, fake, capsys) -> None:
    legit = dataset_service.add_sample(make_request(embedded_urls=["https://example.com/"]))
    dataset_service.add_sample(make_request(embedded_urls=[]))

    assert _run(dataset_settings, "--all") == 0
    assert "No selected sample" in capsys.readouterr().out

    assert _run(dataset_settings, "--all", "--include-synthetic") == 0
    output = capsys.readouterr().out
    assert f"CAPTURED  {legit.sample_id}  https://example.com/" in output
    assert f"data/webpage_screenshots/{legit.sample_id}_web_01.png" in output
    assert "Captured 1," in output
    assert fake.opened == ["https://example.com/"]


def test_scam_samples_need_explicit_flag(dataset_settings, dataset_service, make_request, fake, capsys) -> None:
    scam = dataset_service.add_sample(make_request(
        embedded_urls=["https://prize.example.com/claim"], is_scam=1, scam_type="phishing"))

    assert _run(dataset_settings, "--sample-id", scam.sample_id) == 2
    assert "--allow-scam-urls" in capsys.readouterr().err
    assert fake.opened == []

    assert _run(dataset_settings, "--sample-id", scam.sample_id, "--allow-scam-urls") == 0
    assert fake.opened == ["https://prize.example.com/claim"]


def test_dry_run_opens_nothing(dataset_settings, dataset_service, make_request, fake, capsys) -> None:
    sample = dataset_service.add_sample(make_request(
        embedded_urls=["https://example.com/", "http://192.168.0.1/", "https://www.facebook.com/x"],
        is_scam=1, scam_type="phishing"))
    assert _run(dataset_settings, "--sample-id", sample.sample_id, "--dry-run") == 0
    output = capsys.readouterr().out
    assert "OPEN     " in output and "BLOCK PRIVATE_ADDRESS" in output and "BLOCK SOCIAL_MEDIA_URL" in output
    assert "1 would be opened, 2 blocked" in output
    assert fake.opened == []
    assert not dataset_settings.webpage_captures_path.exists()


def test_selection_required_and_unknown_id(dataset_settings, fake, capsys) -> None:
    with pytest.raises(SystemExit):
        _run(dataset_settings)
    with pytest.raises(SystemExit, match="Unknown sample_id"):
        _run(dataset_settings, "--sample-id", "SVT_009999")
