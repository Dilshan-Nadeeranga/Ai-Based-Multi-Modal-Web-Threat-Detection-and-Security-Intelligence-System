"""API tests (Part 9). Only /health is implemented so far."""


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "c2"}
