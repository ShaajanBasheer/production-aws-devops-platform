from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_authentication_failure_alert():
    event = {
        "source": "web-server-01",
        "event_type": "authentication_failure",
        "username": "admin",
        "source_ip": "198.51.100.150",
    }

    for _ in range(4):
        response = client.post("/events", json=event)

        assert response.status_code == 200
        assert response.json()["alert"] is None

    response = client.post("/events", json=event)

    assert response.status_code == 200

    data = response.json()

    assert data["alert"] is not None
    assert data["alert"]["alert_type"] == "repeated_authentication_failures"
    assert data["alert"]["severity"] == "high"
    assert data["alert"]["attempt_count"] == 5


def test_http_error_spike_alert():
    event = {
        "source": "web-server-01",
        "event_type": "http_request",
        "source_ip": "198.51.100.170",
        "status_code": 401,
    }

    for _ in range(4):
        response = client.post("/events", json=event)

        assert response.status_code == 200
        assert response.json()["alert"] is None

    event["status_code"] = 403

    response = client.post("/events", json=event)

    assert response.status_code == 200

    data = response.json()

    assert data["alert"] is not None
    assert data["alert"]["alert_type"] == "http_error_spike"
    assert data["alert"]["severity"] == "medium"
    assert data["alert"]["attempt_count"] == 5
