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


def test_authentication_alert_is_suppressed_during_cooldown():
    event = {
        "source": "web-server-01",
        "event_type": "authentication_failure",
        "username": "admin",
        "source_ip": "198.51.100.151",
    }

    for _ in range(4):
        response = client.post("/events", json=event)

        assert response.status_code == 200
        assert response.json()["alert"] is None

    response = client.post("/events", json=event)

    assert response.status_code == 200

    first_alert = response.json()["alert"]

    assert first_alert is not None
    assert first_alert["alert_type"] == "repeated_authentication_failures"
    assert first_alert["attempt_count"] == 5

    response = client.post("/events", json=event)

    assert response.status_code == 200
    assert response.json()["alert"] is None

    response = client.get("/alerts")

    assert response.status_code == 200

    matching_alerts = [
        alert
        for alert in response.json()["alerts"]
        if alert["source_ip"] == "198.51.100.151"
    ]

    assert len(matching_alerts) == 1
    assert matching_alerts[0]["id"] == first_alert["id"]


def test_http_error_alert_is_suppressed_during_cooldown():
    event = {
        "source": "web-server-01",
        "event_type": "http_request",
        "source_ip": "198.51.100.171",
        "status_code": 401,
    }

    for _ in range(4):
        response = client.post("/events", json=event)

        assert response.status_code == 200
        assert response.json()["alert"] is None

    event["status_code"] = 403

    response = client.post("/events", json=event)

    assert response.status_code == 200

    first_alert = response.json()["alert"]

    assert first_alert is not None
    assert first_alert["alert_type"] == "http_error_spike"
    assert first_alert["attempt_count"] == 5

    event["status_code"] = 500

    response = client.post("/events", json=event)

    assert response.status_code == 200
    assert response.json()["alert"] is None

    response = client.get("/alerts")

    assert response.status_code == 200

    matching_alerts = [
        alert
        for alert in response.json()["alerts"]
        if alert["source_ip"] == "198.51.100.171"
    ]

    assert len(matching_alerts) == 1
    assert matching_alerts[0]["id"] == first_alert["id"]
