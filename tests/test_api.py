from fastapi.testclient import TestClient

from app.detection import failed_attempts
from app.main import app


client = TestClient(app)


def setup_function():
    failed_attempts.clear()

def test_health_check():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "service": "security-log-analytics",
    }


def test_valid_event_is_accepted():
    response = client.post(
        "/events",
        json={
            "source": "web-server-01",
            "event_type": "authentication_failure",
            "username": "admin",
            "source_ip": "203.0.113.60",
            "endpoint": "/login",
            "status_code": 401,
            "message": "Invalid username or password",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["event"]["source"] == "web-server-01"
    assert data["event"]["event_type"] == "authentication_failure"
    assert data["alert"] is None


def test_invalid_status_code_is_rejected():
    response = client.post(
        "/events",
        json={
            "source": "web-server-01",
            "event_type": "authentication_failure",
            "source_ip": "203.0.113.61",
            "status_code": 999,
        },
    )

    assert response.status_code == 422


def test_alert_is_generated_after_five_failures():
    event = {
        "source": "web-server-01",
        "event_type": "authentication_failure",
        "username": "admin",
        "source_ip": "203.0.113.62",
        "endpoint": "/login",
        "status_code": 401,
    }

    for _ in range(5):
        response = client.post("/events", json=event)

    assert response.status_code == 200

    data = response.json()

    assert data["alert"] is not None
    assert data["alert"]["alert_type"] == "repeated_authentication_failures"
    assert data["alert"]["severity"] == "high"
    assert data["alert"]["attempt_count"] == 5


def test_alerts_endpoint():
    event = {
        "source": "web-server-01",
        "event_type": "authentication_failure",
        "source_ip": "203.0.113.63",
        "status_code": 401,
    }

    for _ in range(5):
        client.post("/events", json=event)

    response = client.get("/alerts")

    assert response.status_code == 200

    data = response.json()

    assert data["count"] >= 1

    matching_alerts = [
        alert
        for alert in data["alerts"]
        if alert["source_ip"] == "203.0.113.63"
    ]

    assert len(matching_alerts) >= 1
    assert matching_alerts[-1]["alert_type"] == "repeated_authentication_failures"
    assert matching_alerts[-1]["severity"] == "high"
    assert matching_alerts[-1]["attempt_count"] == 5


def test_events_endpoint():
    event = {
        "source": "web-server-01",
        "event_type": "http_request",
        "source_ip": "203.0.113.64",
        "status_code": 200,
        "endpoint": "/login",
    }

    response = client.post("/events", json=event)

    assert response.status_code == 200

    response = client.get("/events")

    assert response.status_code == 200

    data = response.json()

    assert data["count"] >= 1

    matching_events = [
        item
        for item in data["events"]
        if item["source_ip"] == "203.0.113.64"
    ]

    assert len(matching_events) >= 1
    assert matching_events[-1]["source"] == "web-server-01"



def test_get_alert_by_id():
    event = {
        "source": "web-server-01",
        "event_type": "authentication_failure",
        "source_ip": "203.0.113.65",
        "status_code": 401,
    }

    for _ in range(5):
        client.post("/events", json=event)

    response = client.get("/alerts/1")

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == 1
    assert data["alert_type"] == "repeated_authentication_failures"
    assert data["severity"] == "high"


def test_get_nonexistent_alert():
    response = client.get("/alerts/999")

    assert response.status_code == 200

    data = response.json()

    assert data["error"] == "Alert not found"
    assert data["alert_id"] == 999
