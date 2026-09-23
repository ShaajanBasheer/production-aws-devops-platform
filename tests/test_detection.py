from app.detection import analyze_event, failed_attempts
from app.models import SecurityEvent


def test_authentication_failure_alert():
    failed_attempts.clear()

    for _ in range(4):
        event = SecurityEvent(
            source="web-server-01",
            event_type="authentication_failure",
            username="admin",
            source_ip="203.0.113.50",
        )

        alert = analyze_event(event)

        assert alert is None

    event = SecurityEvent(
        source="web-server-01",
        event_type="authentication_failure",
        username="admin",
        source_ip="203.0.113.50",
    )

    alert = analyze_event(event)

    assert alert is not None
    assert alert["alert_type"] == "repeated_authentication_failures"
    assert alert["severity"] == "high"
    assert alert["attempt_count"] == 5


def test_http_error_spike_alert():
    failed_attempts.clear()

    from app.detection import http_errors

    http_errors.clear()

    for _ in range(4):
        event = SecurityEvent(
            source="web-server-01",
            event_type="http_request",
            source_ip="203.0.113.70",
            status_code=401,
        )

        alert = analyze_event(event)

        assert alert is None

    event = SecurityEvent(
        source="web-server-01",
        event_type="http_request",
        source_ip="203.0.113.70",
        status_code=403,
    )

    alert = analyze_event(event)

    assert alert is not None
    assert alert["alert_type"] == "http_error_spike"
    assert alert["severity"] == "medium"
    assert alert["error_count"] == 5
