from .models import SecurityEvent
from .storage import (
    count_recent_authentication_failures,
    count_recent_http_errors,
)


# Detection configuration.
FAILURE_THRESHOLD = 5
WINDOW_MINUTES = 5
HTTP_ERROR_THRESHOLD = 5


def analyze_event(event: SecurityEvent) -> dict | None:
    """
    Analyze a security event using recent events stored in PostgreSQL.
    Return an alert if a detection rule is triggered.
    """

    if not event.source_ip:
        return None

    # Rule 1:
    # Detect repeated authentication failures from the same IP.
    if event.event_type == "authentication_failure":
        attempt_count = count_recent_authentication_failures(
            event.source_ip,
            WINDOW_MINUTES,
        )

        if attempt_count >= FAILURE_THRESHOLD:
            return {
                "alert_type": "repeated_authentication_failures",
                "severity": "high",
                "source_ip": event.source_ip,
                "username": event.username,
                "attempt_count": attempt_count,
                "window_minutes": WINDOW_MINUTES,
                "message": (
                    f"{attempt_count} authentication failures detected "
                    f"from {event.source_ip} within {WINDOW_MINUTES} minutes"
                ),
            }

    # Rule 2:
    # Detect repeated HTTP error responses from the same IP.
    if event.status_code in {401, 403, 500}:
        error_count = count_recent_http_errors(
            event.source_ip,
            WINDOW_MINUTES,
        )

        if error_count >= HTTP_ERROR_THRESHOLD:
            return {
                "alert_type": "http_error_spike",
                "severity": "medium",
                "source_ip": event.source_ip,
                "username": event.username,
                "attempt_count": error_count,
                "window_minutes": WINDOW_MINUTES,
                "message": (
                    f"{error_count} HTTP errors detected "
                    f"from {event.source_ip} within {WINDOW_MINUTES} minutes"
                ),
            }

    return None
