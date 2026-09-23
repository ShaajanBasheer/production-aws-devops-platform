from collections import defaultdict
from datetime import datetime, timedelta, timezone

from .models import SecurityEvent


# Store detection events by source IP.
# This is temporary in-memory state.
failed_attempts: dict[str, list[datetime]] = defaultdict(list)
http_errors: dict[str, list[datetime]] = defaultdict(list)


# Detection configuration.
FAILURE_THRESHOLD = 5
WINDOW_MINUTES = 5
HTTP_ERROR_THRESHOLD = 5


def analyze_event(event: SecurityEvent) -> dict | None:
    """
    Analyze a security event and return an alert if a detection rule
    is triggered. Return None when no alert is generated.
    """

    if not event.source_ip:
        return None

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=WINDOW_MINUTES)

    # Rule 1:
    # Detect repeated authentication failures from the same IP.
    if event.event_type == "authentication_failure":
        failed_attempts[event.source_ip].append(now)

        failed_attempts[event.source_ip] = [
            attempt
            for attempt in failed_attempts[event.source_ip]
            if attempt >= cutoff
        ]

        attempt_count = len(failed_attempts[event.source_ip])

        if attempt_count >= FAILURE_THRESHOLD:
            return {
                "alert_type": "repeated_authentication_failures",
                "severity": "high",
                "source_ip": event.source_ip,
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
        http_errors[event.source_ip].append(now)

        http_errors[event.source_ip] = [
            error_time
            for error_time in http_errors[event.source_ip]
            if error_time >= cutoff
        ]

        error_count = len(http_errors[event.source_ip])

        if error_count >= HTTP_ERROR_THRESHOLD:
            return {
                "alert_type": "http_error_spike",
                "severity": "medium",
                "source_ip": event.source_ip,
                "error_count": error_count,
                "window_minutes": WINDOW_MINUTES,
                "message": (
                    f"{error_count} HTTP errors detected "
                    f"from {event.source_ip} within {WINDOW_MINUTES} minutes"
                ),
            }

    return None
