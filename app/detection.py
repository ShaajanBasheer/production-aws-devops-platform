import logging

from .models import SecurityEvent
from .storage import (
    count_recent_authentication_failures,
    count_recent_http_errors,
    has_recent_alert,
)


logger = logging.getLogger(__name__)


# Detection configuration.
FAILURE_THRESHOLD = 5
WINDOW_MINUTES = 5
HTTP_ERROR_THRESHOLD = 5
ALERT_COOLDOWN_MINUTES = 5


def analyze_event(event: SecurityEvent) -> dict | None:
    """
    Analyze a security event using recent events stored in PostgreSQL.
    Return an alert if a detection rule is triggered.
    """

    if not event.source_ip:
        logger.info(
            "Detection skipped | reason=missing_source_ip | event_type=%s",
            event.event_type,
        )
        return None

    # Rule 1:
    # Detect repeated authentication failures from the same IP.
    if event.event_type == "authentication_failure":
        attempt_count = count_recent_authentication_failures(
            event.source_ip,
            WINDOW_MINUTES,
        )

        logger.info(
            "Detection evaluated | rule=repeated_authentication_failures | "
            "source_ip=%s | attempt_count=%s | threshold=%s",
            event.source_ip,
            attempt_count,
            FAILURE_THRESHOLD,
        )

        if attempt_count >= FAILURE_THRESHOLD:
            if has_recent_alert(
                "repeated_authentication_failures",
                event.source_ip,
                ALERT_COOLDOWN_MINUTES,
            ):
                logger.info(
                    "Alert suppressed by cooldown | "
                    "rule=repeated_authentication_failures | "
                    "source_ip=%s | cooldown_minutes=%s",
                    event.source_ip,
                    ALERT_COOLDOWN_MINUTES,
                )
                return None

            logger.warning(
                "Detection rule triggered | "
                "rule=repeated_authentication_failures | "
                "source_ip=%s | attempt_count=%s | severity=high",
                event.source_ip,
                attempt_count,
            )

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

        logger.info(
            "Detection evaluated | rule=http_error_spike | "
            "source_ip=%s | error_count=%s | threshold=%s",
            event.source_ip,
            error_count,
            HTTP_ERROR_THRESHOLD,
        )

        if error_count >= HTTP_ERROR_THRESHOLD:
            if has_recent_alert(
                "http_error_spike",
                event.source_ip,
                ALERT_COOLDOWN_MINUTES,
            ):
                logger.info(
                    "Alert suppressed by cooldown | "
                    "rule=http_error_spike | "
                    "source_ip=%s | cooldown_minutes=%s",
                    event.source_ip,
                    ALERT_COOLDOWN_MINUTES,
                )
                return None

            logger.warning(
                "Detection rule triggered | "
                "rule=http_error_spike | "
                "source_ip=%s | error_count=%s | severity=medium",
                event.source_ip,
                error_count,
            )

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
