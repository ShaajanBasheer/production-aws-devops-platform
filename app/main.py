import logging
import time

from fastapi import FastAPI, Request

from .detection import analyze_event
from .logging_config import configure_logging
from .models import SecurityEvent
from .storage import (
    add_alert,
    add_event_to_database,
    get_alert,
    get_alerts,
    get_events,
)


configure_logging()

logger = logging.getLogger(__name__)


app = FastAPI(
    title="Security Log Analytics & Alerting Platform",
    description="Security event ingestion and detection API",
    version="1.0.0",
)


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    start_time = time.perf_counter()

    try:
        response = await call_next(request)

        duration_ms = (time.perf_counter() - start_time) * 1000

        logger.info(
            "HTTP request completed | method=%s | path=%s | status=%s | duration_ms=%.2f",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
        )

        return response

    except Exception:
        duration_ms = (time.perf_counter() - start_time) * 1000

        logger.exception(
            "HTTP request failed | method=%s | path=%s | duration_ms=%.2f",
            request.method,
            request.url.path,
            duration_ms,
        )

        raise


@app.get("/health")
def health_check():
    logger.info("Health check requested")

    return {
        "status": "healthy",
        "service": "security-log-analytics",
    }


@app.post("/events")
def ingest_event(event: SecurityEvent):
    logger.info(
        "Security event received | source=%s | event_type=%s | source_ip=%s",
        event.source,
        event.event_type,
        event.source_ip,
    )

    add_event_to_database(event)

    alert = analyze_event(event)

    if alert:
        add_alert(alert)

        logger.warning(
            "Security alert generated | alert_type=%s | severity=%s | source_ip=%s",
            alert["alert_type"],
            alert["severity"],
            alert["source_ip"],
        )

    return {
        "event": event,
        "alert": alert,
    }


@app.get("/events")
def get_all_events():
    logger.info("Events requested")

    events = get_events()

    return {
        "count": len(events),
        "events": events,
    }


@app.get("/alerts")
def get_all_alerts():
    logger.info("Alerts requested")

    alerts = get_alerts()

    return {
        "count": len(alerts),
        "alerts": alerts,
    }


@app.get("/alerts/{alert_id}")
def get_alert_by_id(alert_id: int):
    logger.info("Alert requested | alert_id=%s", alert_id)

    alert = get_alert(alert_id)

    if alert:
        return alert

    logger.warning("Alert not found | alert_id=%s", alert_id)

    return {
        "error": "Alert not found",
        "alert_id": alert_id,
    }
