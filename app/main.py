from fastapi import FastAPI

from .detection import analyze_event
from .models import SecurityEvent
from .storage import (
    add_alert,
    add_event,
    get_alert,
    get_alerts,
    get_events,
)


app = FastAPI(
    title="Security Log Analytics & Alerting Platform",
    description="Security event ingestion and detection API",
    version="1.0.0",
)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "security-log-analytics",
    }


@app.post("/events")
def ingest_event(event: SecurityEvent):
    add_event(event)

    alert = analyze_event(event)

    if alert:
        add_alert(alert)

    return {
        "event": event,
        "alert": alert,
    }


@app.get("/events")
def get_all_events():
    events = get_events()

    return {
        "count": len(events),
        "events": events,
    }


@app.get("/alerts")
def get_all_alerts():
    alerts = get_alerts()

    return {
        "count": len(alerts),
        "alerts": alerts,
    }


@app.get("/alerts/{alert_id}")
def get_alert_by_id(alert_id: int):
    alert = get_alert(alert_id)

    if alert:
        return alert

    return {
        "error": "Alert not found",
        "alert_id": alert_id,
    }
