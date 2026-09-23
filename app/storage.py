from .models import SecurityEvent


events: list[SecurityEvent] = []
alerts: list[dict] = []


def add_event(event: SecurityEvent) -> SecurityEvent:
    events.append(event)
    return event


def get_events() -> list[SecurityEvent]:
    return events


def add_alert(alert: dict) -> dict:
    alert["id"] = len(alerts) + 1
    alerts.append(alert)
    return alert


def get_alerts() -> list[dict]:
    return alerts


def get_alert(alert_id: int) -> dict | None:
    for alert in alerts:
        if alert["id"] == alert_id:
            return alert

    return None
