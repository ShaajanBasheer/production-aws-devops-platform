from .models import SecurityEvent


def get_events() -> list[SecurityEvent]:
    from .database import get_database_connection

    connection = get_database_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    source,
                    event_type,
                    username,
                    source_ip,
                    endpoint,
                    status_code,
                    message,
                    timestamp
                FROM security_events
                ORDER BY id ASC
                """
            )

            rows = cursor.fetchall()

        return [
            SecurityEvent(
                source=row[0],
                event_type=row[1],
                username=row[2],
                source_ip=row[3],
                endpoint=row[4],
                status_code=row[5],
                message=row[6],
                timestamp=row[7],
            )
            for row in rows
        ]

    finally:
        connection.close()


def add_alert(alert: dict) -> dict:
    from .database import get_database_connection

    connection = get_database_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO security_alerts (
                    alert_type,
                    severity,
                    source_ip,
                    username,
                    attempt_count,
                    message
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id, created_at
                """,
                (
                    alert.get("alert_type"),
                    alert.get("severity"),
                    alert.get("source_ip"),
                    alert.get("username"),
                    alert.get("attempt_count"),
                    alert.get("message"),
                ),
            )

            row = cursor.fetchone()

        connection.commit()

        alert["id"] = row[0]
        alert["created_at"] = row[1]

        return alert

    finally:
        connection.close()


def get_alerts() -> list[dict]:
    from .database import get_database_connection

    connection = get_database_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    alert_type,
                    severity,
                    source_ip,
                    username,
                    attempt_count,
                    message,
                    created_at
                FROM security_alerts
                ORDER BY id ASC
                """
            )

            rows = cursor.fetchall()

        return [
            {
                "id": row[0],
                "alert_type": row[1],
                "severity": row[2],
                "source_ip": row[3],
                "username": row[4],
                "attempt_count": row[5],
                "message": row[6],
                "created_at": row[7],
            }
            for row in rows
        ]

    finally:
        connection.close()


def get_alert(alert_id: int) -> dict | None:
    from .database import get_database_connection

    connection = get_database_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    alert_type,
                    severity,
                    source_ip,
                    username,
                    attempt_count,
                    message,
                    created_at
                FROM security_alerts
                WHERE id = %s
                """,
                (alert_id,),
            )

            row = cursor.fetchone()

        if row is None:
            return None

        return {
            "id": row[0],
            "alert_type": row[1],
            "severity": row[2],
            "source_ip": row[3],
            "username": row[4],
            "attempt_count": row[5],
            "message": row[6],
            "created_at": row[7],
        }

    finally:
        connection.close()


def add_event_to_database(event: SecurityEvent) -> SecurityEvent:
    from .database import get_database_connection

    connection = get_database_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO security_events (
                    source,
                    event_type,
                    username,
                    source_ip,
                    endpoint,
                    status_code,
                    message,
                    timestamp
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    event.source,
                    event.event_type,
                    event.username,
                    event.source_ip,
                    event.endpoint,
                    event.status_code,
                    event.message,
                    event.timestamp,
                ),
            )

        connection.commit()

    finally:
        connection.close()

    return event
