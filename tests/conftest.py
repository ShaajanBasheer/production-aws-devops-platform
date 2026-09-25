import pytest

from app.database import get_database_connection


TEST_IPS = [
    "203.0.113.60",
    "203.0.113.61",
    "203.0.113.62",
    "203.0.113.63",
    "203.0.113.64",
    "203.0.113.65",
    "198.51.100.62",
    "198.51.100.63",
    "198.51.100.150",
    "198.51.100.170",
]


def cleanup_test_data():
    connection = get_database_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                DELETE FROM security_alerts
                WHERE source_ip = ANY(%s)
                """,
                (TEST_IPS,),
            )

            cursor.execute(
                """
                DELETE FROM security_events
                WHERE source_ip = ANY(%s)
                """,
                (TEST_IPS,),
            )

        connection.commit()

    finally:
        connection.close()


@pytest.fixture(autouse=True)
def clean_test_data():
    cleanup_test_data()

    yield

    cleanup_test_data()
