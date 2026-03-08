from src.duress_auth.storage.database import get_connection


def get_alert_metrics() -> dict:
    with get_connection() as conn:
        pending = conn.execute(
            "SELECT COUNT(*) AS c FROM alert_queue WHERE status = 'pending'"
        ).fetchone()["c"]

        processing = conn.execute(
            "SELECT COUNT(*) AS c FROM alert_queue WHERE status = 'processing'"
        ).fetchone()["c"]

        total_queue = conn.execute(
            "SELECT COUNT(*) AS c FROM alert_queue"
        ).fetchone()["c"]

        dead_letter = conn.execute(
            "SELECT COUNT(*) AS c FROM alert_dead_letter"
        ).fetchone()["c"]

        by_type_rows = conn.execute(
            """
            SELECT alert_type, COUNT(*) AS c
            FROM alert_queue
            GROUP BY alert_type
            ORDER BY c DESC, alert_type ASC
            """
        ).fetchall()

        dlq_by_type_rows = conn.execute(
            """
            SELECT alert_type, COUNT(*) AS c
            FROM alert_dead_letter
            GROUP BY alert_type
            ORDER BY c DESC, alert_type ASC
            """
        ).fetchall()

    return {
        "queue": {
            "total": int(total_queue),
            "pending": int(pending),
            "processing": int(processing),
        },
        "dead_letter": {
            "total": int(dead_letter),
        },
        "by_type": {row["alert_type"]: int(row["c"]) for row in by_type_rows},
        "dead_letter_by_type": {row["alert_type"]: int(row["c"]) for row in dlq_by_type_rows},
    }