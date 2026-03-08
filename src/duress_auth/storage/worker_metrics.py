from src.duress_auth.storage.database import get_connection


def get_worker_metrics() -> dict:
    with get_connection() as conn:
        pending = conn.execute(
            "SELECT COUNT(*) AS c FROM alert_queue WHERE status = 'pending'"
        ).fetchone()["c"]

        processing = conn.execute(
            "SELECT COUNT(*) AS c FROM alert_queue WHERE status = 'processing'"
        ).fetchone()["c"]

        dead_letter = conn.execute(
            "SELECT COUNT(*) AS c FROM alert_dead_letter"
        ).fetchone()["c"]

        alert_processed = conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM audit_logs
            WHERE event_type = 'ALERT_PROCESSED'
            """
        ).fetchone()["c"]

        alert_failed = conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM audit_logs
            WHERE event_type = 'ALERT_FAILED'
            """
        ).fetchone()["c"]

        last_processed_row = conn.execute(
            """
            SELECT timestamp
            FROM audit_logs
            WHERE event_type = 'ALERT_PROCESSED'
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()

        last_failed_row = conn.execute(
            """
            SELECT timestamp
            FROM audit_logs
            WHERE event_type = 'ALERT_FAILED'
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()

    return {
        "worker_pipeline": {
            "healthy": processing >= 0,  # simple operational check
            "queue_pending": int(pending),
            "queue_processing": int(processing),
            "dead_letter_total": int(dead_letter),
        },
        "audit_counters": {
            "alerts_processed": int(alert_processed),
            "alerts_failed": int(alert_failed),
        },
        "last_events": {
            "last_processed_at": last_processed_row["timestamp"] if last_processed_row else None,
            "last_failed_at": last_failed_row["timestamp"] if last_failed_row else None,
        },
    }