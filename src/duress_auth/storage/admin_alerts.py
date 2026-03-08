import json

from src.duress_auth.storage.database import get_connection


def list_dead_letter_alerts(limit: int = 100) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT
                id,
                original_alert_id,
                username,
                session_id,
                alert_type,
                payload_json,
                scheduled_at,
                created_at,
                failed_at,
                attempts,
                last_error
            FROM alert_dead_letter
            ORDER BY failed_at DESC, id DESC
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()

    return [
        {
            "id": int(row["id"]),
            "original_alert_id": row["original_alert_id"],
            "username": row["username"],
            "session_id": row["session_id"],
            "alert_type": row["alert_type"],
            "payload_json": row["payload_json"],
            "scheduled_at": row["scheduled_at"],
            "created_at": row["created_at"],
            "failed_at": row["failed_at"],
            "attempts": int(row["attempts"]),
            "last_error": row["last_error"],
        }
        for row in rows
    ]


def list_queue_alerts(limit: int = 100) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT
                id,
                username,
                session_id,
                alert_type,
                payload_json,
                scheduled_at,
                created_at,
                status,
                attempts,
                last_error,
                locked_by,
                locked_at,
                processed_at
            FROM alert_queue
            ORDER BY
                CASE status
                    WHEN 'processing' THEN 0
                    WHEN 'pending' THEN 1
                    ELSE 2
                END,
                scheduled_at ASC,
                id ASC
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()

    items = []
    for row in rows:
        try:
            payload = json.loads(row["payload_json"]) if row["payload_json"] else {}
        except Exception:
            payload = {"raw": row["payload_json"]}

        items.append(
            {
                "id": int(row["id"]),
                "username": row["username"],
                "session_id": row["session_id"],
                "alert_type": row["alert_type"],
                "payload": payload,
                "scheduled_at": row["scheduled_at"],
                "created_at": row["created_at"],
                "status": row["status"],
                "attempts": int(row["attempts"] or 0),
                "last_error": row["last_error"],
                "locked_by": row["locked_by"],
                "locked_at": row["locked_at"],
                "processed_at": row["processed_at"],
            }
        )

    return items


def replay_dead_letter_alert(dead_letter_id: int) -> dict | None:
    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            """
            SELECT
                id,
                username,
                session_id,
                alert_type,
                payload_json
            FROM alert_dead_letter
            WHERE id = ?
            """,
            (int(dead_letter_id),),
        ).fetchone()

        if row is None:
            conn.rollback()
            return None

        conn.execute(
            """
            INSERT INTO alert_queue (
                username,
                session_id,
                alert_type,
                payload_json,
                scheduled_at,
                created_at,
                status,
                attempts,
                last_error,
                locked_by,
                locked_at,
                processed_at
            )
            VALUES (
                ?, ?, ?, ?,
                datetime('now'),
                datetime('now'),
                'pending',
                0,
                NULL,
                NULL,
                NULL,
                NULL
            )
            """,
            (
                row["username"],
                row["session_id"],
                row["alert_type"],
                row["payload_json"],
            ),
        )

        new_alert_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

        conn.execute(
            "DELETE FROM alert_dead_letter WHERE id = ?",
            (int(dead_letter_id),),
        )

        conn.commit()

    payload = json.loads(row["payload_json"]) if row["payload_json"] else {}
    return {
        "dead_letter_id": int(dead_letter_id),
        "replayed_alert_id": int(new_alert_id),
        "username": row["username"],
        "session_id": row["session_id"],
        "alert_type": row["alert_type"],
        "payload": payload,
    }