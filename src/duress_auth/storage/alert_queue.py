import json
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Optional, List

from src.duress_auth.storage.database import get_connection


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _parse_iso(s: str) -> datetime:
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _worker_id() -> str:
    return hashlib.sha256(f"worker-{_iso(_now_utc())}".encode("utf-8")).hexdigest()[:12]


def _retry_backoff_seconds(attempts: int) -> int:
    """
    Exponential-ish backoff schedule (seconds), attempts start at 1.
      1 -> 5s
      2 -> 30s
      3 -> 300s (5m)
      4 -> 1800s (30m)
      5 -> 7200s (2h)
    Anything above -> 6h
    """
    table = {
        1: 5,
        2: 30,
        3: 300,
        4: 1800,
        5: 7200,
    }
    return table.get(int(attempts), 21600)


@dataclass(frozen=True)
class AlertItem:
    id: int
    username: str
    session_id: Optional[str]
    alert_type: str
    payload: dict[str, Any]
    scheduled_at: datetime
    created_at: datetime
    status: str
    attempts: int
    locked_by: Optional[str]
    locked_at: Optional[datetime]


def enqueue_alert(
    username: str,
    alert_type: str,
    payload: dict[str, Any],
    session_id: str | None = None,
    delay_seconds: int = 0,
) -> int:
    now = _now_utc()
    scheduled = now + timedelta(seconds=max(0, int(delay_seconds)))
    payload_json = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)

    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO alert_queue
              (username, session_id, alert_type, payload_json, scheduled_at, created_at, status, attempts)
            VALUES (?, ?, ?, ?, ?, ?, 'pending', 0)
            """,
            (username, session_id, alert_type, payload_json, _iso(scheduled), _iso(now)),
        )
        conn.commit()
        return int(cur.lastrowid)


def claim_due_alerts(
    *,
    worker_name: str | None = None,
    limit: int = 25,
    lock_ttl_seconds: int = 60,
) -> List[AlertItem]:
    worker = worker_name or _worker_id()
    now = _now_utc()
    now_iso = _iso(now)
    lock_expired_before = _iso(now - timedelta(seconds=int(lock_ttl_seconds)))

    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")

        conn.execute(
            """
            UPDATE alert_queue
            SET status = 'processing',
                locked_by = ?,
                locked_at = ?
            WHERE id IN (
                SELECT id
                FROM alert_queue
                WHERE status = 'pending'
                  AND scheduled_at <= ?
                  AND (locked_at IS NULL OR locked_at < ?)
                ORDER BY scheduled_at ASC, id ASC
                LIMIT ?
            )
            """,
            (worker, now_iso, now_iso, lock_expired_before, int(limit)),
        )

        rows = conn.execute(
            """
            SELECT id, username, session_id, alert_type, payload_json, scheduled_at, created_at,
                   status, attempts, locked_by, locked_at
            FROM alert_queue
            WHERE status = 'processing' AND locked_by = ?
            ORDER BY scheduled_at ASC, id ASC
            """,
            (worker,),
        ).fetchall()

        conn.commit()

    items: List[AlertItem] = []
    for r in rows:
        try:
            payload = json.loads(r["payload_json"])
        except Exception:
            payload = {"raw": r["payload_json"]}

        locked_at = _parse_iso(r["locked_at"]) if r["locked_at"] else None

        items.append(
            AlertItem(
                id=int(r["id"]),
                username=r["username"],
                session_id=r["session_id"],
                alert_type=r["alert_type"],
                payload=payload,
                scheduled_at=_parse_iso(r["scheduled_at"]),
                created_at=_parse_iso(r["created_at"]),
                status=r["status"],
                attempts=int(r["attempts"] or 0),
                locked_by=r["locked_by"],
                locked_at=locked_at,
            )
        )
    return items


def ack_alert(alert_id: int, worker_name: str, *, delete: bool = True) -> None:
    now_iso = _iso(_now_utc())
    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """
            UPDATE alert_queue
            SET status = 'done',
                processed_at = ?,
                locked_by = NULL,
                locked_at = NULL
            WHERE id = ? AND locked_by = ?
            """,
            (now_iso, int(alert_id), worker_name),
        )
        if delete:
            conn.execute("DELETE FROM alert_queue WHERE id = ? AND status = 'done'", (int(alert_id),))
        conn.commit()


def fail_alert(alert_id: int, worker_name: str, error: str, *, max_attempts: int = 3) -> None:
    """
    On failure:
      - attempts += 1
      - last_error set
      - scheduled_at bumped by backoff
      - unlock + status pending
      - if attempts >= max_attempts => DLQ
    """
    now = _now_utc()
    now_iso = _iso(now)
    err = (error or "")[:500]

    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")

        # Ensure ownership
        owner = conn.execute("SELECT locked_by FROM alert_queue WHERE id = ?", (int(alert_id),)).fetchone()
        if owner is None or owner["locked_by"] != worker_name:
            conn.rollback()
            return

        row = conn.execute(
            """
            SELECT id, username, session_id, alert_type, payload_json,
                   scheduled_at, created_at, attempts
            FROM alert_queue
            WHERE id = ?
            """,
            (int(alert_id),),
        ).fetchone()

        attempts = int(row["attempts"] or 0) + 1

        if attempts >= int(max_attempts):
            conn.execute(
                """
                INSERT INTO alert_dead_letter
                (original_alert_id, username, session_id, alert_type, payload_json, scheduled_at, created_at, failed_at, attempts, last_error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(alert_id),
                    row["username"],
                    row["session_id"],
                    row["alert_type"],
                    row["payload_json"],
                    row["scheduled_at"],
                    row["created_at"],
                    now_iso,
                    attempts,
                    err,
                ),
            )
            conn.execute("DELETE FROM alert_queue WHERE id = ?", (int(alert_id),))
            conn.commit()
            return

        backoff = _retry_backoff_seconds(attempts)
        new_scheduled = now + timedelta(seconds=backoff)

        conn.execute(
            """
            UPDATE alert_queue
            SET status = 'pending',
                attempts = ?,
                last_error = ?,
                scheduled_at = ?,
                locked_by = NULL,
                locked_at = NULL
            WHERE id = ? AND locked_by = ?
            """,
            (attempts, err, _iso(new_scheduled), int(alert_id), worker_name),
        )
        conn.commit()