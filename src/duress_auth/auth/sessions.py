import uuid
from datetime import datetime, timezone
from typing import Optional

from src.duress_auth.storage.database import get_connection


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_session(
    username: str,
    mode: str,
    device_label: Optional[str] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> str:
    session_id = str(uuid.uuid4())
    now = _now()

    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO sessions
            (id, username, mode, device_label, created_at, last_seen, revoked, revoked_at, revoke_reason, last_ip, last_user_agent)
            VALUES (?, ?, ?, ?, ?, ?, 0, NULL, NULL, ?, ?)
            """,
            (session_id, username, mode, device_label, now, now, ip, user_agent),
        )
        conn.commit()

    return session_id


def is_session_active(session_id: str) -> bool:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT revoked FROM sessions WHERE id = ?",
            (session_id,),
        ).fetchone()
    if row is None:
        return False
    return int(row["revoked"]) == 0


def touch_session(session_id: str, ip: Optional[str] = None, user_agent: Optional[str] = None) -> None:
    now = _now()
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE sessions
            SET last_seen = ?,
                last_ip = COALESCE(?, last_ip),
                last_user_agent = COALESCE(?, last_user_agent)
            WHERE id = ?
            """,
            (now, ip, user_agent, session_id),
        )
        conn.commit()


def revoke_session(session_id: str, reason: str = "revoked") -> None:
    now = _now()
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE sessions
            SET revoked = 1,
                revoke_reason = ?,
                revoked_at = ?
            WHERE id = ?
            """,
            (reason, now, session_id),
        )
        conn.commit()