import hashlib
from datetime import datetime, timezone
from typing import Optional

from src.duress_auth.storage.database import get_connection


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def store_refresh_token(
    username: str,
    session_id: str,
    refresh_token: str,
    ip: str | None = None,
    user_agent: str | None = None,
    device_id: str | None = None,
) -> None:
    token_hash = _hash_token(refresh_token)
    now = _now()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO refresh_tokens (session_id, username, token_hash, revoked, created_at, ip, user_agent, device_id)
            VALUES (?, ?, ?, 0, ?, ?, ?, ?)
            """,
            (session_id, username, token_hash, now, ip, user_agent, device_id),
        )
        conn.commit()


def revoke_all_refresh_for_session(session_id: str) -> None:
    now = _now()
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE refresh_tokens
            SET revoked = 1, revoked_at = ?
            WHERE session_id = ? AND revoked = 0
            """,
            (now, session_id),
        )
        conn.commit()


def is_refresh_token_active(username: str, session_id: str, refresh_token: str) -> bool:
    token_hash = _hash_token(refresh_token)
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT id
            FROM refresh_tokens
            WHERE username = ? AND session_id = ? AND token_hash = ? AND revoked = 0
            """,
            (username, session_id, token_hash),
        ).fetchone()
    return row is not None


def is_refresh_token_known(username: str, session_id: str, refresh_token: str) -> bool:
    """
    Known = exists in DB (revoked or not).
    Used for reuse detection.
    """
    token_hash = _hash_token(refresh_token)
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT id
            FROM refresh_tokens
            WHERE username = ? AND session_id = ? AND token_hash = ?
            """,
            (username, session_id, token_hash),
        ).fetchone()
    return row is not None


def is_refresh_fingerprint_ok(
    username: str,
    session_id: str,
    refresh_token: str,
    ip: str | None,
    user_agent: str | None,
    device_id: str | None,
) -> bool:
    """
    Fingerprint policy:
      - device_id: STRICT (must match, must be present if stored)
      - user_agent: STRICT (must match, must be present if stored)
      - ip: optional strict (STRICT_IP)

    Notes:
      - We bind to the fingerprint stored with the ACTIVE token row.
      - If client stops sending device_id/user_agent -> fail.
    """
    STRICT_IP = False  # flip to True if you want IP strict

    token_hash = _hash_token(refresh_token)

    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT ip, user_agent, device_id
            FROM refresh_tokens
            WHERE username = ? AND session_id = ? AND token_hash = ? AND revoked = 0
            LIMIT 1
            """,
            (username, session_id, token_hash),
        ).fetchone()

    if row is None:
        return False

    stored_ip = row["ip"]
    stored_ua = row["user_agent"]
    stored_device = row["device_id"]

    # device strict
    if stored_device:
        if not device_id:
            return False
        if stored_device != device_id:
            return False

    # UA strict
    if stored_ua:
        if not user_agent:
            return False
        if stored_ua != user_agent:
            return False

    # IP optional strict
    if STRICT_IP and stored_ip:
        if not ip:
            return False
        if stored_ip != ip:
            return False

    return True


def rotate_refresh_token(username: str, session_id: str, old_refresh: str, new_refresh: str) -> bool:
    """
    Atomic rotation within a session.
    Return True if rotated. False if old is invalid/revoked.
    Keeps fingerprint binding from old token row.
    """
    old_hash = _hash_token(old_refresh)
    new_hash = _hash_token(new_refresh)
    now = _now()

    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            """
            SELECT id, ip, user_agent, device_id
            FROM refresh_tokens
            WHERE username = ? AND session_id = ? AND token_hash = ? AND revoked = 0
            """,
            (username, session_id, old_hash),
        ).fetchone()

        if row is None:
            conn.rollback()
            return False

        # revoke old
        conn.execute(
            "UPDATE refresh_tokens SET revoked = 1, revoked_at = ? WHERE id = ?",
            (now, row["id"]),
        )

        # insert new with SAME fingerprint binding
        conn.execute(
            """
            INSERT INTO refresh_tokens (session_id, username, token_hash, revoked, created_at, ip, user_agent, device_id)
            VALUES (?, ?, ?, 0, ?, ?, ?, ?)
            """,
            (session_id, username, new_hash, now, row["ip"], row["user_agent"], row["device_id"]),
        )

        conn.commit()
        return True