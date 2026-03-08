import sqlite3
import time
from datetime import datetime, timezone, timedelta

from src.duress_auth.audit.logger import log_event
from src.duress_auth.audit.events import (
    # login events
    LOGIN,
    USER_NOT_FOUND,
    BAD_PASSWORD,
    ACCOUNT_LOCKED,
    RATE_LIMITED_IP,
    MODE_REAL,
    MODE_DURESS,
    # refresh events
    REFRESH,
    REFRESH_INVALID,
    REFRESH_REUSED,
    REFRESH_ROTATED,
    INCIDENT,
    INCIDENT_REFRESH_REUSE,
)

from src.duress_auth.auth.manager import AuthManager
from src.duress_auth.auth.sessions import (
    create_session,
    is_session_active,
    touch_session,
    revoke_session,
)
from src.duress_auth.auth.tokens import (
    create_access_token,
    create_refresh_token,
    verify_refresh_token,
    verify_access_token,
)
from src.duress_auth.auth.refresh_store import (
    store_refresh_token,
    is_refresh_token_active,
    is_refresh_token_known,
    rotate_refresh_token,
    revoke_all_refresh_for_session,
    is_refresh_fingerprint_ok,
)
from src.duress_auth.auth.rate_limiter import check_ip_rate_limit
from src.duress_auth.duress.engine import activate_duress_mode
from src.duress_auth.storage.alert_queue import enqueue_alert
from src.duress_auth.storage.database import get_connection, init_db

# ---- tuning ----
MAX_ATTEMPTS_BEFORE_LOCK = 5
BASE_LOCK_SECONDS = 30
MAX_LOCK_SECONDS = 15 * 60

# Timing mitigation
MIN_AUTH_MS = 300

# Duress silent alarm delay
DURESS_ALERT_DELAY_SECONDS = 120


# -------------------------
# time helpers
# -------------------------
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _parse_iso(dt_str: str | None) -> datetime | None:
    if not dt_str:
        return None
    try:
        dt = datetime.fromisoformat(dt_str)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _calc_lock_seconds(failed_attempts: int) -> int:
    over = max(0, failed_attempts - MAX_ATTEMPTS_BEFORE_LOCK)
    seconds = BASE_LOCK_SECONDS * (2 ** over)
    return min(seconds, MAX_LOCK_SECONDS)


def _min_elapsed_sleep(start_perf: float, min_ms: int = MIN_AUTH_MS) -> None:
    elapsed_ms = (time.perf_counter() - start_perf) * 1000.0
    remaining = (min_ms - elapsed_ms) / 1000.0
    if remaining > 0:
        time.sleep(remaining)


# -------------------------
# DB helpers (users)
# -------------------------
def _reset_lock_state(conn, user_id: int) -> None:
    conn.execute(
        """
        UPDATE users
        SET failed_attempts = 0,
            lock_until = NULL,
            last_failed_at = NULL
        WHERE id = ?
        """,
        (user_id,),
    )


def _apply_failed_attempt(conn, user_id: int, failed_attempts: int, now: datetime) -> None:
    new_lock_until = None
    if failed_attempts >= MAX_ATTEMPTS_BEFORE_LOCK:
        new_lock_until = now + timedelta(seconds=_calc_lock_seconds(failed_attempts))

    conn.execute(
        """
        UPDATE users
        SET failed_attempts = ?,
            last_failed_at = ?,
            lock_until = ?
        WHERE id = ?
        """,
        (
            failed_attempts,
            _iso(now),
            _iso(new_lock_until) if new_lock_until else None,
            user_id,
        ),
    )


# -------------------------
# token/session helpers
# -------------------------
def _issue_tokens_and_store_refresh(
    username: str,
    session_id: str,
    ip: str | None,
    user_agent: str | None,
    device_id: str | None,
) -> tuple[str, str]:
    access_token = create_access_token(subject=username, session_id=session_id)
    refresh_token = create_refresh_token(subject=username, session_id=session_id)

    store_refresh_token(
        username=username,
        session_id=session_id,
        refresh_token=refresh_token,
        ip=ip,
        user_agent=user_agent,
        device_id=device_id,
    )

    return access_token, refresh_token


# -------------------------
# public API
# -------------------------
def register_user_service(username: str, password: str, duress_password: str) -> None:
    init_db()

    username = (username or "").strip()

    if len(username) < 3:
        raise ValueError("Username must be at least 3 characters.")
    if len(password) < 10:
        raise ValueError("Password must be at least 10 characters.")
    if password == duress_password:
        raise ValueError("Duress password must be different from real password.")

    auth = AuthManager()
    password_hash = auth.hash_password(password)
    duress_hash = auth.hash_password(duress_password)

    try:
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, duress_hash) VALUES (?, ?, ?)",
                (username, password_hash, duress_hash),
            )
            conn.commit()
    except sqlite3.IntegrityError:
        raise ValueError("Username already exists.")


def login_user_service(
    username: str,
    password: str,
    ip: str | None = None,
    user_agent: str | None = None,
    request_id: str | None = None,
    device_label: str | None = None,
    device_id: str | None = None,
) -> dict | None:
    """
    Returns:
      {"mode": "...", "session_id": "...", "access_token": "...", "refresh_token": "..."}
      or None on failure (uniform for API).
    """
    start = time.perf_counter()
    init_db()

    username = (username or "").strip()
    auth = AuthManager()

    # server protection: rate limit by IP
    if ip and not check_ip_rate_limit(ip):
        log_event(username, LOGIN, False, RATE_LIMITED_IP, ip, user_agent, request_id, session_id=None)
        _min_elapsed_sleep(start)
        return None

    # timing mitigation dummy
    dummy_hash = auth.hash_password("dummy_password_for_timing_mitigation")

    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT
                id,
                username,
                password_hash,
                duress_hash,
                failed_attempts,
                lock_until
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

        if row is None:
            auth.verify_password(dummy_hash, password)
            log_event(username, LOGIN, False, USER_NOT_FOUND, ip, user_agent, request_id, session_id=None)
            _min_elapsed_sleep(start)
            return None

        user_id = row["id"]
        failed_attempts = int(row["failed_attempts"] or 0)
        lock_until = _parse_iso(row["lock_until"])
        now = _now_utc()

        # locked account (uniform failure)
        if lock_until and now < lock_until:
            auth.verify_password(row["password_hash"], password)
            log_event(username, LOGIN, False, ACCOUNT_LOCKED, ip, user_agent, request_id, session_id=None)
            _min_elapsed_sleep(start)
            return None

        real_ok = auth.verify_password(row["password_hash"], password)
        duress_ok = auth.verify_password(row["duress_hash"], password)

        if real_ok:
            _reset_lock_state(conn, user_id)
            conn.commit()

            session_id = create_session(
                username=username,
                mode="real",
                device_label=device_label,
                ip=ip,
                user_agent=user_agent,
            )

            log_event(username, LOGIN, True, MODE_REAL, ip, user_agent, request_id, session_id=session_id)
            access_token, refresh_token = _issue_tokens_and_store_refresh(username, session_id, ip, user_agent, device_id)

            _min_elapsed_sleep(start)
            return {
                "mode": "real",
                "session_id": session_id,
                "access_token": access_token,
                "refresh_token": refresh_token,
            }

        if duress_ok:
            _reset_lock_state(conn, user_id)
            conn.commit()

            session_id = create_session(
                username=username,
                mode="duress",
                device_label=device_label,
                ip=ip,
                user_agent=user_agent,
            )

            log_event(username, LOGIN, True, MODE_DURESS, ip, user_agent, request_id, session_id=session_id)
            access_token, refresh_token = _issue_tokens_and_store_refresh(username, session_id, ip, user_agent, device_id)

            # duress side effect (your decoy + deception engine entrypoint)
            activate_duress_mode(username)

            # SILENT ALARM: enqueue delayed alert
            enqueue_alert(
                username=username,
                session_id=session_id,
                alert_type="DURESS_LOGIN",
                delay_seconds=DURESS_ALERT_DELAY_SECONDS,
                payload={
                    "kind": "silent_alarm",
                    "reason": "duress_password_used",
                    "ip": ip,
                    "user_agent": user_agent,
                    "device_id": device_id,
                    "request_id": request_id,
                    "ts": _iso(_now_utc()),
                },
            )

            _min_elapsed_sleep(start)
            return {
                "mode": "duress",
                "session_id": session_id,
                "access_token": access_token,
                "refresh_token": refresh_token,
            }

        # bad password path
        failed_attempts += 1
        _apply_failed_attempt(conn, user_id, failed_attempts, now)
        conn.commit()

    log_event(username, LOGIN, False, BAD_PASSWORD, ip, user_agent, request_id, session_id=None)
    _min_elapsed_sleep(start)
    return None


def refresh_user_service(
    refresh_token: str,
    ip: str | None = None,
    user_agent: str | None = None,
    request_id: str | None = None,
    device_id: str | None = None,
) -> dict | None:
    init_db()
    token = (refresh_token or "").strip()

    payload = verify_refresh_token(token)
    if payload is None:
        log_event("unknown", REFRESH, False, REFRESH_INVALID, ip, user_agent, request_id, session_id=None)
        return None

    username = payload.get("sub")
    session_id = payload.get("sid")

    if not username or not session_id:
        log_event("unknown", REFRESH, False, REFRESH_INVALID, ip, user_agent, request_id, session_id=None)
        return None

    if not is_session_active(session_id):
        log_event(username, REFRESH, False, REFRESH_INVALID, ip, user_agent, request_id, session_id=session_id)
        return None

    # fingerprint binding check BEFORE rotation
    if not is_refresh_fingerprint_ok(
        username=username,
        session_id=session_id,
        refresh_token=token,
        ip=ip,
        user_agent=user_agent,
        device_id=device_id,
    ):
        revoke_all_refresh_for_session(session_id)
        revoke_session(session_id, reason="fingerprint_mismatch")

        log_event(username, REFRESH, False, "FINGERPRINT_MISMATCH", ip, user_agent, request_id, session_id=session_id)
        log_event(username, INCIDENT, False, "INCIDENT_FINGERPRINT_MISMATCH", ip, user_agent, request_id, session_id=session_id)

        # enqueue SOC-style alert immediately
        enqueue_alert(
            username=username,
            session_id=session_id,
            alert_type="FINGERPRINT_MISMATCH",
            delay_seconds=0,
            payload={
                "kind": "incident",
                "severity": "high",
                "reason": "refresh_fingerprint_mismatch",
                "ip": ip,
                "user_agent": user_agent,
                "device_id": device_id,
                "request_id": request_id,
                "ts": _iso(_now_utc()),
            },
        )
        return None

    # ACTIVE token -> ROTATE
    if is_refresh_token_active(username, session_id, token):
        new_access = create_access_token(subject=username, session_id=session_id)
        new_refresh = create_refresh_token(subject=username, session_id=session_id)

        ok = rotate_refresh_token(username, session_id, token, new_refresh)
        if not ok:
            log_event(username, REFRESH, False, REFRESH_INVALID, ip, user_agent, request_id, session_id=session_id)
            return None

        touch_session(session_id, ip, user_agent)
        log_event(username, REFRESH, True, REFRESH_ROTATED, ip, user_agent, request_id, session_id=session_id)

        return {
            "username": username,
            "session_id": session_id,
            "access_token": new_access,
            "refresh_token": new_refresh,
        }

    # KNOWN but revoked -> REUSE DETECTED
    if is_refresh_token_known(username, session_id, token):
        revoke_all_refresh_for_session(session_id)
        revoke_session(session_id, reason="refresh_reuse_detected")

        log_event(username, REFRESH, False, REFRESH_REUSED, ip, user_agent, request_id, session_id=session_id)
        log_event(username, INCIDENT, False, INCIDENT_REFRESH_REUSE, ip, user_agent, request_id, session_id=session_id)

        enqueue_alert(
            username=username,
            session_id=session_id,
            alert_type="REFRESH_REUSE",
            delay_seconds=0,
            payload={
                "kind": "incident",
                "severity": "critical",
                "reason": "refresh_reuse_detected",
                "ip": ip,
                "user_agent": user_agent,
                "device_id": device_id,
                "request_id": request_id,
                "ts": _iso(_now_utc()),
            },
        )
        return None

    log_event(username, REFRESH, False, REFRESH_INVALID, ip, user_agent, request_id, session_id=session_id)
    return None


def me_user_service(
    access_token: str,
    ip: str | None = None,
    user_agent: str | None = None,
    request_id: str | None = None,
) -> dict | None:
    init_db()
    token = (access_token or "").strip()

    payload = verify_access_token(token)
    if payload is None:
        return None

    username = payload.get("sub")
    session_id = payload.get("sid")
    if not username or not session_id:
        return None

    if not is_session_active(session_id):
        return None

    touch_session(session_id, ip, user_agent)
    return {"username": username, "session_id": session_id}


def logout_user_service(
    refresh_token: str | None,
    ip: str | None = None,
    user_agent: str | None = None,
    request_id: str | None = None,
) -> None:
    init_db()

    if not refresh_token:
        return

    token = refresh_token.strip()
    payload = verify_refresh_token(token)
    if payload is None:
        return

    username = payload.get("sub") or "unknown"
    session_id = payload.get("sid")
    if not session_id:
        return

    revoke_all_refresh_for_session(session_id)
    revoke_session(session_id, reason="logout")

    log_event(username, "LOGOUT", True, "USER_LOGOUT", ip, user_agent, request_id, session_id=session_id)