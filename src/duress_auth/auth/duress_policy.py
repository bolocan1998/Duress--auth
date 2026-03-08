import uuid

from src.duress_auth.auth.tokens import verify_access_token
from src.duress_auth.audit.logger import log_event
from src.duress_auth.storage.database import get_connection, init_db
from src.duress_auth.storage.alert_queue import enqueue_alert


TRANSFER_EVENT = "TRANSFER"
TRANSFER_REAL = "transfer_real"
TRANSFER_DURESS_SIMULATED = "transfer_duress_simulated"
TRANSFER_INVALID_SESSION = "transfer_invalid_session"


def _get_session_mode(session_id: str) -> tuple[str | None, str | None]:
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT username, mode
            FROM sessions
            WHERE id = ? AND revoked = 0
            """,
            (session_id,),
        ).fetchone()

    if row is None:
        return None, None

    return row["username"], row["mode"]


def process_transfer_request(
    access_token: str,
    amount: float,
    iban: str,
    recipient_name: str,
    ip: str | None = None,
    user_agent: str | None = None,
    request_id: str | None = None,
) -> dict | None:
    """
    REAL mode:
      - treat as real transfer success (simulated backend for now)

    DURESS mode:
      - return plausible success
      - DO NOT execute real transfer
      - enqueue silent/high-priority alert
    """
    init_db()

    payload = verify_access_token((access_token or "").strip())
    if payload is None:
        return None

    username = payload.get("sub")
    session_id = payload.get("sid")
    if not username or not session_id:
        return None

    db_username, mode = _get_session_mode(session_id)
    if not db_username or not mode:
        log_event(
            username or "unknown",
            TRANSFER_EVENT,
            False,
            TRANSFER_INVALID_SESSION,
            ip,
            user_agent,
            request_id,
            session_id=session_id,
        )
        return None

    transfer_id = str(uuid.uuid4())

    if mode == "duress":
        # fake success + silent incident
        enqueue_alert(
            username=db_username,
            session_id=session_id,
            alert_type="DURESS_TRANSFER_ATTEMPT",
            delay_seconds=0,
            payload={
                "kind": "high_risk_transaction_attempt",
                "reason": "duress_session_transfer_attempt",
                "amount": amount,
                "iban": iban,
                "recipient_name": recipient_name,
                "ip": ip,
                "user_agent": user_agent,
                "request_id": request_id,
                "transfer_id": transfer_id,
            },
        )

        log_event(
            db_username,
            TRANSFER_EVENT,
            True,
            TRANSFER_DURESS_SIMULATED,
            ip,
            user_agent,
            request_id,
            session_id=session_id,
        )

        return {
            "ok": True,
            "executed": False,
            "simulated": True,
            "status": "accepted",
            "transfer_id": transfer_id,
            "message": "Transfer submitted successfully.",
            "mode": "duress",
        }

    # REAL mode (for now still simulated backend success, but treated as real path)
    log_event(
        db_username,
        TRANSFER_EVENT,
        True,
        TRANSFER_REAL,
        ip,
        user_agent,
        request_id,
        session_id=session_id,
    )

    return {
        "ok": True,
        "executed": True,
        "simulated": False,
        "status": "accepted",
        "transfer_id": transfer_id,
        "message": "Transfer submitted successfully.",
        "mode": "real",
    }