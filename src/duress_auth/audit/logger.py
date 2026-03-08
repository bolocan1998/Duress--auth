import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from src.duress_auth.storage.database import get_connection
from src.duress_auth.audit import events as E


def _severity(event_type: str, success: bool, details: str) -> str:
    if event_type in (E.INCIDENT,):
        return "ERROR"
    if event_type in (E.DECEPTION,):
        return "WARN"
    if event_type in (E.LOGIN, E.REFRESH, E.LOGOUT, E.SESSION):
        if not success and details in (E.ACCOUNT_LOCKED, E.RATE_LIMITED_IP, E.REFRESH_REUSED):
            return "WARN"
        return "INFO"
    return "INFO"


def _emit_json(record: Dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(record, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def log_event(
    username: str,
    event_type: str,
    success: bool,
    details: str,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
    session_id: Optional[str] = None,
) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    sev = _severity(event_type, success, details)

    record = {
        "ts": ts,
        "severity": sev,
        "event_type": event_type,
        "success": bool(success),
        "details": details,
        "username": username,
        "session_id": session_id,
        "ip": ip,
        "user_agent": user_agent,
        "request_id": request_id,
    }
    _emit_json(record)

    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO audit_logs (username, event_type, success, details, ip, user_agent, request_id, session_id, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (username, event_type, int(success), details, ip, user_agent, request_id, session_id, ts),
        )
        conn.commit()