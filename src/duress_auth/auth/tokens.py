import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from jose import JWTError, jwt

ISSUER = "duress-auth"
AUDIENCE = "duress-auth-clients"

SECRET_KEY = os.getenv("DURESS_AUTH_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("DURESS_AUTH_SECRET_KEY environment variable not set")

ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 30


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _base_claims(subject: str, session_id: str, token_type: str) -> Dict[str, Any]:
    now = _now()
    return {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": subject,
        "sid": session_id,
        "jti": str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "type": token_type,
    }


def create_access_token(subject: str, session_id: str) -> str:
    now = _now()
    payload = _base_claims(subject, session_id, "access")
    payload["exp"] = int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp())
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(subject: str, session_id: str) -> str:
    now = _now()
    payload = _base_claims(subject, session_id, "refresh")
    payload["exp"] = int((now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)).timestamp())
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_access_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], audience=AUDIENCE, issuer=ISSUER)
        if payload.get("type") != "access":
            return None
        return payload
    except JWTError:
        return None


def verify_refresh_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], audience=AUDIENCE, issuer=ISSUER)
        if payload.get("type") != "refresh":
            return None
        return payload
    except JWTError:
        return None