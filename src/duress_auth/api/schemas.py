from pydantic import BaseModel, Field


# =========================
# REGISTER
# =========================

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3)
    password: str = Field(..., min_length=10)
    duress_password: str = Field(..., min_length=10)


class RegisterResponse(BaseModel):
    ok: bool
    request_id: str


# =========================
# LOGIN
# =========================

class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    ok: bool
    mode: str
    access_token: str
    refresh_token: str
    request_id: str


# =========================
# REFRESH
# =========================

class RefreshResponse(BaseModel):
    ok: bool
    access_token: str
    refresh_token: str
    request_id: str


# =========================
# TRANSFER
# =========================

class TransferRequest(BaseModel):
    amount: float = Field(..., gt=0)
    iban: str = Field(..., min_length=10)
    recipient_name: str = Field(..., min_length=2)


class TransferResponse(BaseModel):
    ok: bool
    executed: bool
    simulated: bool
    status: str
    transfer_id: str
    message: str
    mode: str


# =========================
# ADMIN ALERTS
# =========================

class ReplayAlertResponse(BaseModel):
    ok: bool
    dead_letter_id: int
    replayed_alert_id: int
    username: str
    session_id: str | None = None
    alert_type: str
    payload: dict