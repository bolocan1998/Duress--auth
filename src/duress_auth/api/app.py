import uuid
from fastapi import FastAPI, Request, HTTPException, Query

from src.duress_auth.storage.database import init_db
from src.duress_auth.storage.alert_metrics import get_alert_metrics
from src.duress_auth.storage.worker_metrics import get_worker_metrics
from src.duress_auth.storage.admin_alerts import (
    list_dead_letter_alerts,
    list_queue_alerts,
    replay_dead_letter_alert,
)

from src.duress_auth.api.schemas import (
    LoginRequest,
    RegisterRequest,
    TransferRequest,
    TransferResponse,
    ReplayAlertResponse,
)
from src.duress_auth.auth.service import (
    register_user_service,
    login_user_service,
    refresh_user_service,
)
from src.duress_auth.auth.duress_policy import process_transfer_request

app = FastAPI(title="DuressAuth API", version="0.1.0")


@app.get("/")
def root():
    return {"name": "DuressAuth API", "ok": True}


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/metrics/alerts")
def metrics_alerts():
    return {
        "ok": True,
        "alerts": get_alert_metrics(),
    }


@app.get("/metrics/workers")
def metrics_workers():
    init_db()
    return {
        "ok": True,
        "workers": get_worker_metrics(),
    }


@app.get("/admin/alerts/queue")
def admin_queue_alerts(limit: int = Query(default=100, ge=1, le=500)):
    init_db()
    items = list_queue_alerts(limit=limit)
    return {
        "ok": True,
        "count": len(items),
        "items": items,
    }


@app.get("/admin/alerts/dead_letter")
def admin_dead_letter(limit: int = Query(default=100, ge=1, le=500)):
    init_db()
    items = list_dead_letter_alerts(limit=limit)
    return {
        "ok": True,
        "count": len(items),
        "items": items,
    }


@app.post("/admin/alerts/replay/{dead_letter_id}", response_model=ReplayAlertResponse)
def admin_replay_dead_letter(dead_letter_id: int):
    init_db()

    result = replay_dead_letter_alert(dead_letter_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Dead letter alert not found.")

    return ReplayAlertResponse(ok=True, **result)


@app.post("/register")
def register(payload: RegisterRequest, request: Request):
    init_db()
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

    try:
        register_user_service(
            payload.username,
            payload.password,
            payload.duress_password,
        )
        return {
            "ok": True,
            "request_id": request_id,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/login")
def login(payload: LoginRequest, request: Request):
    init_db()
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

    ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    device_id = request.headers.get("X-Device-Id")

    result = login_user_service(
        payload.username,
        payload.password,
        ip=ip,
        user_agent=user_agent,
        request_id=request_id,
        device_id=device_id,
    )

    if result is None:
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    return {
        "ok": True,
        "mode": result["mode"],
        "access_token": result["access_token"],
        "refresh_token": result["refresh_token"],
        "request_id": request_id,
    }


@app.post("/refresh")
def refresh(request: Request):
    init_db()
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

    ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    device_id = request.headers.get("X-Device-Id")

    refresh_token = request.headers.get("X-Refresh-Token")
    if not refresh_token:
        raise HTTPException(status_code=400, detail="Missing refresh token.")

    result = refresh_user_service(
        refresh_token=refresh_token,
        ip=ip,
        user_agent=user_agent,
        request_id=request_id,
        device_id=device_id,
    )

    if result is None:
        raise HTTPException(status_code=401, detail="Invalid refresh token.")

    return {
        "ok": True,
        "access_token": result["access_token"],
        "refresh_token": result["refresh_token"],
        "request_id": request_id,
    }


@app.post("/transfer", response_model=TransferResponse)
def transfer(payload: TransferRequest, request: Request):
    init_db()
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

    ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    auth = request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token.")

    access_token = auth.split(" ", 1)[1].strip()

    result = process_transfer_request(
        access_token=access_token,
        amount=payload.amount,
        iban=payload.iban,
        recipient_name=payload.recipient_name,
        ip=ip,
        user_agent=user_agent,
        request_id=request_id,
    )

    if result is None:
        raise HTTPException(status_code=401, detail="Invalid or expired session.")

    return TransferResponse(**result)