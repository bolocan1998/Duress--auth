import json
import time
from dataclasses import dataclass
from typing import Any

from src.duress_auth.storage.alert_queue import claim_due_alerts, ack_alert, fail_alert
from src.duress_auth.audit.logger import log_event

ALERT_PROCESSED = "ALERT_PROCESSED"
ALERT_FAILED = "ALERT_FAILED"


@dataclass(frozen=True)
class WorkerConfig:
    worker_name: str = "worker-1"
    poll_interval_seconds: float = 1.0
    batch_size: int = 25
    lock_ttl_seconds: int = 60
    max_attempts: int = 3


def _simulate_admin_notification(alert_type: str, username: str, payload: dict[str, Any]) -> None:
    print(f"[ADMIN] {alert_type} user={username} payload={json.dumps(payload, ensure_ascii=False)}")


def _simulate_email(alert_type: str, username: str, payload: dict[str, Any]) -> None:
    print(f"[EMAIL] To=security@company.local | Subject={alert_type} | user={username} | data={json.dumps(payload, ensure_ascii=False)}")


def _simulate_soc_event(alert_type: str, username: str, payload: dict[str, Any]) -> None:
    severity = payload.get("severity") or ("high" if "MISMATCH" in alert_type else "info")
    print(f"[SOC] severity={severity} event={alert_type} user={username} ts={payload.get('ts')}")


def _process_one(alert) -> None:
    if alert.alert_type == "DURESS_LOGIN":
        _simulate_admin_notification(alert.alert_type, alert.username, alert.payload)
        time.sleep(0.05)
        _simulate_email(alert.alert_type, alert.username, alert.payload)
        time.sleep(0.05)
        _simulate_soc_event(alert.alert_type, alert.username, alert.payload)
        return

    if alert.alert_type in ("FINGERPRINT_MISMATCH", "REFRESH_REUSE"):
        _simulate_soc_event(alert.alert_type, alert.username, alert.payload)
        time.sleep(0.05)
        _simulate_admin_notification(alert.alert_type, alert.username, alert.payload)
        return

    _simulate_soc_event(alert.alert_type, alert.username, alert.payload)


def run_worker(config: WorkerConfig | None = None) -> None:
    cfg = config or WorkerConfig()
    print(f"[WORKER] started name={cfg.worker_name} poll={cfg.poll_interval_seconds}s batch={cfg.batch_size}")

    while True:
        try:
            claimed = claim_due_alerts(
                worker_name=cfg.worker_name,
                limit=cfg.batch_size,
                lock_ttl_seconds=cfg.lock_ttl_seconds,
            )

            if not claimed:
                time.sleep(cfg.poll_interval_seconds)
                continue

            for alert in claimed:
                try:
                    _process_one(alert)

                    log_event(
                        alert.username,
                        ALERT_PROCESSED,
                        True,
                        f"processed:{alert.alert_type}",
                        ip=alert.payload.get("ip"),
                        user_agent=alert.payload.get("user_agent"),
                        request_id=alert.payload.get("request_id"),
                        session_id=alert.session_id,
                    )

                    ack_alert(alert.id, cfg.worker_name, delete=True)

                except Exception as e:
                    log_event(
                        alert.username,
                        ALERT_FAILED,
                        False,
                        f"failed:{alert.alert_type}:{e}",
                        ip=alert.payload.get("ip"),
                        user_agent=alert.payload.get("user_agent"),
                        request_id=alert.payload.get("request_id"),
                        session_id=alert.session_id,
                    )

                    fail_alert(alert.id, cfg.worker_name, str(e), max_attempts=cfg.max_attempts)

        except KeyboardInterrupt:
            print("\n[WORKER] stopped by user")
            return
        except Exception as e:
            print(f"[WORKER] loop error: {e}")
            time.sleep(1.0)


if __name__ == "__main__":
    run_worker()