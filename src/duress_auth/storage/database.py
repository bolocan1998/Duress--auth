import sqlite3
from pathlib import Path

DB_PATH = Path("data") / "duress_auth.db"


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {r["name"] for r in rows}


def _add_column_if_missing(conn: sqlite3.Connection, table: str, column_def: str, column_name: str) -> None:
    cols = _table_columns(conn, table)
    if column_name in cols:
        return
    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column_def}")


def init_db() -> None:
    with get_connection() as conn:
        # users
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                duress_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                lock_until TEXT,
                last_failed_at TEXT
            )
            """
        )

        # audit logs
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                event_type TEXT NOT NULL,
                success INTEGER NOT NULL,
                details TEXT NOT NULL,
                ip TEXT,
                user_agent TEXT,
                request_id TEXT,
                session_id TEXT,
                timestamp TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_logs(username)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_username_ts ON audit_logs(username, timestamp)")

        # sessions
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                mode TEXT NOT NULL, -- real|duress
                device_label TEXT,
                created_at TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                revoked_at TEXT,
                revoke_reason TEXT,
                last_ip TEXT,
                last_user_agent TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_revoked ON sessions(revoked)")

        # refresh tokens
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                username TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                revoked_at TEXT,
                ip TEXT,
                user_agent TEXT,
                device_id TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_refresh_username ON refresh_tokens(username)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_refresh_session ON refresh_tokens(session_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_refresh_hash ON refresh_tokens(token_hash)")

        # alert queue
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                session_id TEXT,
                alert_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                scheduled_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_username ON alert_queue(username)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_scheduled ON alert_queue(scheduled_at)")

        # dead letter queue (DLQ)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_dead_letter (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_alert_id INTEGER,
                username TEXT NOT NULL,
                session_id TEXT,
                alert_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                scheduled_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                failed_at TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                last_error TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dlq_username ON alert_dead_letter(username)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dlq_failed_at ON alert_dead_letter(failed_at)")

        # ---- schema upgrades for alert_queue (safe migration) ----
        # Note: SQLite can't ADD COLUMN IF NOT EXISTS => we probe PRAGMA and ALTER if missing.
        _add_column_if_missing(conn, "alert_queue", "status TEXT NOT NULL DEFAULT 'pending'", "status")
        _add_column_if_missing(conn, "alert_queue", "attempts INTEGER NOT NULL DEFAULT 0", "attempts")
        _add_column_if_missing(conn, "alert_queue", "last_error TEXT", "last_error")
        _add_column_if_missing(conn, "alert_queue", "locked_by TEXT", "locked_by")
        _add_column_if_missing(conn, "alert_queue", "locked_at TEXT", "locked_at")
        _add_column_if_missing(conn, "alert_queue", "processed_at TEXT", "processed_at")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_status_sched ON alert_queue(status, scheduled_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_lock ON alert_queue(locked_at, locked_by)")

        conn.commit()