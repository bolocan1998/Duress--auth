# Event types
LOGIN = "login"
REFRESH = "refresh"
LOGOUT = "logout"
SESSION = "session"
INCIDENT = "incident"
DECEPTION = "deception"

# Login details
USER_NOT_FOUND = "user_not_found"
BAD_PASSWORD = "bad_password"
ACCOUNT_LOCKED = "account_locked"
RATE_LIMITED_IP = "rate_limited_ip"
MODE_REAL = "mode_real"
MODE_DURESS = "mode_duress"

# Refresh details
REFRESH_OK = "refresh_ok"
REFRESH_ROTATED = "refresh_rotated"
REFRESH_REUSED = "refresh_reused"
REFRESH_REVOKED = "refresh_revoked"
REFRESH_INVALID = "refresh_invalid"

# Session details
SESSION_CREATED = "session_created"
SESSION_REVOKED = "session_revoked"
SESSION_REVOKE_ALL = "session_revoke_all"

# Incident details
INCIDENT_REFRESH_REUSE = "incident_refresh_reuse"
INCIDENT_SUSPICIOUS = "incident_suspicious"

# Deception details
DECEPTION_FAKE_SESSION = "deception_fake_session"
DECEPTION_TELEMETRY = "deception_telemetry"
DELAYED_ALERT_QUEUED = "delayed_alert_queued"