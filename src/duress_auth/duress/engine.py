from src.duress_auth.audit.logger import log_event


def activate_duress_mode(username: str) -> None:
    # aici pui ce vrei: alert, dummy session, trigger, etc.
    log_event(username, event_type="duress_activated", success=True, details="Duress mode triggered during login")
    print("Duress mode activated.")