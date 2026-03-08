import time
from collections import defaultdict

# Simple in-memory rate limiter (per IP)
# max 10 attempts per 60 seconds

MAX_ATTEMPTS = 10
WINDOW_SECONDS = 60

_ip_attempts = defaultdict(list)


def check_ip_rate_limit(ip: str) -> bool:
    """
    Returns True if request is allowed.
    Returns False if rate limit exceeded.
    """

    now = time.time()

    # remove expired timestamps
    _ip_attempts[ip] = [
        ts for ts in _ip_attempts[ip]
        if now - ts < WINDOW_SECONDS
    ]

    if len(_ip_attempts[ip]) >= MAX_ATTEMPTS:
        return False

    _ip_attempts[ip].append(now)
    return True