import getpass
import uuid

from src.duress_auth.auth.service import login_user_service


def login_user() -> None:
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    request_id = str(uuid.uuid4())

    result = login_user_service(
        username=username,
        password=password,
        ip="127.0.0.1",
        user_agent="cli",
        request_id=request_id,
    )

    if result is None:
        print("Invalid credentials.")
        return

    print("Login successful.")
    print("Session ID:", result["session_id"])
    print("Access token:", result["access_token"])
    print("Refresh token:", result["refresh_token"])