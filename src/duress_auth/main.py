import argparse

from src.duress_auth.auth.register import register_user
from src.duress_auth.auth.login import login_user


def main() -> None:
    parser = argparse.ArgumentParser(
        description="DuressAuth - Coercion-resistant authentication (CLI + API)"
    )
    parser.add_argument(
        "command",
        choices=["register", "login", "whoami", "refresh", "api"],
        help="Command to execute",
    )
    args = parser.parse_args()

    if args.command == "register":
        register_user()
        return

    if args.command == "login":
        login_user()
        return

    if args.command == "whoami":
        from src.duress_auth.auth.tokens import verify_access_token

        token = input("Access token: ").strip()
        payload = verify_access_token(token)
        if payload is None:
            print("Invalid or expired token.")
            return

        print(f"Authenticated as: {payload.get('sub')}")
        print(f"Session ID: {payload.get('sid')}")
        return

    if args.command == "refresh":
        from src.duress_auth.auth.service import refresh_user_service

        old_refresh = input("Refresh token: ").strip()

        result = refresh_user_service(
            refresh_token=old_refresh,
            ip="127.0.0.1",
            user_agent="cli",
            request_id=None,
        )

        if result is None:
            print("Invalid / reused / expired refresh token.")
            return

        print("New access token:")
        print(result["access_token"])
        print("New refresh token:")
        print(result["refresh_token"])
        return

    if args.command == "api":
        # Start FastAPI server
        import uvicorn
        from src.duress_auth.api.app import create_app

        app = create_app()
        uvicorn.run(app, host="127.0.0.1", port=8000, reload=True)
        return


if __name__ == "__main__":
    main()