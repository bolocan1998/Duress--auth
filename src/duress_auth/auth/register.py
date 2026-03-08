import getpass

from src.duress_auth.auth.service import register_user_service

def register_user() -> None:
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    duress_password = getpass.getpass("Duress password: ")

    try:
        register_user_service(username, password, duress_password)
        print("User successfully registered.")
    except ValueError as e:
        print(str(e))
