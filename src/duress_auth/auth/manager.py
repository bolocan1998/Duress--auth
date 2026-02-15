from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


class AuthManager:
    def __init__(self):
        self.ph = PasswordHasher()

    def hash_password(self, password: str) -> str:
        return self.ph.hash(password)

    def verify_password(self, hashed_password: str, plain_password: str) -> bool:
        try:
            self.ph.verify(hashed_password, plain_password)
            return True
        except VerifyMismatchError:
            return False
