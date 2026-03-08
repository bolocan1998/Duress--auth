import os
import hashlib
import hmac


class AuthManager:
    def hash_password(self, password: str) -> str:
        salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
        return f"pbkdf2$200000${salt.hex()}${dk.hex()}"

    def verify_password(self, stored: str, password: str) -> bool:
        try:
            scheme, iterations, salt_hex, hash_hex = stored.split("$")
            if scheme != "pbkdf2":
                return False
            it = int(iterations)
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(hash_hex)
            dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, it)
            return hmac.compare_digest(dk, expected)
        except Exception:
            return False
