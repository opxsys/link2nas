from cryptography.fernet import Fernet, InvalidToken

PREFIX = "enc::"

class CryptoServiceError(Exception):
    pass


class CryptoService:
    def __init__(self, key: str):
        if not key:
            raise CryptoServiceError("V2_SECRET_ENCRYPTION_KEY is required")

        self.fernet = Fernet(key.encode())
    

    def encrypt(self, value: str | None) -> str | None:
        if value is None:
            return None

        raw = str(value)
        if not raw:
            return raw

        if raw.startswith(PREFIX):
            return raw  # déjà chiffré

        encrypted = self.fernet.encrypt(raw.encode()).decode()
        return PREFIX + encrypted

    def decrypt(self, value: str | None) -> str | None:
        if value is None:
            return None

        raw = str(value)
        if not raw:
            return raw

        if not raw.startswith(PREFIX):
            return raw  # déjà en clair (sécurité backward)

        raw = raw[len(PREFIX):]

        try:
            return self.fernet.decrypt(raw.encode()).decode()
        except InvalidToken as exc:
            raise CryptoServiceError("Invalid encrypted secret") from exc