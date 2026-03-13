import hashlib
import hmac
from app.config import settings

class SecurityHelper:
    @staticmethod
    def encrypt_data(data: str) -> str:
        """Simulates data encryption using the ENCRYPTION_KEY."""
        # In a real SaaS, use cryptography.fernet or similar.
        # For this version, we'll use a simple keyed-hash for demonstration or 
        # placeholder for real encryption.
        key = settings.ENCRYPTION_KEY.encode()
        data_bytes = data.encode()
        return hmac.new(key, data_bytes, hashlib.sha256).hexdigest()

    @staticmethod
    def generate_api_secret() -> str:
        import secrets
        return secrets.token_urlsafe(32)

security_helper = SecurityHelper()
