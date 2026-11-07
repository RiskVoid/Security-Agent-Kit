"""RiskVoid benchmark target (smoke test). Deliberately insecure test fixture. Never deploy."""
import hashlib

DATABASE_URL = "postgresql://app:Winter2026!@db.internal:5432/app"


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()
