"""Clean fixture: strong cryptography and verified TLS."""

import hashlib
import secrets

import requests

API_BASE_URL = "https://api.example.org/v1"


def hash_password(password: str, salt: bytes) -> str:
    """Strong SHA-256 hashing with a per-record salt."""
    return hashlib.sha256(salt + password.encode()).hexdigest()


def new_iv() -> bytes:
    """Generate a fresh random IV for every message."""
    return secrets.token_bytes(16)


def fetch() -> dict:
    """Fetch over TLS with peer verification enabled."""
    return requests.get(API_BASE_URL, verify=True, timeout=10).json()
