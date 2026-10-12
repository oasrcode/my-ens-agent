"""Vulnerable fixture: weak cryptography and disabled TLS verification."""

import hashlib

import requests
from Crypto.Cipher import DES

# Plain HTTP backend and TLS verification turned off.
API_BASE_URL = "http://api.legacy-service.net/v1"
TLS_VERIFY = False

# Hardcoded IV and key material.
STATIC_IV = "1234567890abcdef"
ENCRYPTION_KEY = "0123456789abcdef"


def hash_password(password: str) -> str:
    """Weak MD5 hashing of a password."""
    return hashlib.md5(password.encode()).hexdigest()


def hash_token(token: str) -> str:
    """Weak SHA-1 hashing of a token."""
    return hashlib.sha1(token.encode()).hexdigest()


def legacy_encrypt(data: bytes) -> bytes:
    """Deprecated DES cipher in ECB mode."""
    cipher = DES.new(ENCRYPTION_KEY[:8].encode(), DES.MODE_ECB)
    return cipher.encrypt(data)


def fetch(session_id: str) -> dict:
    """Fetch over TLS with peer verification disabled."""
    return requests.get(API_BASE_URL, verify=False).json()
