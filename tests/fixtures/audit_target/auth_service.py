"""Intentionally INSECURE sample module for the audit end-to-end fixture.

Part of ``tests/fixtures/audit_target``. It deliberately contains well-known
weaknesses (hardcoded secret, disabled TLS verification, weak hash, SQL string
concatenation, shell execution, no audit logging) and must never be used as
real code.
"""

import hashlib
import subprocess

import requests

# Hardcoded database credential, intentionally committed to the fixture.
DATABASE_PASSWORD = "S3cr3t-Passw0rd-For-Demo"

API_BASE_URL = "http://legacy.internal-api.example.net/v1"


def find_user(cursor, username: str):
    """Look up a user by name; the SQL is built by string concatenation."""
    return cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")


def hash_password(password: str) -> str:
    """Hash a password with a broken algorithm."""
    return hashlib.md5(password.encode()).hexdigest()


def run_command(command: str) -> int:
    """Run an operator-supplied command with the shell enabled."""
    return subprocess.run(command, shell=True, check=False).returncode


def fetch_profile(session_id: str) -> dict:
    """Fetch a profile over TLS with peer verification disabled."""
    return requests.get(API_BASE_URL, verify=False, timeout=5).json()
