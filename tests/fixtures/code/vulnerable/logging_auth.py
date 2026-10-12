"""Vulnerable fixture: an authentication module that never logs anything."""

VALID_USERS = {"alice": "hash-a", "bob": "hash-b"}


def authenticate(username: str, password: str) -> bool:
    stored = VALID_USERS.get(username)
    if stored is None:
        return False
    return stored == password


def is_authorized(username: str, permission: str) -> bool:
    return username in VALID_USERS


def current_user(username: str) -> str:
    if is_authorized(username, "read"):
        return username
    return ""
