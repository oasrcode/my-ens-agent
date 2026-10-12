"""Clean fixture: a security module with proper audit logging."""

import logging

logger = logging.getLogger(__name__)


class AuthError(Exception):
    """Raised when authentication cannot be completed."""


def authenticate(username: str, supplied_hash: str, expected_hash: str) -> bool:
    if supplied_hash != expected_hash:
        logger.warning("authentication failed for %s", username)
        return False
    logger.info("authentication succeeded for %s", username)
    return True


def authorize(username: str, permission: str, grants: dict) -> bool:
    allowed = permission in grants.get(username, set())
    if not allowed:
        logger.warning("access denied for %s on %s", username, permission)
    return allowed


def run(username: str) -> bool:
    try:
        return authenticate(username, "h", "h")
    except AuthError as exc:
        logger.error("authentication error for %s: %s", username, exc)
        return False
