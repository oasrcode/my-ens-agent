"""Vulnerable fixture: logs a secret and swallows every error."""

import logging

logger = logging.getLogger(__name__)


def login(username: str, password: str) -> None:
    try:
        do_login(username, password)
    except Exception:
        pass
    logger.debug("login attempt for %s with password %s", username, password)
