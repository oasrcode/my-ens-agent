"""Clean fixture: secrets are loaded from the environment, never hardcoded."""

import os

DATABASE_PASSWORD = os.environ["DATABASE_PASSWORD"]
API_KEY = os.getenv("API_KEY", "")
SESSION_TOKEN = "{{ session_token }}"
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")
