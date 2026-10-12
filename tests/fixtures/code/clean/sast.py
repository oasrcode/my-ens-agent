"""Clean fixture: parameterised queries and safe deserialisation."""

import json
import subprocess

import yaml


def find_user(cursor, name: str):
    """Parameterised SQL, no string building."""
    return cursor.execute("SELECT * FROM users WHERE name = %s", (name,))


def run_command(args: list[str]) -> int:
    """Run an explicit argument list without a shell."""
    return subprocess.run(args, check=True).returncode


def load_config(raw: str) -> dict:
    """Safe YAML loader."""
    return yaml.safe_load(raw)


def load_state(blob: str) -> dict:
    """Plain JSON parsing, no object deserialisation."""
    return json.loads(blob)
