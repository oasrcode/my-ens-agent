"""Vulnerable fixture: risky sinks (injection, eval/exec, unsafe loads)."""

import os
import pickle
import subprocess

import yaml


def find_user(cursor, name: str):
    """SQL built by string concatenation."""
    return cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")


def run_command(command: str) -> int:
    """Shell execution of an untrusted command."""
    return os.system(command)


def run_shell(command: str) -> int:
    """subprocess with shell=True."""
    return subprocess.run(command, shell=True, check=False).returncode


def evaluate(expression: str):
    """Dynamic code execution."""
    return eval(expression)


def execute(code: str):
    """Dynamic code execution via exec."""
    return exec(code)


def load_state(blob: bytes):
    """Unsafe pickle deserialisation."""
    return pickle.loads(blob)


def load_config(raw: str):
    """yaml.load without a safe loader."""
    return yaml.load(raw)
