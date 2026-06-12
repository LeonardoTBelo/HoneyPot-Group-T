"""
logger.py — Honeypot Structured Logging Module
Logs all honeypot interactions to a JSON file and optionally to the console.
"""

import json
import logging
import os
from datetime import datetime, timezone


LOG_FILE = os.path.join(os.path.dirname(__file__), "honeypot.log")


class JsonFormatter(logging.Formatter):
    """Custom formatter that outputs each log record as a JSON object."""

    def format(self, record):
        log_entry = record.__dict__.get("log_data", {})
        log_entry["level"] = record.levelname
        return json.dumps(log_entry)


def _setup_logger():
    logger = logging.getLogger("honeypot")
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:
        # File handler — one JSON object per line
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setFormatter(JsonFormatter())
        logger.addHandler(file_handler)

        # Console handler — same format so it's easy to read during dev
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(JsonFormatter())
        logger.addHandler(console_handler)

    return logger


_logger = _setup_logger()


def _log(event_type: str, data: dict):
    """Internal helper — attaches timestamp and event_type then logs."""
    entry = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event": event_type,
        **data,
    }
    record = logging.LogRecord(
        name="honeypot",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="",
        args=(),
        exc_info=None,
    )
    record.log_data = entry
    _logger.handle(record)


# ── Public API ────────────────────────────────────────────────────────────────

def log_connection(source_ip: str, source_port: int, service: str):
    """Log a new incoming connection."""
    _log("connection", {
        "source_ip": source_ip,
        "source_port": source_port,
        "service": service,
    })


def log_login_attempt(source_ip: str, service: str, username: str, password: str, success: bool):
    """Log an authentication attempt with credentials."""
    _log("login_attempt", {
        "source_ip": source_ip,
        "service": service,
        "username": username,
        "password": password,
        "success": success,
    })


def log_command(source_ip: str, service: str, session_id: str, command: str):
    """Log a command or input sent by the attacker."""
    _log("command", {
        "source_ip": source_ip,
        "service": service,
        "session_id": session_id,
        "command": command,
    })


def log_disconnection(source_ip: str, service: str, session_id: str, duration_seconds: float):
    """Log when an attacker disconnects."""
    _log("disconnection", {
        "source_ip": source_ip,
        "service": service,
        "session_id": session_id,
        "duration_seconds": round(duration_seconds, 2),
    })
