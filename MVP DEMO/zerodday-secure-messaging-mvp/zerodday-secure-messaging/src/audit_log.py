"""
ZeroDay Secure Messaging — Security Audit Logger
Logs security-relevant events: key operations, handshake steps,
encryption/decryption, failures, replay detection, session lifecycle.
"""
import logging
import time
import json
import os
from datetime import datetime, timezone
from enum import Enum


class SecurityEvent(str, Enum):
    # Key lifecycle
    KEY_GENERATED = "KEY_GENERATED"
    KEY_REGISTERED = "KEY_REGISTERED"
    KEY_REVOKED = "KEY_REVOKED"
    KEY_ZEROED = "KEY_ZEROED"

    # Handshake
    HANDSHAKE_STARTED = "HANDSHAKE_STARTED"
    HANDSHAKE_COMPLETED = "HANDSHAKE_COMPLETED"
    HANDSHAKE_FAILED = "HANDSHAKE_FAILED"
    SIG_VERIFIED = "SIG_VERIFIED"
    SIG_FAILED = "SIG_FAILED"
    CIPHER_NEGOTIATED = "CIPHER_NEGOTIATED"

    # Messaging
    MSG_ENCRYPTED = "MSG_ENCRYPTED"
    MSG_DECRYPTED = "MSG_DECRYPTED"
    MSG_SIGNED = "MSG_SIGNED"
    MSG_VERIFIED = "MSG_VERIFIED"

    # Attacks detected
    REPLAY_DETECTED = "REPLAY_DETECTED"
    TAMPER_DETECTED = "TAMPER_DETECTED"
    MITM_DETECTED = "MITM_DETECTED"
    INVALID_VERSION = "INVALID_VERSION"
    CIPHER_MISMATCH = "CIPHER_MISMATCH"

    # Session lifecycle
    SESSION_CREATED = "SESSION_CREATED"
    SESSION_CLOSED = "SESSION_CLOSED"
    SESSION_EXPIRED = "SESSION_EXPIRED"

    # Document
    DOC_SIGNED = "DOC_SIGNED"
    DOC_VERIFIED = "DOC_VERIFIED"
    DOC_TAMPERED = "DOC_TAMPERED"

    # Blockchain
    CHAIN_VALIDATED = "CHAIN_VALIDATED"
    CHAIN_TAMPER_DETECTED = "CHAIN_TAMPER_DETECTED"


class SecurityLogger:
    """Structured security event logger.

    Writes JSON-structured logs to both file and console.
    Each entry includes: timestamp, event type, severity, session context,
    and event-specific details.
    """

    SEVERITY_MAP = {
        SecurityEvent.KEY_GENERATED: "INFO",
        SecurityEvent.KEY_REGISTERED: "INFO",
        SecurityEvent.KEY_REVOKED: "WARNING",
        SecurityEvent.KEY_ZEROED: "DEBUG",
        SecurityEvent.HANDSHAKE_STARTED: "INFO",
        SecurityEvent.HANDSHAKE_COMPLETED: "INFO",
        SecurityEvent.HANDSHAKE_FAILED: "ERROR",
        SecurityEvent.SIG_VERIFIED: "DEBUG",
        SecurityEvent.SIG_FAILED: "CRITICAL",
        SecurityEvent.CIPHER_NEGOTIATED: "INFO",
        SecurityEvent.MSG_ENCRYPTED: "DEBUG",
        SecurityEvent.MSG_DECRYPTED: "DEBUG",
        SecurityEvent.MSG_SIGNED: "DEBUG",
        SecurityEvent.MSG_VERIFIED: "DEBUG",
        SecurityEvent.REPLAY_DETECTED: "CRITICAL",
        SecurityEvent.TAMPER_DETECTED: "CRITICAL",
        SecurityEvent.MITM_DETECTED: "CRITICAL",
        SecurityEvent.INVALID_VERSION: "ERROR",
        SecurityEvent.CIPHER_MISMATCH: "ERROR",
        SecurityEvent.SESSION_CREATED: "INFO",
        SecurityEvent.SESSION_CLOSED: "INFO",
        SecurityEvent.SESSION_EXPIRED: "WARNING",
        SecurityEvent.DOC_SIGNED: "INFO",
        SecurityEvent.DOC_VERIFIED: "INFO",
        SecurityEvent.DOC_TAMPERED: "CRITICAL",
        SecurityEvent.CHAIN_VALIDATED: "INFO",
        SecurityEvent.CHAIN_TAMPER_DETECTED: "CRITICAL",
    }

    def __init__(self, log_file: str = None, console: bool = True):
        self.logger = logging.getLogger("zerodday.security")
        self.logger.setLevel(logging.DEBUG)
        self.logger.handlers.clear()

        formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%dT%H:%M:%S'
        )

        if console:
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            ch.setFormatter(formatter)
            self.logger.addHandler(ch)

        if log_file:
            os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
            fh = logging.FileHandler(log_file)
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(formatter)
            self.logger.addHandler(fh)

        self._events: list[dict] = []

    def log(self, event: SecurityEvent, session_id: str = None, **details):
        """Log a security event with structured data."""
        severity = self.SEVERITY_MAP.get(event, "INFO")
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event.value,
            "severity": severity,
            "session_id": session_id or "N/A",
            **details,
        }
        self._events.append(entry)

        # Format for readable logging
        detail_str = " ".join(f"{k}={v}" for k, v in details.items()) if details else ""
        msg = f"[{event.value}] session={session_id or 'N/A'} {detail_str}"

        level = getattr(logging, severity, logging.INFO)
        self.logger.log(level, msg)

    def get_events(self, event_type: SecurityEvent = None) -> list[dict]:
        """Retrieve logged events, optionally filtered by type."""
        if event_type:
            return [e for e in self._events if e["event"] == event_type.value]
        return list(self._events)

    def get_security_incidents(self) -> list[dict]:
        """Get all CRITICAL severity events (potential attacks)."""
        return [e for e in self._events if e["severity"] == "CRITICAL"]

    def export_json(self, filepath: str):
        """Export all events as a JSON file for audit."""
        with open(filepath, "w") as f:
            json.dump(self._events, f, indent=2)

    def summary(self) -> dict:
        """Return a summary of logged events by severity."""
        counts = {}
        for e in self._events:
            sev = e["severity"]
            counts[sev] = counts.get(sev, 0) + 1
        return {
            "total_events": len(self._events),
            "by_severity": counts,
            "incidents": len(self.get_security_incidents()),
        }


# Global logger instance — modules import and use this
audit_log = SecurityLogger(log_file=None, console=False)


def init_logging(log_file: str = None, console: bool = True):
    """Initialize the global audit logger."""
    global audit_log
    audit_log = SecurityLogger(log_file=log_file, console=console)
    return audit_log
