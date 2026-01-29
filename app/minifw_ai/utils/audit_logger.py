"""
Thread-safe JSONL Audit Logger for MiniFW-AI

Provides regulator-grade audit trail logging using Python's logging module
for thread-safety in async FastAPI environments.
"""
from __future__ import annotations

import os
import json
import logging
from datetime import datetime, timezone
from typing import Optional

# Dedicated audit logger - thread-safe via Python logging module
_audit_logger: Optional[logging.Logger] = None


def reset_audit_logger() -> None:
    """
    Reset the audit logger state. Used for testing to allow
    re-initialization with different paths between tests.
    """
    global _audit_logger
    if _audit_logger is not None:
        for handler in _audit_logger.handlers[:]:
            handler.close()
            _audit_logger.removeHandler(handler)
    _audit_logger = None


def _get_audit_logger() -> logging.Logger:
    """
    Lazy initialization of the audit logger.
    Uses Python's logging.FileHandler which is thread-safe.
    """
    global _audit_logger
    
    if _audit_logger is not None and _audit_logger.handlers:
        return _audit_logger
    
    path = os.getenv("MINIFW_AUDIT_LOG", "/opt/minifw_ai/logs/audit.jsonl")
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(path), exist_ok=True)
    
    # Create dedicated logger (not root logger)
    _audit_logger = logging.getLogger("minifw.audit")
    _audit_logger.setLevel(logging.INFO)
    _audit_logger.propagate = False  # Don't propagate to root logger
    
    # Remove existing handlers to avoid duplicates on reinit
    for handler in _audit_logger.handlers[:]:
        _audit_logger.removeHandler(handler)
    
    # FileHandler is thread-safe
    handler = logging.FileHandler(path, encoding='utf-8')
    handler.setFormatter(logging.Formatter('%(message)s'))
    _audit_logger.addHandler(handler)
    
    return _audit_logger


def append_audit(
    event_type: str,
    action: str,
    target: str = "",
    details: Optional[dict] = None
) -> None:
    """
    Write a structured JSONL audit record.
    
    Thread-safe via Python logging module - safe for use in async FastAPI
    and multi-threaded worker environments.
    
    Args:
        event_type: Category of event (e.g., "ENFORCEMENT", "POLICY", "AUTH")
        action: Specific action (e.g., "BLOCK", "POLICY_UPDATED", "LOGIN_SUCCESS")
        target: Subject of action (IP address, username, domain, etc.)
        details: Optional additional context as dictionary
    
    Example:
        append_audit(
            event_type="ENFORCEMENT",
            action="BLOCK",
            target="192.168.1.100",
            details={"reason": "threat_score_exceeded", "score": 95}
        )
    """
    logger = _get_audit_logger()
    
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "action": action,
        "target": target,
        "details": details or {}
    }
    
    logger.info(json.dumps(entry, ensure_ascii=False))


def log_enforcement(action: str, target: str, **kwargs) -> None:
    """Convenience wrapper for enforcement audit events."""
    append_audit(event_type="ENFORCEMENT", action=action, target=target, details=kwargs)


def log_policy_change(action: str, **kwargs) -> None:
    """Convenience wrapper for policy audit events."""
    append_audit(event_type="POLICY", action=action, details=kwargs)


def log_auth_success(username: str, **kwargs) -> None:
    """Log successful authentication."""
    append_audit(event_type="AUTH", action="LOGIN_SUCCESS", target=username, details=kwargs)


def log_auth_failure(username: str, reason: str = "invalid_credentials", **kwargs) -> None:
    """Log failed authentication attempt."""
    details = {"reason": reason, **kwargs}
    append_audit(event_type="AUTH", action="LOGIN_FAILURE", target=username, details=details)
