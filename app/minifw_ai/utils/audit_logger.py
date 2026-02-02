"""
Thread-safe JSONL Audit Logger for MiniFW-AI

Provides regulator-grade audit trail logging using Python's logging module
for thread-safety in async FastAPI environments.

Detection-to-Enforcement Binding:
- log_detection() generates unique event_id (UUID) and returns it
- log_enforcement() requires triggering_event_id to close the audit loop
"""
from __future__ import annotations

import os
import json
import logging
import uuid
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

def log_detection(
    detection_type: str,
    source_ip: str,
    domain: str,
    score: int,
    model_version: str,
    confidence: float,
    threshold_applied: int,
    details: Optional[dict] = None
) -> str:
    """
    Logs an AI detection event and returns a unique Event ID.
    This ID must be passed to the enforcement layer for audit binding.
    
    Args:
        detection_type: Type of detection (e.g., "THREAT_BEHAVIOR", "GAMBLING_BEHAVIOR")
        source_ip: Client IP that triggered detection
        domain: Target domain involved
        score: Threat score (0-100)
        model_version: Version of the AI model used
        confidence: Confidence score as float (0.0-1.0)
        threshold_applied: Block threshold that was exceeded
        details: Optional additional context
    
    Returns:
        event_id: Unique UUID string that must be passed to log_enforcement()
    """
    # Type validation for float fields
    if not isinstance(confidence, (int, float)):
        raise TypeError(f"confidence must be a float, got {type(confidence).__name__}")
    
    event_id = str(uuid.uuid4())
    logger = _get_audit_logger()
    
    entry = {
        "event_id": event_id,
        "event_type": "DETECTION",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "detection_type": detection_type,
        "source_ip": source_ip,
        "target_domain": domain,
        "ai_score": score,
        "confidence": float(confidence),
        "model_version": model_version,
        "threshold_applied": threshold_applied,
        "details": details or {}
    }
    
    logger.info(json.dumps(entry, ensure_ascii=False))
    return event_id


def log_enforcement(
    action: str, 
    target: str, 
    triggering_event_id: str,
    details: Optional[dict] = None
) -> None:
    """
    Log enforcement action with mandatory linkage to triggering detection.
    
    Args:
        action: Enforcement action (e.g., "BLOCK")
        target: Target of enforcement (IP address)
        triggering_event_id: UUID from log_detection() - REQUIRED for audit binding
        details: Optional additional context
    """
    logger = _get_audit_logger()
    
    entry = {
        "event_type": "ENFORCEMENT",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "target": target,
        "triggering_event_id": triggering_event_id,
        "details": details or {}
    }
    
    logger.info(json.dumps(entry, ensure_ascii=False))


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
