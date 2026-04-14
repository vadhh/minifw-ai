"""Structured audit logger for MiniFW-AI.

Writes append-only JSONL records to the configured audit log path.
Used by both the firewall daemon and the web admin panel.

Audit categories:
  - SYSTEM    : daemon start/stop, config load, firewall init
  - STATE     : protection state transitions
  - ENFORCE   : IP block/unblock actions
  - AUTH      : login, logout, 2FA, password change
  - POLICY    : deny/allow list changes, threshold changes
  - USER_MGMT : user create/update/delete
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


_DEFAULT_AUDIT_PATH = "/opt/minifw_ai/logs/audit.jsonl"

# Module-level writer instance (initialised on first use)
_writer: Optional["AuditWriter"] = None


@dataclass
class AuditRecord:
    ts: str
    category: str          # SYSTEM | STATE | ENFORCE | AUTH | POLICY | USER_MGMT
    action: str            # e.g. "daemon_start", "ip_block", "login_success"
    detail: str            # human-readable description
    actor: str = "system"  # username or "system"/"daemon"
    target: str = ""       # affected resource (IP, domain, username, etc.)
    metadata: dict = field(default_factory=dict)


class AuditWriter:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, record: AuditRecord) -> None:
        try:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(record), ensure_ascii=False) + "\n")
        except OSError as e:
            logging.error(f"[AUDIT] Failed to write audit record: {e}")


def _get_writer() -> AuditWriter:
    global _writer
    if _writer is None:
        path = os.environ.get("MINIFW_AUDIT_LOG", _DEFAULT_AUDIT_PATH)
        _writer = AuditWriter(path)
    return _writer


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def audit(
    category: str,
    action: str,
    detail: str,
    actor: str = "system",
    target: str = "",
    **metadata,
) -> None:
    """Write a single audit record."""
    record = AuditRecord(
        ts=_now(),
        category=category,
        action=action,
        detail=detail,
        actor=actor,
        target=target,
        metadata=metadata,
    )
    _get_writer().write(record)


# ── Convenience helpers ──────────────────────────────────────────────

def audit_daemon_start(sector: str, state: str) -> None:
    audit("SYSTEM", "daemon_start", f"Daemon started (sector={sector}, state={state})",
          target=sector, sector=sector, initial_state=state)


def audit_daemon_stop(reason: str = "normal") -> None:
    audit("SYSTEM", "daemon_stop", f"Daemon stopped ({reason})", reason=reason)


def audit_config_loaded(policy_path: str, feeds_dir: str) -> None:
    audit("SYSTEM", "config_loaded", f"Policy loaded from {policy_path}",
          target=policy_path, feeds_dir=feeds_dir)


def audit_firewall_init(set_name: str, table: str) -> None:
    audit("SYSTEM", "firewall_init", f"nftables set '{set_name}' initialised in {table}",
          target=set_name, table=table)


def audit_firewall_init_failed(error: str) -> None:
    audit("SYSTEM", "firewall_init_failed", f"CRITICAL: Firewall init failed: {error}",
          error=error)


def audit_state_transition(old_state: str, new_state: str, reason: str) -> None:
    audit("STATE", "state_transition",
          f"State changed: {old_state} -> {new_state} ({reason})",
          target=new_state, old_state=old_state, new_state=new_state, reason=reason)


def audit_ip_block(ip: str, score: int, reasons: list, domain: str, sector: str) -> None:
    audit("ENFORCE", "ip_block",
          f"Blocked {ip} (score={score}, domain={domain})",
          target=ip, score=score, reasons=reasons, domain=domain, sector=sector)


def audit_login_success(username: str, ip: str = "") -> None:
    audit("AUTH", "login_success", f"User '{username}' logged in",
          actor=username, target=username, source_ip=ip)


def audit_login_failed(username: str, ip: str = "") -> None:
    audit("AUTH", "login_failed", f"Failed login attempt for '{username}'",
          actor=username, target=username, source_ip=ip)


def audit_2fa_success(username: str) -> None:
    audit("AUTH", "2fa_success", f"2FA verified for '{username}'",
          actor=username, target=username)


def audit_2fa_failed(username: str) -> None:
    audit("AUTH", "2fa_failed", f"2FA failed for '{username}'",
          actor=username, target=username)


def audit_logout(username: str) -> None:
    audit("AUTH", "logout", f"User '{username}' logged out",
          actor=username, target=username)


def audit_password_change(username: str, changed_by: str = "") -> None:
    actor = changed_by or username
    audit("AUTH", "password_change", f"Password changed for '{username}'",
          actor=actor, target=username)


def audit_policy_change(action_name: str, resource_type: str, value: str, username: str) -> None:
    audit("POLICY", action_name, f"{action_name}: {resource_type} = {value}",
          actor=username, target=value, resource_type=resource_type)


def audit_user_mgmt(action_name: str, target_user: str, actor: str, **kwargs) -> None:
    audit("USER_MGMT", action_name, f"{action_name}: user '{target_user}'",
          actor=actor, target=target_user, **kwargs)
