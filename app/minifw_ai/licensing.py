"""Offline signed-license verification for the admin interface."""

from __future__ import annotations

import base64
import binascii
import json
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from minifw_ai.mode_context import get_mode_ui

GRACE_PERIOD = timedelta(days=14)
MAX_LICENSE_BYTES = 64 * 1024


def _license_path() -> Path:
    return Path(os.environ.get("MINIFW_LICENSE_FILE", "/etc/minifw/license.json"))


def _keyring_path() -> Path:
    return Path(os.environ.get(
        "MINIFW_LICENSE_PUBLIC_KEYS_FILE",
        "/opt/minifw_ai/config/license_public_keys.json",
    ))


def get_deployment_id() -> str:
    path = Path(os.environ.get(
        "MINIFW_INSTALLATION_ID_FILE", "/var/lib/minifw-ai/installation-id"
    ))
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return path.read_text(encoding="ascii").strip()
    deployment_id = str(uuid.uuid4())
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(deployment_id + "\n")
    return deployment_id


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("License timestamps must be ISO 8601 strings")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("License timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def _invalid(reason: str, **details: object) -> dict:
    return {"status": "invalid", "reason": reason, **details}


def verify_license(raw: bytes) -> dict:
    """Verify signed license contents and return UI-safe status metadata."""
    try:
        envelope = json.loads(raw)
        if not isinstance(envelope, dict):
            return _invalid("License file must contain a JSON object")
        key_id = envelope["key_id"]
        payload = envelope["payload"]
        if not isinstance(key_id, str) or not isinstance(payload, dict):
            return _invalid("License envelope is malformed")
        if payload.get("schema_version") != 1:
            return _invalid("Unsupported license schema")
        required = (
            "license_id", "customer_id", "deployment_id", "product_mode",
            "issued_at", "starts_at", "expires_at",
        )
        if any(not isinstance(payload.get(k), str) or not payload[k] for k in required):
            return _invalid("License is missing required fields")
        issued = _parse_time(payload["issued_at"])
        starts = _parse_time(payload["starts_at"])
        expires = _parse_time(payload["expires_at"])
        if starts >= expires or issued > expires:
            return _invalid("License date range is invalid")

        keyring = json.loads(_keyring_path().read_text(encoding="utf-8"))
        keys = keyring.get("keys", {}) if isinstance(keyring, dict) else {}
        encoded_key = keys.get(key_id) if isinstance(keys, dict) else None
        if not encoded_key:
            return {"status": "not_configured", "reason": "No trusted signing key is configured"}
        public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(encoded_key, validate=True))
        signature = base64.b64decode(envelope["signature"], validate=True)
        signed = json.dumps(
            {"key_id": key_id, "payload": payload},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
        public_key.verify(signature, signed)

        mode = get_mode_ui().product_mode
        if not mode:
            return _invalid("Product mode is not configured")
        if payload["deployment_id"] != get_deployment_id():
            return _invalid("License is issued for a different deployment")
        if payload["product_mode"] != mode:
            return _invalid("License is issued for a different product mode")

        now = datetime.now(timezone.utc)
        if now < starts:
            state = "not_yet_valid"
        elif now <= expires:
            state = "valid"
        elif now <= expires + GRACE_PERIOD:
            state = "grace"
        else:
            state = "expired"
        return {
            "status": state,
            "license_id": payload["license_id"],
            "customer_id": payload["customer_id"],
            "deployment_id": payload["deployment_id"],
            "product_mode": payload["product_mode"],
            "starts_at": payload["starts_at"],
            "expires_at": payload["expires_at"],
        }
    except (OSError, KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError,
            binascii.Error, InvalidSignature) as exc:
        return _invalid(str(exc) or "License verification failed")


def get_license_status() -> dict:
    path = _license_path()
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return {"status": "unlicensed", "reason": "No license file is installed"}
    except OSError as exc:
        return _invalid(f"Could not read license file: {exc}")
    if len(raw) > MAX_LICENSE_BYTES:
        return _invalid("License file exceeds the 64 KiB limit")
    return verify_license(raw)


def install_license(raw: bytes) -> dict:
    if not raw or len(raw) > MAX_LICENSE_BYTES:
        raise ValueError("License file must be between 1 byte and 64 KiB")
    status = verify_license(raw)
    if status["status"] not in ("valid", "grace"):
        raise ValueError(status.get("reason", f"License status is {status['status']}"))

    path = _license_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".license-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, path)
    except Exception:
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass
        raise
    return status
