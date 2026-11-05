#!/usr/bin/env python3
"""Vendor-side helper for generating an Ed25519 keypair and issuing licenses."""

import argparse
import base64
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def generate(args) -> None:
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    private_path = Path(args.private_key)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(private_bytes)
    keyring_path = Path(args.keyring)
    keyring = json.loads(keyring_path.read_text(encoding="utf-8")) if keyring_path.exists() else {"keys": {}}
    keys = keyring.setdefault("keys", {})
    if args.key_id in keys:
        raise SystemExit(f"Key ID already exists in keyring: {args.key_id}")
    keys[args.key_id] = base64.b64encode(public_bytes).decode("ascii")
    keyring_path.write_text(json.dumps(keyring, indent=2) + "\n", encoding="utf-8")
    print(f"Private key: {private_path} (keep offline; never package it)")
    print(f"Public keyring: {args.keyring} (package this with the product)")


def issue(args) -> None:
    private_key = serialization.load_pem_private_key(
        Path(args.private_key).read_bytes(), password=None
    )
    issued_at = utc_now()
    starts_at = args.starts_at or issued_at
    start_time = datetime.fromisoformat(starts_at.replace("Z", "+00:00"))
    if start_time.tzinfo is None:
        raise SystemExit("--starts-at must include a timezone")
    expires_at = args.expires_at
    if expires_at:
        end_time = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if end_time.tzinfo is None or end_time <= start_time:
            raise SystemExit("--expires-at must include a timezone and follow --starts-at")
    else:
        try:
            end_time = start_time.replace(year=start_time.year + 1)
        except ValueError:
            end_time = start_time.replace(year=start_time.year + 1, day=28)
        expires_at = end_time.isoformat().replace("+00:00", "Z")
    payload = {
        "schema_version": 1,
        "license_id": str(uuid.uuid4()),
        "customer_id": args.customer_id,
        "deployment_id": args.deployment_id,
        "product_mode": args.product_mode,
        "issued_at": issued_at,
        "starts_at": starts_at,
        "expires_at": expires_at,
    }
    signed = json.dumps(
        {"key_id": args.key_id, "payload": payload},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    envelope = {
        "key_id": args.key_id,
        "payload": payload,
        "signature": base64.b64encode(private_key.sign(signed)).decode("ascii"),
    }
    Path(args.output).write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
    print(f"License written: {args.output}")


parser = argparse.ArgumentParser(description=__doc__)
subparsers = parser.add_subparsers(required=True)
keygen = subparsers.add_parser("keygen", help="Generate a vendor signing key and public keyring")
keygen.add_argument("--key-id", required=True)
keygen.add_argument("--private-key", required=True)
keygen.add_argument("--keyring", required=True)
keygen.set_defaults(func=generate)
license_parser = subparsers.add_parser("issue", help="Issue a signed per-deployment license")
license_parser.add_argument("--private-key", required=True)
license_parser.add_argument("--key-id", required=True)
license_parser.add_argument("--customer-id", required=True)
license_parser.add_argument("--deployment-id", required=True)
license_parser.add_argument("--product-mode", required=True, choices=(
    "minifw_hospital", "minifw_school", "minifw_financial",
    "minifw_establishment", "minifw_legal", "minifw_government",
))
license_parser.add_argument("--expires-at", help="Timezone-aware ISO 8601 timestamp (default: one calendar year after start)")
license_parser.add_argument("--starts-at", help="Timezone-aware ISO 8601 timestamp; defaults to now")
license_parser.add_argument("--output", required=True)
license_parser.set_defaults(func=issue)
args = parser.parse_args()
args.func(args)
