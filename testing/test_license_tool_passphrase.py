"""scripts/license_tool.py signs with a passphrase-encrypted vendor key only when given the passphrase."""

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

TOOL = Path(__file__).resolve().parents[1] / "scripts" / "license_tool.py"


def _issue(key_path, out, passphrase):
    env = {k: v for k, v in os.environ.items() if k != "MINIFW_SIGNING_PASSPHRASE"}
    if passphrase is not None:
        env["MINIFW_SIGNING_PASSPHRASE"] = passphrase
    return subprocess.run(
        [sys.executable, str(TOOL), "issue", "--private-key", str(key_path), "--key-id", "test-key",
         "--customer-id", "c", "--deployment-id", "d", "--product-mode", "minifw_financial",
         "--output", str(out)],
        # No controlling terminal, so a missing passphrase fails instead of waiting at a getpass prompt.
        env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, start_new_session=True, timeout=30,
    )


def test_encrypted_key_signs_with_passphrase_and_refuses_without(tmp_path):
    key = Ed25519PrivateKey.generate()
    key_path = tmp_path / "vendor.pem"
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"correct horse"),
    ))

    ok = _issue(key_path, tmp_path / "ok.json", "correct horse")
    assert ok.returncode == 0, ok.stderr
    lic = json.loads((tmp_path / "ok.json").read_text())
    signed = json.dumps({"key_id": lic["key_id"], "payload": lic["payload"]},
                        sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    key.public_key().verify(base64.b64decode(lic["signature"]), signed)

    assert _issue(key_path, tmp_path / "bad.json", "wrong").returncode != 0
    assert _issue(key_path, tmp_path / "none.json", None).returncode != 0
    assert not (tmp_path / "bad.json").exists() and not (tmp_path / "none.json").exists()


def test_unencrypted_key_still_signs(tmp_path):
    key_path = tmp_path / "vendor.pem"
    key_path.write_bytes(Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ))
    result = _issue(key_path, tmp_path / "lic.json", None)
    assert result.returncode == 0, result.stderr
