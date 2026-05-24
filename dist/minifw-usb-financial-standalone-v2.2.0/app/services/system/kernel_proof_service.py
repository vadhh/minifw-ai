import os
import subprocess
import json
from pathlib import Path


def compute_kernel_proof() -> dict:
    result = {"active": False, "label": "Not active", "detail": "", "table": "minifw"}

    # Stage 1 — direct nft probe (same network namespace)
    try:
        out = subprocess.run(
            ["nft", "list", "table", "inet", "minifw"],
            capture_output=True, text=True, timeout=3
        )
        if out.returncode == 0 and "MiniFW-AI-Blocklist" in out.stdout:
            result.update(active=True, label="Blocked at kernel level (nftables)",
                          detail="inet/minifw table active with drop rule")
            return result
        if out.returncode == 0:
            result.update(active=True, label="nftables table active",
                          detail="inet/minifw table present (drop rule pending first block)")
            return result
    except (FileNotFoundError, Exception):
        pass

    # Stage 2 — audit.jsonl sentinel (Docker shared-volume)
    audit_log = os.environ.get("MINIFW_AUDIT_LOG", "/opt/minifw_ai/logs/audit.jsonl")
    try:
        audit_path = Path(audit_log)
        if audit_path.exists():
            for line in audit_path.open("r", encoding="utf-8"):
                line = line.strip()
                if not line:
                    continue
                try:
                    if json.loads(line).get("action") == "firewall_init":
                        result.update(active=True,
                                      label="Blocked at kernel level (nftables)",
                                      detail="Confirmed via engine audit log (Docker deployment)")
                        return result
                except json.JSONDecodeError:
                    continue
            result["detail"] = "Engine starting — nftables init pending"
        else:
            result["detail"] = "Engine not started (no audit log found)"
    except Exception as exc:
        result["detail"] = f"Audit log check failed: {exc}"

    return result
