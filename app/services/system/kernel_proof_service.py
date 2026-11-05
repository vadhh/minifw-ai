import json
import os
from pathlib import Path


def compute_kernel_proof() -> dict:
    """Kernel-rule status without nftables privileges.

    Stage 1 reads the engine's runtime-health snapshot, which the root engine refreshes
    from its own `nft -j list table` probe (same boot, same process, at most 10 s old).
    Stage 2 falls back to the engine's firewall_init audit record.
    """
    result = {"active": False, "label": "Not active", "detail": "", "table": "minifw"}

    from minifw_ai.runtime_health import assess
    health_file = Path(os.environ.get("MINIFW_HEALTH_FILE", "/opt/minifw_ai/logs/runtime-health.json"))
    try:
        health = assess(json.loads(health_file.read_text()))
    except (OSError, ValueError):
        health = {}
    if health.get("kernel_rule_present") is True:
        result.update(active=True, label="Blocked at kernel level (nftables)",
                      detail="Engine-verified inet/minifw drop rule (runtime health, <=10 s old)")
        return result
    if "kernel_rule_present" in health:
        result["detail"] = "Engine running but the inet/minifw drop rule is missing"
        return result

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
                                      label="nftables initialised (not currently verified)",
                                      detail="Engine audit log records firewall_init; live health unavailable")
                        return result
                except json.JSONDecodeError:
                    continue
            result["detail"] = "Engine starting — nftables init pending"
        else:
            result["detail"] = "Engine not started (no audit log found)"
    except Exception as exc:
        result["detail"] = f"Audit log check failed: {exc}"

    return result
