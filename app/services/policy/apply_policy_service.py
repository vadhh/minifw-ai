"""Request the single privileged action provided by the packaged systemd path unit."""
import json
import os
from pathlib import Path
import time

from minifw_ai.runtime_health import assess

APPLY_REQUEST = Path("/var/lib/minifw-ai/apply-policy")


def apply_saved_policy():
    health_file = Path(os.environ.get("MINIFW_HEALTH_FILE", "/opt/minifw_ai/logs/runtime-health.json"))

    def snapshot():
        try:
            return json.loads(health_file.read_text())
        except (OSError, ValueError):
            return {}

    before = snapshot().get("pid")
    # Exclusive creation prevents concurrent requests from silently replacing each other.
    with APPLY_REQUEST.open("x"):
        pass
    until = time.monotonic() + 15
    while time.monotonic() < until:
        current = snapshot()
        proof = assess(current)
        if current.get("pid") != before and proof.get("kernel_rule_present"):
            return {"message": "Engine restarted; saved policy and feeds loaded. Check protection status on the dashboard.",
                    "engine_pid": current["pid"]}
        time.sleep(.2)
    raise TimeoutError("Engine restart could not be verified. Check protection status and contact your administrator before applying again.")
