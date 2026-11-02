"""Observed engine progress and independently refreshed kernel-rule proof."""

import json
import logging
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time


def kernel_ready(table, chain, set_name):
    result = subprocess.run(["nft", "-j", "list", "table", "inet", table],
                            capture_output=True, text=True, timeout=2, check=True)
    objects = json.loads(result.stdout)["nftables"]
    has_set = any(item.get("set", {}).get("name") == set_name and
                  item["set"].get("type") == "ipv4_addr" for item in objects)
    has_chain = any(item.get("chain", {}).get("name") == chain and
                    item["chain"].get("hook") == "forward" for item in objects)
    has_drop = False
    for item in objects:
        rule = item.get("rule", {})
        expressions = rule.get("expr", [])
        source_match = any(expr.get("match", {}).get("left") ==
                           {"payload": {"protocol": "ip", "field": "saddr"}} and
                           expr["match"].get("right") == "@" + set_name for expr in expressions)
        if rule.get("chain") == chain and source_match and any("drop" in expr for expr in expressions):
            has_drop = True
    return has_set and has_chain and has_drop


def process_identity(pid):
    # Fields after the final ')' avoid spaces inside a process name.
    return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]


def assess(snapshot, now=None):
    now = time.monotonic() if now is None else now
    try:
        if snapshot["boot_id"] != Path("/proc/sys/kernel/random/boot_id").read_text().strip():
            raise ValueError("different boot")
        if process_identity(snapshot["pid"]) != snapshot["process_start"]:
            raise ValueError("different process")
        heartbeat_age = now - snapshot["heartbeat"]
        kernel_age = now - snapshot["kernel_checked"]
        if not (0 <= heartbeat_age <= 5 and 0 <= kernel_age <= 10):
            raise ValueError("stale progress")
        sources = snapshot["sources"]
        ages = {name: None if stamp is None else now - stamp for name, stamp in sources.items()}
        recent = bool(ages) and all(age is not None and 0 <= age <= 30 for age in ages.values())
        ready = snapshot["kernel_ready"] is True and recent
        return {"status": "ready" if ready else "not_ready", "heartbeat_age_seconds": heartbeat_age,
                "kernel_rule_present": snapshot["kernel_ready"] is True, "source_age_seconds": ages,
                "coverage": "Progress and IPv4 rule presence only; quiet sources remain unverified; not traffic enforcement or AI quality acceptance"}
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, OSError):
        return {"status": "not_ready", "reason": "missing, stale or invalid engine evidence"}


class RuntimeHealth:
    def __init__(self, path, sources, table, chain, set_name):
        self.path = Path(path)
        if not Path("/proc/sys/kernel/random/boot_id").is_file():
            self.snapshot = None
            logging.warning("Runtime readiness unavailable without Linux procfs")
            return
        self.snapshot = {"pid": os.getpid(), "process_start": process_identity(os.getpid()),
                         "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                         "sources": dict.fromkeys(sources), "heartbeat": time.monotonic(),
                         "kernel_ready": False, "kernel_checked": 0.0}
        self.kernel = (False, 0.0)
        self.last_write = 0.0

        def check():
            while True:
                try:
                    ready = kernel_ready(table, chain, set_name)
                except (OSError, ValueError, subprocess.SubprocessError):
                    ready = False
                self.kernel = (ready, time.monotonic())
                time.sleep(2)

        threading.Thread(target=check, name="minifw-kernel-health", daemon=True).start()

    def observe(self, source):
        if self.snapshot is None:
            return
        now = time.monotonic()
        if source in self.snapshot["sources"]:
            self.snapshot["sources"][source] = now
        if now - self.last_write < 1:
            return
        self.snapshot.update(heartbeat=now, kernel_ready=self.kernel[0], kernel_checked=self.kernel[1])
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", dir=self.path.parent, prefix=".runtime-health-", delete=False) as stream:
                temporary = Path(stream.name)
                # Group-readable so the non-root dashboard (group of the setgid logs dir) can assess it.
                os.fchmod(stream.fileno(), 0o640)
                json.dump(self.snapshot, stream)
            temporary.replace(self.path)
        except OSError:
            logging.exception("Failed to publish runtime health; readiness must remain unavailable")
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        self.last_write = now
