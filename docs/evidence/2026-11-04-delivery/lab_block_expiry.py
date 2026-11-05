"""Isolate C16's duplicate/expiry failure from storage, using an unhooked nft table."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import time

assert socket.gethostname() in {"minifw-monday-education", "minifw-monday-financial"} and os.geteuid() == 0
assert subprocess.check_output(["systemd-detect-virt"], text=True).strip() in {"kvm", "qemu"}

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

old = load("old_enforce", "/home/lab/tuesday-c16/app/minifw_ai/enforce.py")
new = load("new_enforce", "/opt/minifw_ai/app/minifw_ai/enforce.py")
table, name, ip = "minifw_wednesday_probe", "blocked", "192.0.2.1"
def nft(*args, check=True):
    return subprocess.run(["nft", *args], capture_output=True, text=True, check=check)
assert nft("list", "table", "inet", table, check=False).returncode != 0
try:
    nft("add", "table", "inet", table)
    nft("add", "set", "inet", table, name, "{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "}")
    def present():
        return nft("get", "element", "inet", table, name, "{", ip, "}", check=False).returncode == 0
    results = []
    for label, module, options in [("C16", old, {}), ("C18", new, {"refresh": True})]:
        nft("flush", "set", "inet", table, name)
        assert module.ipset_add(name, ip, 3, table_name=table)
        time.sleep(2)
        assert present(), "Old block expired before the controlled deny observation"
        decision_result = module.ipset_add(name, ip, 15, table_name=table, **options)
        before_expiry = nft("get", "element", "inet", table, name, "{", ip, "}").stdout
        time.sleep(1.3)
        protected = present()
        assert protected == (label == "C18")
        results.append({"candidate": label, "renewal_result": decision_result,
                        "protected_after_old_expiry": protected, "kernel_before_old_expiry": before_expiry})
    print(json.dumps({"results": results, "storage_failure_injected": False,
                      "old_source_sha256": hashlib.sha256(Path(old.__file__).read_bytes()).hexdigest(),
                      "new_source_sha256": hashlib.sha256(Path(new.__file__).read_bytes()).hexdigest()}, indent=2))
finally:
    nft("delete", "table", "inet", table)
