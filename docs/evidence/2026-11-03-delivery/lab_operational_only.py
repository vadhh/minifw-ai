"""Reuse existing operational checks without the unrelated VPN/provider suite."""
import os
from pathlib import Path
import socket
import subprocess
import sys

edition, package, source = sys.argv[1:]
assert edition in {"education", "financial"}
assert socket.gethostname() == "minifw-monday-" + edition and os.geteuid() == 0
assert subprocess.check_output(["systemd-detect-virt"], text=True).strip() in {"kvm", "qemu"}
sys.path.insert(0, str(Path(source) / "testing"))
import lab_gateway_acceptance as gateway
import lab_extended_acceptance as extended


def exercise(root, run, start, record, nft, ns, member, children):
    extended.operational_checks(root, run, start, record, nft, ns, member)


extended.exercise = exercise
gateway.acceptance(edition, package, extended=True)
