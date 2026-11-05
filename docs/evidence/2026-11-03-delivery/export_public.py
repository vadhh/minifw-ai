"""Finalize disposable lab state and export public results, never keys/DB/backups."""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tarfile

edition, package = sys.argv[1:]
assert edition in {"education", "financial"} and os.geteuid() == 0
assert socket.gethostname() == "minifw-monday-" + edition
assert subprocess.check_output(["systemd-detect-virt"], text=True).strip() in {"kvm", "qemu"}
subprocess.run(["systemctl", "stop", "minifw-ai", "minifw-ai-web", "dnsmasq"], check=True)
private = Path("/var/tmp/minifw-tuesday-private-backup")
payload = private / "final-payload"
assert not payload.exists()
subprocess.run(["dpkg-deb", "-x", package, str(payload)], check=True)
# Remove only the fixture policy/feed edits; original pre-test state is backed up privately.
for source in (payload / "opt/minifw_ai/config").rglob("*"):
    if source.is_file():
        target = Path("/") / source.relative_to(payload)
        target.write_bytes(source.read_bytes())
        if "/modes/" in str(target) or "/feeds/" in str(target):
            subprocess.run(["chown", "root:minifw-web", str(target)], check=True)
            target.chmod(0o664)
        else:
            subprocess.run(["chown", "root:root", str(target)], check=True)
            target.chmod(0o644)
verify = subprocess.run(["dpkg", "--verify", "minifw-ai"], capture_output=True, text=True)
assert verify.returncode == 0 and not verify.stdout, verify.stdout
assert not any(Path("/etc/systemd/system").glob("minifw-ai*.service.d/*tuesday*"))
assert not any(Path("/etc/systemd/system").glob("minifw-ai*.service.d/90-monday*"))
assert not any(item["name"] in {"mf-client", "mf-server"} for item in json.loads(subprocess.check_output(["ip", "-j", "netns", "list"], text=True).strip() or "[]"))
logs = sorted(Path("/var/tmp").glob("minifw-c16-*.log"))
runs = set()
for log in logs:
    for line in log.read_text().splitlines():
        if line.startswith("EVIDENCE_DIRECTORY "):
            path = Path(line.split(" ", 1)[1])
            assert path.parent == Path("/var/tmp") and path.name.startswith("minifw-monday-" + edition + "-")
            runs.add(path)
summary = {"edition": edition, "package_sha256": hashlib.sha256(Path(package).read_bytes()).hexdigest(),
           "dpkg_verify": "clean after restoring package fixture config", "services_at_handoff": "stopped",
           "namespaces": "cleaned", "private_state_backup": str(private), "runs": sorted(map(str, runs))}
final = Path("/var/tmp/minifw-c16-final-state.json")
final.write_text(json.dumps(summary, indent=2) + "\n")
output = Path(f"/var/tmp/minifw-c16-public-{edition}.tar.gz")
with tarfile.open(output, "w:gz") as archive:
    for file in [*logs, *Path("/var/tmp").glob("minifw-c16-tests*.xml"), final]:
        archive.add(file, arcname=file.name)
    for root in sorted(runs):
        for file in sorted(root.iterdir()):
            if file.is_file() and not file.is_symlink() and file.suffix in {".log", ".json", ".jsonl", ".nft", ".sha256"}:
                archive.add(file, arcname="runs/" + root.name + "/" + file.name)
output.chmod(0o644)
print(json.dumps(summary, indent=2))
print("PUBLIC_EVIDENCE_SHA256", hashlib.sha256(output.read_bytes()).hexdigest())
