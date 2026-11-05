"""60-second routed load and an isolated 64-KiB full log filesystem; lab only."""
import json
import http.client
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time

edition, package, source = sys.argv[1:4]
disk_only = sys.argv[4:] == ["--disk-only"]
assert edition in {"education", "financial"}
assert socket.gethostname() == "minifw-monday-" + edition and os.geteuid() == 0
assert subprocess.check_output(["systemd-detect-virt"], text=True).strip() in {"kvm", "qemu"}
sys.path.insert(0, str(Path(source) / "testing"))
import lab_gateway_acceptance as gateway
import lab_extended_acceptance as extended


def exercise(root, run, start, record, nft, ns, member, children):
    start(source="file", packet=True)
    run("systemctl", "start", "minifw-ai-web")
    samples = []

    def sample():
        return run("systemctl", "show", "minifw-ai", "minifw-ai-web", "-p", "MemoryCurrent", "-p", "CPUUsageNSec", "-p", "NRestarts", "-p", "ActiveState").stdout

    code = '''import http.client,json,time
begin=time.monotonic(); success=failed=0
while time.monotonic()-begin<60:
 tick=time.monotonic()
 try:
  c=http.client.HTTPConnection("198.18.0.2",8080,timeout=2); c.request("GET","/"); r=c.getresponse(); r.read(); success+=r.status==200; c.close()
 except OSError: failed+=1
 time.sleep(max(0,.2-(time.monotonic()-tick)))
print(json.dumps({"duration_seconds":time.monotonic()-begin,"offered_rate_rps":5,"success":success,"failures":failed}))
'''
    if disk_only:
        code = code.replace("begin<60", "begin<0")
    output = (root / "bounded-load.json").open("w")
    process = subprocess.Popen(["ip", "netns", "exec", "mf-client", "/usr/bin/python3", "-c", code], stdout=output)
    children.append(process)
    while process.poll() is None:
        samples.append({"monotonic": time.monotonic(), "services": sample()})
        time.sleep(5)
    output.close()
    assert process.returncode == 0
    actual = json.loads((root / "bounded-load.json").read_text())
    (root / "resource-samples.json").write_text(json.dumps(samples, indent=2))
    if not disk_only:
        record("bounded_load", **actual, legitimate_not_isolated=not member(), qualification="60 seconds only, not prolonged load")
        record("bounded_load_acceptance", result="pass" if actual["failures"] == 0 and not member() else "failed legitimate traffic control")
    # Fill a dedicated tmpfs, never the guest disk or an operational log volume.
    fault = root / "full-log-fs"
    fault.mkdir()
    override = Path("/etc/systemd/system/minifw-ai.service.d/95-tuesday-log-fault.conf")
    assert not override.exists()
    run("mount", "-t", "tmpfs", "-o", "size=64k,mode=0755", "minifw-test-full", str(fault))
    try:
        with (fault / "fill").open("wb", buffering=0) as stream:
            try:
                while True:
                    stream.write(b"x" * 4096)
                    stream.flush()
            except OSError as error:
                assert error.errno == 28
        (fault / "events.jsonl").touch()
        override.write_text(f"[Service]\nEnvironment=MINIFW_LOG={fault}/events.jsonl\nEnvironment=PYTHONPATH=/var/tmp/minifw-f2-instrument:/opt/minifw_ai/app:/opt/minifw_ai\n")
        run("systemctl", "daemon-reload")
        run("systemctl", "restart", "minifw-ai")
        time.sleep(3)
        ns("dns", "10.10.0.1", "4chan.org" if edition == "education" else "secure-bankofamerica-login.com")
        time.sleep(3)
        run("systemctl", "kill", "--signal=USR1", "--kill-who=main", "minifw-ai")
        time.sleep(1)
        blocked = member()
        record("fault_diagnostics", dns_log=(root / "dns.log").read_text(),
               dns_process_log=(root / "dnsmasq-process.log").read_text(),
               engine=run("systemctl", "show", "minifw-ai", "-p", "MainPID", "-p", "NRestarts", "-p", "ExecMainStatus").stdout)
        nft("disk-full-block-state")
        status = sample()
        probe = run("ip", "netns", "exec", "mf-client", "/usr/bin/python3",
                    str(Path(source) / "testing/lab_gateway_acceptance.py"), "client", "http", "198.18.0.2", "8080", "/", check=False)
        dashboard = {}
        for path in ("/auth/login", "/health/"):
            connection = http.client.HTTPSConnection("127.0.0.1", 8443, context=ssl._create_unverified_context(), timeout=5)
            connection.request("GET", path)
            response = connection.getresponse()
            dashboard[path] = response.status
            response.read()
            connection.close()
        record("isolated_disk_full", filesystem_bytes=65536, kernel_block_present=blocked,
               free_bytes=os.statvfs(fault).f_bavail * os.statvfs(fault).f_frsize,
               event_log_bytes=(fault / "events.jsonl").stat().st_size,
               routed_http_exit=probe.returncode, services=status, dashboard_http=dashboard,
               acceptance="pass" if blocked and probe.returncode != 0 else "failed enforcement under full log filesystem")
    finally:
        run("systemctl", "stop", "minifw-ai")
        override.unlink(missing_ok=True)
        run("systemctl", "daemon-reload")
        run("umount", str(fault))
        start(source="file", packet=True)
        ns("http", "198.18.0.2", "8080", "/")
        record("disk_full_recovery", legitimate_http="200", engine="restarted with normal log path")
        run("systemctl", "stop", "minifw-ai-web", check=False)


extended.exercise = exercise
gateway.acceptance(edition, package, extended=True)
