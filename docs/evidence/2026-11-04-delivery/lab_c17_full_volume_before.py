"""C18: 300 HTTP requests, then a full shared event/flow volume with engine continuity and deny renewal."""
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
assert len(sys.argv) == 4, "Expected edition, package and source"
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

    code = '''import concurrent.futures,http.client,json,socket,time
begin=time.monotonic()
def request(index):
 started=time.monotonic()
 c=http.client.HTTPConnection("198.18.0.2",8080,timeout=2)
 try:
  c.request("GET","/"); r=c.getresponse(); r.read()
  result="success" if r.status==200 else "http_"+str(r.status)
 except (OSError,http.client.HTTPException) as error:
  result=type(error).__name__
 finally: c.close()
 return {"index":index,"scheduled_seconds":index/5,"started_seconds":started-begin,"finished_seconds":time.monotonic()-begin,"result":result}
with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
 futures=[]
 for index in range(10):
  time.sleep(max(0,begin+index/5-time.monotonic()))
  futures.append(pool.submit(request,index))
 rows=[future.result() for future in futures]
success=sum(row["result"]=="success" for row in rows)
print(json.dumps({"duration_seconds":time.monotonic()-begin,"offered_rate_rps":5,"scheduled":10,"attempted":len(rows),"completed":len(rows),"success":success,"failures":len(rows)-success,"requests":rows}))
'''
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
    if True:
        record("bounded_load", **actual, legitimate_not_isolated=not member(), qualification="60 seconds only, not prolonged load")
        record("bounded_load_acceptance", result="pass" if actual["failures"] == 0 and not member() else "failed legitimate traffic control")
    assert actual["success"] == 10 and actual["failures"] == 0 and not member(), "Legitimate traffic failed"
    run("nft", "flush", "set", "inet", "minifw", "minifw_block_v4")
    assert not member(), "Disk-full probe must start without any earlier load-test block"
    ns("http", "198.18.0.2", "8080", "/")
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
        (fault / "flows.jsonl").touch()
        override.write_text(f"[Service]\nEnvironment=MINIFW_LOG={fault}/events.jsonl\nEnvironment=MINIFW_FLOW_RECORDS={fault}/flows.jsonl\n")
        run("systemctl", "daemon-reload")
        run("systemctl", "restart", "minifw-ai")
        time.sleep(3)
        pid_before = run("systemctl", "show", "minifw-ai", "-p", "MainPID", "--value").stdout.strip()
        for _ in range(30):
            ns("http", "198.18.0.2", "8080", "/")
        time.sleep(6)
        pid_after = run("systemctl", "show", "minifw-ai", "-p", "MainPID", "--value").stdout.strip()
        restarts = run("systemctl", "show", "minifw-ai", "-p", "NRestarts", "--value").stdout.strip()
        record("full_log_and_flow_volume_progress", pid_before=pid_before, pid_after=pid_after,
               automatic_restarts=int(restarts), legitimate_HTTP=30)
        assert pid_before == pid_after and restarts == "0", "Full log/flow volume interrupted the engine"
        run("nft", "add", "element", "inet", "minifw", "minifw_block_v4", "{", "10.10.0.20", "timeout", "2s", "}")
        nft("older-block-before-deny")
        ns("dns", "10.10.0.1", "4chan.org" if edition == "education" else "secure-bankofamerica-login.com")
        time.sleep(4)
        blocked = member()
        record("older_block_renewed_by_explicit_deny", old_timeout_seconds=2, checked_after_seconds=4, kernel_block_present=blocked)
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
               flow_log_bytes=(fault / "flows.jsonl").stat().st_size,
               routed_http_exit=probe.returncode, services=status, dashboard_http=dashboard,
               acceptance="pass" if blocked and probe.returncode != 0 else "failed enforcement under full log filesystem")
        assert blocked and probe.returncode != 0, "Deny enforcement failed under full log filesystem"
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
