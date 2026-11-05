"""Real authenticated dashboard save -> packaged policy -> routed nftables result."""
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse

edition, package, source = sys.argv[1:]
assert edition in {"education", "financial"}
assert socket.gethostname() == "minifw-monday-" + edition and os.geteuid() == 0
assert subprocess.check_output(["systemd-detect-virt"], text=True).strip() in {"kvm", "qemu"}
sys.path.insert(0, str(Path(source) / "testing"))
import lab_gateway_acceptance as gateway
import lab_extended_acceptance as extended


def exercise(root, run, start, record, nft, ns, member, children):
    start(source="file", packet=True)
    run("systemctl", "start", "minifw-ai-web")
    mode = "minifw_school" if edition == "education" else "minifw_financial"
    policy = Path(f"/opt/minifw_ai/config/modes/{mode}/policy.json")
    original = policy.read_bytes()
    override = Path("/etc/systemd/system/minifw-ai.service.d/95-tuesday-policy.conf")
    assert not override.exists()
    domain = "tuesday-policy.lab.test"
    cookie = ""
    added = False

    def call(method, path, data=None, form=False):
        connection = http.client.HTTPSConnection("127.0.0.1", 8443, context=ssl._create_unverified_context(), timeout=10)
        headers = {"Cookie": cookie} if cookie else {}
        if data is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
            data = urllib.parse.urlencode(data) if form else json.dumps(data)
        connection.request(method, path, body=data, headers=headers)
        response = connection.getresponse()
        result = response.status, response.getheader("Set-Cookie"), response.read()
        connection.close()
        return result

    try:
        secret = dict(line.split("=", 1) for line in Path("/etc/minifw/minifw.env").read_text().splitlines() if "=" in line)
        for _ in range(30):
            try:
                status, token, _ = call("POST", "/auth/login", {"username": "admin", "password": secret["MINIFW_ADMIN_PASSWORD"]}, True)
                break
            except OSError:
                time.sleep(.2)
        assert status == 303 and "access_token=" in token
        cookie = token.split(";", 1)[0]
        fixture_policy = json.loads(original)
        fixture_policy["collectors"].update(dnsmasq_log_path=str(root / "dns.log"), zeek_ssl_log_path=str(root / "ssl.log"))
        policy.write_text(json.dumps(fixture_policy, indent=2))
        enforcement = json.loads(original)["enforcement"]
        timeout = 13 if enforcement["ip_timeout_seconds"] == 11 else 11
        values = {name: enforcement[name] for name in ("ipset_name_v4", "nft_table", "nft_chain")}
        values["ip_timeout_seconds"] = timeout
        assert call("POST", "/admin/policy/enforcement", values)[0] == 200
        response = call("POST", "/admin/deny-domain", {"domain": domain})
        assert response[0] == 200, (response[0], response[2])
        added = True
        assert json.loads(policy.read_text())["enforcement"]["ip_timeout_seconds"] == timeout
        override.write_text(f"[Service]\nEnvironment=MINIFW_POLICY={policy}\nEnvironment=MINIFW_DNS_SOURCE=file\n")
        run("systemctl", "daemon-reload")
        run("systemctl", "restart", "minifw-ai")
        time.sleep(2)
        ns("http", "198.18.0.2", "8080", "/")
        ns("dns", "10.10.0.1", domain)
        until = time.monotonic() + 10
        while not member() and time.monotonic() < until:
            time.sleep(.2)
        assert member(), "Dashboard-added deny domain did not reach enforcement"
        output = run("nft", "get", "element", "inet", "minifw", "minifw_block_v4", "{", "10.10.0.20", "}").stdout
        assert f"timeout {timeout}s" in output, output
        nft("dashboard-policy-timeout")
        ns("http", "198.18.0.2", "8080", "/", allowed=False)
        record("dashboard_to_engine_enforcement", authenticated_save=True, packaged_policy=str(policy),
               restart_required=True, previous_timeout_seconds=enforcement["ip_timeout_seconds"], timeout_seconds=timeout, added_domain=domain,
               fixture_setup="collector paths supplied directly by lab root; enforcement timeout and deny domain saved through dashboard",
               actual_kernel=output, routed_before="HTTP 200", routed_after="blocked")
    finally:
        try:
            if added:
                assert call("DELETE", "/admin/deny-domain", {"domain": domain})[0] == 200
        finally:
            policy.write_bytes(original)
            override.unlink(missing_ok=True)
            run("systemctl", "stop", "minifw-ai-web", check=False)
            run("systemctl", "daemon-reload")


extended.exercise = exercise
gateway.acceptance(edition, package, extended=True)
