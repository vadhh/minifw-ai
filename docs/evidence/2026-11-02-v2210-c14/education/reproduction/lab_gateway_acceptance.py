"""Run only in the dedicated minifw-monday-* QEMU guests, never on the host.

sudo /opt/minifw_ai/venv/bin/python testing/lab_gateway_acceptance.py education PACKAGE.deb
Records real namespace -> VM forwarding -> namespace traffic and kernel state.
The local HTTP/TLS/DNS fixtures do not establish third-party application acceptance.
"""

import hashlib
import http.client
import http.server
import json
import os
import shlex
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from lab_sandbox import SERVER, SANDBOX_PASSWORD, SandboxState, handler_for, dns_answer

CLIENT = "10.10.0.20"
SERVER6 = "fd42:18::2"


def dns_packet(domain):
    return struct.pack("!HHHHHH", 1234, 0x100, 1, 0, 0, 0) + b"".join(
        bytes([len(label)]) + label.encode() for label in domain.split(".")) + b"\0\0\1\0\1"


def serve(cert, key):
    Handler = handler_for(SandboxState(), Path(__file__).with_name("lesson.webm"))

    class DualHTTP(http.server.ThreadingHTTPServer):
        address_family = socket.AF_INET6
        daemon_threads = True

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    plain = DualHTTP(("::", 8080), Handler)
    secure = DualHTTP(("::", 443), Handler)
    secure.socket = context.wrap_socket(secure.socket, server_side=True)
    legacy_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    legacy_context.minimum_version = legacy_context.maximum_version = ssl.TLSVersion.TLSv1
    legacy_context.set_ciphers("DEFAULT:@SECLEVEL=0")
    legacy_context.load_cert_chain(cert, key)
    legacy = DualHTTP(("::", 8445), Handler)
    legacy.socket = legacy_context.wrap_socket(legacy.socket, server_side=True)
    for server in [plain, secure, legacy]:
        threading.Thread(target=server.serve_forever, daemon=True).start()

    class DoT(socketserver.BaseRequestHandler):
        def handle(self):
            with context.wrap_socket(self.request, server_side=True) as connection:
                size = struct.unpack("!H", connection.recv(2))[0]
                query = connection.recv(size)
                answer = dns_answer(query)
                connection.sendall(struct.pack("!H", len(answer)) + answer)

    dot = socketserver.ThreadingTCPServer((SERVER, 853), DoT)
    threading.Thread(target=dot.serve_forever, daemon=True).start()

    def listen(port):
        def consume(connection):
            with connection:
                while connection.recv(4096):
                    pass

        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((SERVER, port))
            listener.listen(32)
            while True:
                connection, _ = listener.accept()
                threading.Thread(target=consume, args=(connection,), daemon=True).start()

    for port in range(20000, 20015):
        threading.Thread(target=listen, args=(port,), daemon=True).start()
    threading.Event().wait()


def client(args):
    mode, host = args[:2]
    context = ssl._create_unverified_context()  # Only the generated lab server certificate.
    if mode == "dns":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            if len(args) > 3:
                sock.bind((args[3], 0))
            sock.sendto(dns_packet(args[2]), (host, 53))
            data, _ = sock.recvfrom(4096)
            assert data[:2] == b"\x04\xd2"
            print(json.dumps({"ok": True, "resolver": host, "domain": args[2], "answer": socket.inet_ntoa(data[-4:])}))
    elif mode == "dot":
        with socket.create_connection((host, 853), timeout=2) as raw:
            with context.wrap_socket(raw, server_hostname="lab.test") as sock:
                query = dns_packet(args[2])
                sock.sendall(struct.pack("!H", len(query)) + query)
                size = struct.unpack("!H", sock.recv(2))[0]
                data = sock.recv(size)
                assert data[:2] == query[:2]
                print(json.dumps({"ok": True, "transport": "DoT", "tls": sock.version()}))
    elif mode == "tls":
        version = getattr(ssl.TLSVersion, args[3])
        context.minimum_version = context.maximum_version = version
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
        with socket.create_connection((host, int(args[2])), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname="lab.test") as sock:
                negotiated = sock.version()
                time.sleep(1)  # Observe post-ServerHello policy before sending application data.
                sock.sendall(b"GET / HTTP/1.0\r\nHost: lab.test\r\n\r\n")
                data = sock.recv(4096)
                assert b"200 OK" in data
                print(json.dumps({"tls": negotiated, "application_access": "allowed"}))
    elif mode == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(b"ordinary UDP, not a VPN", (host, 51820))
        print(json.dumps({"ordinary_udp_sent": True}))
    elif mode == "scan":
        connections = [socket.create_connection((host, port), timeout=2) for port in range(20000, 20015)]
        print(json.dumps({"opened": len(connections)}), flush=True)
        time.sleep(60)
    elif mode == "counter":
        with socket.socket() as sock:
            sock.settimeout(12)
            sock.bind((CLIENT, 55000))
            sock.connect((host, 8080))
            sock.sendall(b"GET /slow HTTP/1.0\r\nHost: lab.test\r\n\r\n")
            while sock.recv(65536):
                pass
    elif mode == "workflows":
        staff_ip = args[2]

        def request(method, path, payload=None, cookie="", source=CLIENT, headers=None):
            connection = http.client.HTTPSConnection(host, 443, context=context, timeout=2,
                                                      source_address=(source, 0))
            fields = dict(headers or {})
            if cookie:
                fields["Cookie"] = cookie
            if payload is not None:
                fields["Content-Type"] = "application/json"
            connection.request(method, path, json.dumps(payload).encode() if payload is not None else None, fields)
            response = connection.getresponse()
            body = response.read()
            result = response.status, {key.lower(): value for key, value in response.getheaders()}, body
            connection.close()
            return result

        assert request("GET", "/api/account")[0] == 401
        assert request("POST", "/login", {"username": "alice", "password": "wrong"})[0] == 401

        def login(username, source=CLIENT):
            status, headers, body = request("POST", "/login", {"username": username, "password": SANDBOX_PASSWORD}, source=source)
            assert status == 200 and json.loads(body)["user"] == username
            assert "Secure" in headers["set-cookie"] and "HttpOnly" in headers["set-cookie"]
            return headers["set-cookie"].split(";", 1)[0]

        alice = login("alice")
        assert json.loads(request("GET", "/api/account", cookie=alice)[2])["credits"] == 100000
        payment = request("POST", "/payment", {"amount": 1250}, alice)
        transfer = request("POST", "/transfer", {"to": "bob", "amount": 2500}, alice)
        assert payment[0] == transfer[0] == 201
        assert json.loads(transfer[2])["to"] == "bob"
        assert request("POST", "/transfer", {"to": "bob", "amount": 999999999}, alice)[0] == 409
        assert request("POST", "/transfer", {"to": "bob", "amount": -1}, alice)[0] == 400
        assert json.loads(request("GET", "/api/account", cookie=alice)[2])["credits"] == 96250
        bob = login("bob")
        assert json.loads(request("GET", "/api/account", cookie=bob)[2])["credits"] == 52500
        statement = request("GET", "/documents/statement.csv", cookie=alice)
        assert statement[0] == 200 and b"alice,96250,2" in statement[2]
        student = login("student")
        assert request("GET", "/staff", cookie=student)[0] == 403
        staff = login("staff", staff_ip)
        staff_result = request("GET", "/staff", cookie=staff, source=staff_ip)
        assert staff_result[0] == 200 and json.loads(staff_result[2])["items"]
        lesson = request("GET", "/lessons/intro")
        assert lesson[0] == 200 and b"<video" in lesson[2]
        search = request("GET", "/search?q=fractions")
        assert search[0] == 200 and json.loads(search[2])["results"][0]["path"] == "/lessons/intro"
        partial = request("GET", "/media/lesson.webm", headers={"Range": "bytes=0-1023"})
        assert partial[0] == 206 and len(partial[2]) == 1024 and partial[2][:4] == bytes.fromhex("1a45dfa3")
        video = request("GET", "/media/lesson.webm")
        video_hash = hashlib.sha256(video[2]).hexdigest()
        assert video[0] == 200 and video_hash == video[1]["x-content-sha256"]
        Path("/tmp/minifw-sandbox-video.webm").write_bytes(video[2])
        print(json.dumps({"login": "passed", "api": "passed", "payment_credits": 1250,
                          "transfer_credits": 2500, "alice_credits": 96250, "bob_credits": 52500,
                          "overdraft_rejected": True, "statement_sha256": hashlib.sha256(statement[2]).hexdigest(),
                          "lesson": "passed", "search": "passed", "student_staff_access": "rejected",
                          "staff_service": "passed", "staff_source_ip": staff_ip,
                          "video_bytes": len(video[2]), "video_sha256": video_hash, "video_range": "passed",
                          "scope": "Fictional local sandbox; external institutions and browser playback are not validated"}))
    else:
        port, path = int(args[2]), args[3]
        connection = (http.client.HTTPSConnection(host, port, context=context, timeout=2)
                      if port == 443 else http.client.HTTPConnection(host, port, timeout=2))
        method = "POST" if path in {"/login", "/payment", "/api", "/transfer", "/dns-query"} else "GET"
        payload = dns_packet(args[4]) if path == "/dns-query" else b"authorized-lab-fixture"
        connection.request(method, path, body=payload if method == "POST" else None)
        response = connection.getresponse()
        body = response.read()
        assert response.status == 200
        if path == "/dns-query":
            assert body[:2] == payload[:2]
        print(json.dumps({"ok": True, "host": host, "port": port, "path": path,
                          "status": response.status, "bytes": len(body)}))
        connection.close()


def acceptance(edition, package, metadata=False, extended=False, provider_only=False):
    sector = "education" if edition == "education" else "finance"
    installed = subprocess.check_output(["dpkg-query", "-W", "-f=${Version}", "minifw-ai"], text=True).strip()
    assert installed == "2.2.10-" + sector, "Only v2.2.10 may be tested"
    assert subprocess.check_output(["dpkg-deb", "-f", package, "Version"], text=True).strip() == installed
    mode = "minifw_school" if edition == "education" else "minifw_financial"
    sector = "education" if edition == "education" else "finance"
    root = Path("/var/tmp") / ("minifw-monday-" + edition + "-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    root.mkdir(mode=0o755)
    results = []
    children = []
    script = str(Path(__file__).resolve())
    journal_since = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    dropin = Path("/etc/systemd/system/minifw-ai.service.d/90-monday-lab.conf")
    assert not dropin.exists(), "Existing lab override must be reviewed before another run"
    state_path = Path("/opt/minifw_ai/logs/deployment_state.json")
    state_before = state_path.read_bytes() if state_path.exists() else None
    state_mode = state_path.stat().st_mode & 0o777 if state_before is not None else 0o600

    def run(*command, check=True, timeout=30):
        print("$", shlex.join(command), flush=True)
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        if result.stdout:
            print(result.stdout.rstrip(), flush=True)
        if result.stderr:
            print(result.stderr.rstrip(), flush=True)
        if check:
            result.check_returncode()
        return result

    def ns(*args, allowed=True):
        result = run("ip", "netns", "exec", "mf-client", "/usr/bin/python3", script, "client", *args, check=False)
        assert (result.returncode == 0) == allowed, (args, result.returncode, result.stderr)
        return result

    def record(name, **actual):
        row = {"test": name, "actual": actual, "time": datetime.now(timezone.utc).isoformat()}
        results.append(row)
        (root / "results.json").write_text(json.dumps(results, indent=2))
        print("VERIFIED", json.dumps(row), flush=True)

    def nft(label):
        output = run("nft", "-a", "list", "table", "inet", "minifw", check=False).stdout
        (root / (label + ".nft")).write_text(output)

    def member():
        return subprocess.run(["nft", "get", "element", "inet", "minifw", "minifw_block_v4", "{", CLIENT, "}"],
                              capture_output=True).returncode == 0

    def wait_for(predicate, seconds=12):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            if predicate():
                return
            time.sleep(0.2)
        raise AssertionError("Timed out waiting for controlled lab result")

    policy = json.loads(Path(f"/opt/minifw_ai/config/modes/{mode}/policy.json").read_text())
    policy["enforcement"]["ip_timeout_seconds"] = 15  # Expiry mechanism test; shipping timeout/thresholds are untouched.
    policy["collectors"].update(dnsmasq_log_path=str(root / "dns.log"), zeek_ssl_log_path=str(root / "ssl.log"))
    (root / "policy.json").write_text(json.dumps(policy, indent=2))
    (root / "ssl.log").touch()
    (root / "empty-conntrack").touch()
    (root / "bin").mkdir()
    (root / "bin/nft").symlink_to("/usr/sbin/nft")
    (root / "package.sha256").write_text(hashlib.sha256(Path(package).read_bytes()).hexdigest() + "  " + str(package) + "\n")
    run("dpkg-query", "-W", "minifw-ai")
    existing_namespaces = json.loads(run("ip", "-j", "netns", "list").stdout.strip() or "[]")
    assert not {"mf-client", "mf-server"}.intersection(item["name"] for item in existing_namespaces)
    run("systemctl", "stop", "minifw-ai", "minifw-ai-web", "dnsmasq")
    nft("before-lab")
    run("nft", "delete", "table", "inet", "minifw", check=False)

    def start(source="file", flow="normal", zeek_missing=False, packet=False, ai=False, block_vpn=False):
        run("systemctl", "stop", "minifw-ai")
        event_path = root / "events.jsonl"
        previous_packets = event_path.read_text().count('"telemetry_source": "packet"') if event_path.exists() else 0
        if metadata:
            policy["protocol_controls"] = {"minimum_tls_version": "TLSv1.2", "block_vpn_tunnels": block_vpn}
            (root / "policy.json").write_text(json.dumps(policy, indent=2))
            state_path.unlink(missing_ok=True)  # Controlled initial AI state; original restored in finally.
        run("nft", "flush", "set", "inet", "minifw", "minifw_block_v4", check=False)
        run("conntrack", "-D", "-s", CLIENT, check=False)
        if zeek_missing:
            (root / "ssl.log").unlink(missing_ok=True)
        else:
            (root / "ssl.log").touch()
        conntrack = str(root / "empty-conntrack") if flow == "quiet" else "/proc/net/nf_conntrack"
        extra = f"Environment=PATH={root}/bin:/usr/bin:/bin\n" if flow == "missing" else ""
        text = ("[Service]\n" + extra + f"Environment=MINIFW_POLICY={root}/policy.json\n"
                f"Environment=MINIFW_LOG={root}/events.jsonl\nEnvironment=MINIFW_AUDIT_LOG={root}/audit.jsonl\n"
                f"Environment=MINIFW_FLOW_RECORDS={root}/flows.jsonl\nEnvironment=MINIFW_DNS_SOURCE={source}\n"
                f"Environment=MINIFW_CONNTRACK_PATH={conntrack}\nEnvironment=AI_ENABLED={int(ai)}\nEnvironment=DEGRADED_MODE=0\n"
                f"Environment=MINIFW_PACKET_INTERFACE={'mfcg' if packet else ''}\n"
                f"Environment=MINIFW_MLP_MODEL=/opt/minifw_ai/models/mlp_packet14.pkl\n"
                f"Environment=MINIFW_DISABLE_FLOWS=0\nEnvironment=MINIFW_SECTOR={sector}\nEnvironment=PRODUCT_MODE={mode}\n")
        dropin.parent.mkdir(exist_ok=True)
        dropin.write_text(text)
        audit = root / "audit.jsonl"
        previous = audit.read_text().count('"daemon_start"') if audit.exists() else 0
        run("systemctl", "daemon-reload")
        run("systemctl", "start", "minifw-ai")
        wait_for(lambda: audit.exists() and audit.read_text().count('"daemon_start"') > previous, 20)
        time.sleep(1.5 if packet else 0.4)
        run("systemctl", "show", "minifw-ai", "-p", "ActiveState", "-p", "MainPID", "-p", "ExecMainStatus")
        if packet:
            # Readiness is an observed packet decision, not a process or fixed startup delay.
            until = time.monotonic() + 20
            while time.monotonic() < until:
                ns("http", SERVER, "8080", "/")
                path = root / "events.jsonl"
                if path.exists() and path.read_text().count('"telemetry_source": "packet"') > previous_packets:
                    break
                time.sleep(.5)
            else:
                raise AssertionError("Packet sensor not ready: no observed packet decisions")

    dns_log = (root / "dnsmasq-process.log").open("w")
    try:
        run("modprobe", "nf_conntrack")
        run("sysctl", "-w", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1", "net.netfilter.nf_conntrack_acct=0")
        for namespace in ["mf-client", "mf-server"]:
            run("ip", "netns", "add", namespace)
            run("ip", "-n", namespace, "link", "set", "lo", "up")
        for gateway, peer, namespace, v4, gw4, v6, gw6 in [
            ("mfcg", "mfc0", "mf-client", "10.10.0.20/24", "10.10.0.1/24", "fd42:10::20/64", "fd42:10::1/64"),
            ("mfsg", "mfs0", "mf-server", "198.18.0.2/24", "198.18.0.1/24", "fd42:18::2/64", "fd42:18::1/64"),
        ]:
            run("ip", "link", "add", gateway, "type", "veth", "peer", "name", peer)
            run("ip", "link", "set", peer, "netns", namespace)
            for address in [gw4, gw6]:
                run("ip", "addr", "add", address, "dev", gateway)
            run("ip", "link", "set", gateway, "up")
            for address in [v4, v6]:
                run("ip", "-n", namespace, "addr", "add", address, "dev", peer)
            run("ip", "-n", namespace, "link", "set", peer, "up")
            run("ip", "-n", namespace, "route", "add", "default", "via", gw4.split("/")[0])
            run("ip", "-n", namespace, "-6", "route", "add", "default", "via", gw6.split("/")[0])
        run("ip", "-br", "address")
        run("ip", "-n", "mf-client", "route")
        run("ip", "-n", "mf-server", "route")
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=lab.test", "-keyout", str(root / "server.key"), "-out", str(root / "server.crt"))
        server_log = (root / "server.log").open("w")
        server = subprocess.Popen(["ip", "netns", "exec", "mf-server", "/usr/bin/python3", script,
                                   "server", str(root / "server.crt"), str(root / "server.key")], stdout=server_log, stderr=server_log)
        children.append(server)
        dns = subprocess.Popen(["/usr/sbin/dnsmasq", "--conf-file=/dev/null", "--keep-in-foreground", "--user=root", "--no-resolv", "--no-hosts",
            "--bind-interfaces", "--interface=mfcg", "--listen-address=10.10.0.1", "--address=/#/198.18.0.2",
            "--log-queries", f"--log-facility={root}/dns.log", f"--pid-file={root}/dns.pid"], stdout=dns_log, stderr=dns_log)
        children.append(dns)
        alternate_dns = subprocess.Popen(["ip", "netns", "exec", "mf-server", "/usr/sbin/dnsmasq", "--conf-file=/dev/null", "--keep-in-foreground",
            "--user=root", "--no-resolv", "--no-hosts", "--bind-interfaces", "--listen-address=198.18.0.2",
            "--address=/#/198.18.0.2", f"--pid-file={root}/alternate-dns.pid"], stdout=dns_log, stderr=dns_log)
        children.append(alternate_dns)
        time.sleep(1.5)
        assert all(process.poll() is None for process in children), "Lab fixtures failed to start"
        if provider_only:
            from lab_extended_acceptance import provider_checks
            provider_checks(root, run, start, record, children)
            return
        if extended:
            from lab_extended_acceptance import exercise
            exercise(root, run, start, record, nft, ns, member, children)
            return
        if metadata:
            def rows():
                path = root / "events.jsonl"
                return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

            start(source="none")
            ns("tls", SERVER, "8445", "TLSv1")
            record("TLS10_fixture_before_enforcement", application="allowed", meaning="The lab server genuinely accepts TLS 1.0")
            start(source="none", packet=True, ai=True)
            ns("http", SERVER, "8080", "/")
            wait_for(lambda: any(row.get("mlp_status") == "inferred" for row in rows()))
            inferred = next(row for row in reversed(rows()) if row.get("mlp_status") == "inferred")
            features = inferred["mlp_features"]
            assert inferred["mlp_schema"] == "packet14-v1" and len(features) == 14
            assert inferred["mlp_mode"] == "shadow_only" and inferred["score"] == 0
            assert features[0] > 0 and features[1] >= 5
            assert abs(features[3] - features[2] / features[0]) < 0.001
            record("measured_packet_model_inference", schema=inferred["mlp_schema"], features=features,
                   probability=inferred["mlp_probability"], telemetry=inferred["telemetry_source"],
                   training="synthetic; no real-world sector accuracy", DNS="disabled", mode="shadow_only", enforcement_score=0)
            workflow = ns("workflows", SERVER, CLIENT)
            record("measured_AI_legitimate_workflows", **json.loads(workflow.stdout))
            wait_for(lambda: (root / "flows.jsonl").exists() and (root / "flows.jsonl").stat().st_size > 0)
            exports = [json.loads(line) for line in (root / "flows.jsonl").read_text().splitlines()]
            assert exports and all(row["features"] is None and row["packet_feature_schema"] == "packet14-v1" for row in exports)
            record("packet_schema_export", legacy24_features=None, packet_schema="packet14-v1")
            for version in ["TLSv1_2", "TLSv1_3"]:
                ns("tls", SERVER, "443", version)
                expected = "TLSv1.2" if version == "TLSv1_2" else "TLSv1.3"
                wait_for(lambda: any(row.get("tls_version") == expected for row in rows()))
                assert not member()
                record("allowed_" + expected, application="allowed", selected_version=expected)
            start(source="none", packet=True)
            ns("tls", SERVER, "8445", "TLSv1", allowed=False)
            wait_for(member)
            nft("tls10-blocked")
            assert any("tls_version_below_minimum:TLSv1.0:TLSv1.2" in row["reasons"] for row in rows())
            ns("http", SERVER, "8080", "/", allowed=False)
            record("TLS10_enforcement", client=CLIENT, forwarded="blocked", scope="After visible ServerHello; no TLS decryption")
            run("nft", "delete", "element", "inet", "minifw", "minifw_block_v4", "{", CLIENT, "}")
            ns("http", SERVER, "8080", "/")

            def wireguard():
                run("modprobe", "wireguard")
                keys = [subprocess.check_output(["wg", "genkey"], text=True) for _ in range(2)]
                public = [subprocess.check_output(["wg", "pubkey"], input=key, text=True).strip() for key in keys]
                for index, namespace in enumerate(["mf-client", "mf-server"]):
                    key_path = root / (namespace + ".key")
                    key_path.touch(mode=0o600, exist_ok=True)
                    key_path.write_text(keys[index])
                    run("ip", "-n", namespace, "link", "delete", "wg0", check=False)
                    run("ip", "-n", namespace, "link", "add", "wg0", "type", "wireguard")
                    run("ip", "-n", namespace, "addr", "add", f"10.66.0.{index+1}/30", "dev", "wg0")
                    command = ["ip", "netns", "exec", namespace, "wg", "set", "wg0", "listen-port", "51820",
                               "private-key", str(key_path), "peer", public[1-index],
                               "allowed-ips", f"10.66.0.{2-index}/32"]
                    if index == 0:
                        command += ["endpoint", SERVER + ":51820"]
                    run(*command)
                    run("ip", "-n", namespace, "link", "set", "wg0", "up")

            start(source="none", packet=True)
            ns("udp", SERVER)
            time.sleep(0.5)
            assert not any(row.get("vpn_protocol") for row in rows())
            record("ordinary_UDP_not_a_tunnel", detected=False)
            wireguard()
            run("ip", "netns", "exec", "mf-client", "ping", "-I", "wg0", "-c", "2", "-W", "2", "10.66.0.2")
            wait_for(lambda: any(row.get("vpn_protocol") == "wireguard" for row in rows()))
            assert not member()
            record("WireGuard_monitor", tunnel="actual kernel WireGuard", inner_ping="allowed", action="monitor")
            start(source="none", packet=True, block_vpn=True)
            wireguard()
            run("ip", "netns", "exec", "mf-client", "ping", "-I", "wg0", "-c", "2", "-W", "1", "10.66.0.2", check=False)
            wait_for(member)
            nft("wireguard-blocked")
            failed = run("ip", "netns", "exec", "mf-client", "ping", "-I", "wg0", "-c", "1", "-W", "1", "10.66.0.2", check=False)
            assert failed.returncode != 0
            ns("http", SERVER, "8080", "/", allowed=False)
            record("WireGuard_enforcement", client=CLIENT, inner_ping="blocked", forwarded="blocked",
                   limitation="Handshake/transport pattern, not cryptographic authentication or all VPN protocols")

            start()
            dns.terminate()
            dns.wait(timeout=5)
            config = root / "safesearch.conf"
            run("/opt/minifw_ai/venv/bin/python", "/opt/minifw_ai/app/minifw_ai/safesearch.py", "--output", str(config))
            print(config.read_text(), flush=True)
            restricted = subprocess.Popen(["/usr/sbin/dnsmasq", "--conf-file=" + str(config), "--keep-in-foreground",
                "--user=root", "--no-resolv", "--no-hosts", "--bind-interfaces", "--listen-address=10.10.0.1",
                "--address=/#/198.18.0.2", "--log-queries", f"--log-facility={root}/restricted-dns.log"],
                stdout=dns_log, stderr=dns_log)
            children.append(restricted)
            time.sleep(.5)
            assert restricted.poll() is None
            aliases = {
                "forcesafesearch.google.com": ["google.com", "www.google.com", "google.co.id", "www.google.co.id"],
                "strict.bing.com": ["bing.com", "www.bing.com", "edgeservices.bing.com"],
                "restrict.youtube.com": ["www.youtube.com", "m.youtube.com", "youtubei.googleapis.com",
                                         "youtube.googleapis.com", "www.youtube-nocookie.com"],
            }
            for name, target in [(name, target) for target, names in aliases.items() for name in names]:
                answer = run("ip", "netns", "exec", "mf-client", "dig", "@10.10.0.1", name, "A", "+noall", "+answer").stdout
                assert target + "." in answer and "\tA\t" in answer
                record("restricted_DNS_" + name, cname=target, answer=answer.strip())
            answer = run("ip", "netns", "exec", "mf-client", "dig", "@10.10.0.1", "accounts.google.com", "A", "+short").stdout
            assert answer.strip() == SERVER
            answer = run("ip", "netns", "exec", "mf-client", "dig", "@10.10.0.1", "youtube.com", "A", "+short").stdout
            assert answer.strip() == SERVER
            canary = run("ip", "netns", "exec", "mf-client", "dig", "@10.10.0.1", "use-application-dns.net", "A").stdout
            assert "status: NXDOMAIN" in canary, canary
            record("firefox_doh_canary", query="use-application-dns.net A", status="NXDOMAIN",
                   meaning="Firefox keeps default DoH off on this resolver; explicit user DoH and other browsers unaffected")
            ns("http", SERVER, "8080", "/")
            record("SafeSearch_scope", accounts_unmodified=True, forwarding="allowed",
                   remaining="Alternate/encrypted DNS, unlisted domains and browser results require separate acceptance")
            return
        start()
        assert Path("/proc/sys/net/netfilter/nf_conntrack_acct").read_text().strip() == "1"
        record("engine_activates_kernel_accounting", result="enabled")
        segment_clients = ({"student": CLIENT, "staff": "192.168.1.20", "guest": "192.168.100.20", "admin": "10.0.0.20"}
                           if edition == "education" else
                           {"dmz": CLIENT, "trading": "10.50.0.20", "internal": "192.168.1.20", "guest": "192.168.100.20"})
        for segment, address in segment_clients.items():
            if address != CLIENT:
                run("ip", "-n", "mf-client", "addr", "add", address + "/32", "dev", "mfc0")
                run("ip", "route", "add", address + "/32", "dev", "mfcg")
            domain = segment + ".approved.test"
            ns("dns", "10.10.0.1", domain, address)

            def selected_segment():
                path = root / "events.jsonl"
                if not path.exists():
                    return False
                rows = [json.loads(line) for line in path.read_text().splitlines()]
                return any(row["client_ip"] == address and row["domain"] == domain and row["segment"] == segment for row in rows)

            wait_for(selected_segment)
            record("policy_selection_" + segment, client=address, segment=segment,
                   topology="Routed source aliases in the isolated client namespace; not VLAN-isolation acceptance")

        workflow = ns("workflows", SERVER, segment_clients.get("staff", segment_clients.get("internal", CLIENT)))
        record("legitimate_sandbox_workflows", **json.loads(workflow.stdout))

        sys.path.insert(0, "/opt/minifw_ai/app")
        from minifw_ai.collector_flow import FlowTracker, parse_conntrack_line
        counter_log = (root / "counter-client.log").open("w")
        counter_client = subprocess.Popen(["ip", "netns", "exec", "mf-client", "/usr/bin/python3", script,
                                          "client", "counter", SERVER], stdout=counter_log, stderr=counter_log)
        children.append(counter_client)
        time.sleep(0.8)

        def measured_sample():
            output = run("conntrack", "-L", "-s", CLIENT, "-o", "extended").stdout
            samples = [parse_conntrack_line(line) for line in output.splitlines()]
            return next(sample for sample in samples if sample and sample.src_port == 55000)

        first = measured_sample()
        assert all(value is not None for value in first.counters), "Kernel accounting unavailable"
        tracker = FlowTracker()
        for _ in range(20):
            measured, _ = tracker.observe_conntrack(first)
        assert measured.pkt_count == measured.get_total_bytes() == 0
        time.sleep(2)
        second = measured_sample()
        measured, _ = tracker.observe_conntrack(second)
        expected = [new - old for new, old in zip(second.counters, first.counters)]
        assert (measured.pkt_count, measured.bytes_sent, measured.bytes_recv) == (
            expected[0] + expected[2], expected[1], expected[3])
        assert measured.bytes_recv > 0 and not measured.interarrival_times
        record("kernel_counter_deltas", first=first.counters, second=second.counters,
               measured_packets=measured.pkt_count, measured_bytes_out=measured.bytes_sent,
               measured_bytes_in=measured.bytes_recv, repeated_snapshot_increments=0,
               packet_timing_available=False)
        counter_client.terminate()
        counter_client.wait(timeout=5)

        denied = "4chan.org" if edition == "education" else "secure-bankofamerica-login.com"
        for mode_name, args in [("alternate_DNS", ("dns", SERVER, denied)),
                                ("DoH", ("http", SERVER, "443", "/dns-query", denied)),
                                ("DoT", ("dot", SERVER, denied)),
                                ("direct_IP", ("http", SERVER, "8080", "/")),
                                ("IPv6", ("http", SERVER6, "8080", "/"))]:
            ns(*args)
            record("bypass_" + mode_name, result="allowed", coverage="outside current name/IPv4 coverage")

        for flow_mode in ["quiet", "missing"]:
            start(flow=flow_mode)
            before = time.monotonic()
            query = denied if flow_mode == "quiet" else "www." + denied
            ns("dns", "10.10.0.1", query)
            wait_for(member)
            elapsed = time.monotonic() - before
            assert elapsed < 3, "Quiet/missing flow collector delayed DNS decision"
            nft("dns-block-flow-" + flow_mode)
            ns("http", SERVER, "8080", "/", allowed=False)
            record("DNS_decision_with_flow_" + flow_mode, client=CLIENT, domain=query, elapsed_seconds=elapsed, forwarded="blocked")

        if edition == "education":
            start()
            ns("dns", "10.10.0.1", "nordvpn.com")
            wait_for(member)
            nft("vpn-provider-domain-block")
            ns("http", SERVER, "8080", "/", allowed=False)
            record("VPN_provider_domain", domain="nordvpn.com", forwarded="blocked", limitation="Not a VPN tunnel detection test")

        start()
        ns("dns", "10.10.0.1", denied)
        wait_for(member)
        nft("blocked-before-duplicate")
        before = (root / "events.jsonl").read_text().count('"action": "block"')
        ns("dns", "10.10.0.1", denied)
        time.sleep(0.5)
        assert (root / "events.jsonl").read_text().count('"action": "block"') == before
        nft("blocked-after-duplicate")
        record("duplicate_block", added_events=0, expiry_refresh=False)
        run("systemctl", "restart", "minifw-ai")
        wait_for(member, 3)
        ns("http", SERVER, "8080", "/", allowed=False)
        record("restart_preserves_kernel_block", result="blocked")
        wait_for(lambda: not member(), 20)
        nft("after-expiry")
        ns("http", SERVER, "8080", "/")
        record("expiry_recovery", result="allowed", lab_timeout_seconds=15)

        ns("dns", "10.10.0.1", denied)
        wait_for(member)
        ns("http", SERVER6, "8080", "/")
        record("IPv6_during_IPv4_isolation", result="allowed", limitation="IPv6 is not enforced")
        run("nft", "delete", "element", "inet", "minifw", "minifw_block_v4", "{", CLIENT, "}")
        ns("http", SERVER, "8080", "/")
        nft("after-manual-unblock")
        record("manual_unblock_recovery", result="allowed")

        for dns_mode in ["none", "missing"]:
            if dns.poll() is None:
                dns.terminate()
                dns.wait(timeout=5)
            if dns_mode == "missing":
                (root / "dns.log").rename(root / "dns-before-missing.log")
            start(source="none" if dns_mode == "none" else "file", zeek_missing=dns_mode == "missing")
            nft("flow-before-" + dns_mode)
            attack_log = (root / ("scan-" + dns_mode + ".log")).open("w")
            attack = subprocess.Popen(["ip", "netns", "exec", "mf-client", "/usr/bin/python3", script,
                                       "client", "scan", SERVER], stdout=attack_log, stderr=attack_log)
            children.append(attack)
            wait_for(member)
            nft("flow-blocked-" + dns_mode)
            ns("http", SERVER, "8080", "/", allowed=False)
            events = [json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()]
            actual = next(event for event in reversed(events) if event["action"] == "block")
            assert actual["telemetry_source"] == "flow" and "port_scan" in actual["reasons"]
            record("flow_only_with_DNS_" + dns_mode, client=actual["client_ip"], destination=actual["dst_ip"],
                   decision=actual["reasons"], forwarded="blocked")
            attack.terminate()
            attack.wait(timeout=5)
            time.sleep(0.5)  # Let both endpoints close before deleting the next run's conntrack state.

        record("acceptance_scope", shared_core="verified by controlled routed traffic", production_ready=False,
               remaining="real sector applications, SafeSearch, VPN tunnel detection, measured-feature model validation")
    finally:
        run("systemctl", "stop", "minifw-ai", check=False)
        for process in children:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
        journal = run("journalctl", "-u", "minifw-ai", "--no-pager", "--since", journal_since, check=False).stdout
        (root / "engine-journal.log").write_text(journal)
        nft("final")
        dropin.unlink(missing_ok=True)
        if metadata:
            if state_before is None:
                state_path.unlink(missing_ok=True)
            else:
                state_path.write_bytes(state_before)
                state_path.chmod(state_mode)
        run("systemctl", "daemon-reload", check=False)
        for namespace in ["mf-client", "mf-server"]:
            run("ip", "netns", "delete", namespace, check=False)
        for interface in ["mfcg", "mfsg"]:
            run("ip", "link", "delete", interface, check=False)
        print("EVIDENCE_DIRECTORY", root, flush=True)


if __name__ == "__main__":
    assert socket.gethostname().startswith("minifw-monday-"), "Refusing to run outside dedicated lab VM"
    if sys.argv[1] == "server":
        serve(*sys.argv[2:])
    elif sys.argv[1] == "client":
        try:
            client(sys.argv[2:])
        except (OSError, ssl.SSLError, http.client.HTTPException) as error:
            print(json.dumps({"ok": False, "error": type(error).__name__}), flush=True)
            raise SystemExit(2)
    else:
        assert os.geteuid() == 0 and subprocess.check_output(["systemd-detect-virt"], text=True).strip() in {"kvm", "qemu"}
        assert sys.argv[1] in {"education", "financial"}
        assert socket.gethostname() == "minifw-monday-" + sys.argv[1]
        acceptance(sys.argv[1], sys.argv[2], metadata="--metadata" in sys.argv[3:], extended="--extended" in sys.argv[3:],
                   provider_only="--providers-only" in sys.argv[3:])
