"""Browser, tunnel, bypass and labelled-measurement checks in the guarded lab driver."""

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import ssl
import sqlite3
import urllib.error
import urllib.request


def operational_checks(root, run, start, record, nft, ns, member):
    override = Path("/etc/systemd/system/minifw-ai-web.service.d/90-monday-health.conf")
    assert not override.exists()
    override.parent.mkdir(exist_ok=True)
    override.write_text(f"[Service]\nEnvironment=MINIFW_HEALTH_FILE={root}/runtime-health.json\n")
    marker = Path("/opt/minifw_ai/config/continuation-marker.json")
    assert not marker.exists()

    def health():
        try:
            response = urllib.request.urlopen("https://127.0.0.1:8443/health/", context=ssl._create_unverified_context(), timeout=3)
        except urllib.error.HTTPError as error:
            response = error
        return response.code, json.load(response)

    def ready():
        for _ in range(15):
            ns("http", "198.18.0.2", "8080", "/")
            try:
                status, data = health()
                if status == 200:
                    return data
            except (OSError, ValueError):
                pass
            time.sleep(.5)
        raise AssertionError("No observed healthy decision/kernel state")

    try:
        start(source="none", packet=True)
        run("systemctl", "daemon-reload")
        run("systemctl", "start", "minifw-ai-web")
        record("runtime_health_observed_ready", **ready())
        run("systemctl", "stop", "minifw-ai")
        status, data = health()
        assert status == 503
        record("runtime_health_stopped_engine", http_status=status, **data)
        start(source="none", packet=True)
        ready()
        nft("health-before-missing-rule")
        run("nft", "flush", "chain", "inet", "minifw", "forward")
        time.sleep(3)
        ns("http", "198.18.0.2", "8080", "/")
        status, data = health()
        assert status == 503 and data["kernel_rule_present"] is False
        nft("health-missing-rule")
        record("runtime_health_missing_rule", http_status=status, **data)
        start(source="none", packet=True)
        ready()
        # No background fixture traffic: quiet does not certify a working sensor.
        time.sleep(32)
        status, data = health()
        assert status == 503
        record("runtime_health_quiet_sensor", http_status=status, **data)
        ready()
        marker.write_text('{"snapshot":1}')
        database = "/opt/minifw_ai/minifw.db"
        with sqlite3.connect(database) as connection:
            connection.execute("CREATE TABLE continuation_rehearsal (marker INTEGER)")
            connection.execute("INSERT INTO continuation_rehearsal VALUES (1)")
        backup = run("bash", "/opt/minifw_ai/scripts/backup.sh", timeout=60)
        archive = Path(next(line.split()[1] for line in backup.stdout.splitlines() if line.startswith("BACKUP ")))
        assert archive.stat().st_mode & 0o777 == 0o600 and archive.parent.stat().st_mode & 0o777 == 0o700
        assert run("runuser", "-u", "lab", "--", "test", "-r", str(archive), check=False).returncode != 0
        marker.write_text('{"snapshot":2}')
        with sqlite3.connect(database) as connection:
            connection.execute("UPDATE continuation_rehearsal SET marker=2")
        run("bash", "/opt/minifw_ai/scripts/restore.sh", str(archive), timeout=60)
        assert json.loads(marker.read_text())["snapshot"] == 1
        with sqlite3.connect(database) as connection:
            assert connection.execute("SELECT marker FROM continuation_rehearsal").fetchall() == [(1,)]
            assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        record("private_backup_restore_rehearsal", file_and_database="restored", sqlite_integrity="ok",
               archive_mode="0600", directory_mode="0700", unprivileged_read="denied",
               dynamic_blocks="not restored", package_rollback="not tested")
        ready()
    finally:
        run("systemctl", "stop", "minifw-ai-web", check=False)
        override.unlink(missing_ok=True)
        run("systemctl", "daemon-reload", check=False)
        marker.unlink(missing_ok=True)
        with sqlite3.connect("/opt/minifw_ai/minifw.db") as connection:
            connection.execute("DROP TABLE IF EXISTS continuation_rehearsal")


def guard_checks(root, run, start, record, nft, ns, member):
    python = "/opt/minifw_ai/venv/bin/python"
    start()
    try:
        run(python, "-m", "minifw_ai.egress_guard", "--interface", "mfcg", "--block-ipv6")
        denied = "4chan.org" if socket.gethostname().endswith("education") else "secure-bankofamerica-login.com"
        ns("dns", "198.18.0.2", denied)
        for _ in range(30):
            if member():
                break
            time.sleep(.2)
        assert member(), "Redirected alternate DNS must reach the gateway's deny decision"
        nft("redirected-dns-client-blocked")
        ns("http", "198.18.0.2", "8080", "/", allowed=False)
        record("guarded_alternate_DNS", result="redirected_and_blocked", client="10.10.0.20",
               requested_resolver="198.18.0.2", actual_resolver="gateway", forwarded="blocked")
        run("nft", "delete", "element", "inet", "minifw", "minifw_block_v4", "{", "10.10.0.20", "}")
        ns("dot", "198.18.0.2", "approved.test", allowed=False)
        ns("http", "fd42:18::2", "8080", "/", allowed=False)
        ns("http", "198.18.0.2", "443", "/dns-query", "denied.lab.test")
        ns("http", "198.18.0.2", "8080", "/")
        record("guarded_bypass_scope", DoT="blocked", IPv6="blocked by explicit full IPv6 forwarding denial",
               DoH="allowed", direct_IP="allowed", UDP_853="configured; no DoQ protocol acceptance",
               limitation="No generic HTTPS DoH identification, IPv6 inspection or all-tunnel claim")
        rules = run("nft", "-a", "list", "table", "inet", "minifw_egress").stdout
        (root / "egress-guard.nft").write_text(rules)
    finally:
        run(python, "-m", "minifw_ai.egress_guard", "--remove", check=False)
    ns("http", "fd42:18::2", "8080", "/")
    ns("dot", "198.18.0.2", "approved.test")
    record("guard_removal_recovery", IPv6="allowed", DoT="allowed")


def browser_checks(output):
    from playwright.sync_api import sync_playwright

    assert os.geteuid() != 0, "Run the browser as the unprivileged lab user"
    output = Path(output)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path="/usr/bin/chromium", chromium_sandbox=True,
                                            args=["--disable-dev-shm-usage", "--no-proxy-server"])
        try:
            context = browser.new_context(ignore_https_errors=True, accept_downloads=True)
            page = context.new_page()
            page.goto("https://198.18.0.2/", wait_until="domcontentloaded")

            def request(path, data=None):
                return page.evaluate("""async ([path, data]) => {
                    const r = await fetch(path, data === null ? {} : {method:'POST',
                        headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)});
                    return {status:r.status, body:await r.json()};
                }""", [path, data])

            from lab_sandbox import SANDBOX_PASSWORD
            assert request("/api/account")["status"] == 401
            assert request("/login", {"username": "alice", "password": "wrong"})["status"] == 401
            assert request("/login", {"username": "alice", "password": SANDBOX_PASSWORD})["status"] == 200
            before = request("/api/account")["body"]["credits"]
            assert request("/payment", {"amount": 1250})["status"] == 201
            assert request("/transfer", {"amount": 2500, "to": "bob"})["status"] == 201
            assert request("/api/account")["body"]["credits"] == before - 3750
            assert request("/transfer", {"amount": 10**9, "to": "bob"})["status"] == 409
            with page.expect_download() as download:
                page.evaluate("location.href='/documents/statement.csv'")
            document = download.value
            assert document.suggested_filename == "sandbox-statement.csv"
            assert b"alice," in Path(document.path()).read_bytes()
            assert request("/login", {"username": "student", "password": SANDBOX_PASSWORD})["status"] == 200
            assert request("/staff")["status"] == 403
            assert request("/login", {"username": "staff", "password": SANDBOX_PASSWORD})["status"] == 200
            assert request("/staff")["status"] == 200
            page.goto("https://198.18.0.2/learning", wait_until="domcontentloaded")
            page.locator("video").evaluate("v => {v.muted=true; return v.play();}")
            page.wait_for_function("document.querySelector('video').ended", timeout=15000)
            media = page.locator("video").evaluate("v => ({time:v.currentTime,duration:v.duration,width:v.videoWidth,height:v.videoHeight,frames:v.getVideoPlaybackQuality().totalVideoFrames,error:v.error})")
            assert media["time"] > 0 and media["width"] > 0 and media["frames"] > 0 and media["error"] is None
            page.screenshot(path=str(output / "lesson-played.png"))
            page.get_by_label("Search lessons").fill("fractions")
            page.get_by_role("button", name="Search").click()
            page.wait_for_url("**/search?q=fractions")
            assert "Fractions" in page.locator("body").inner_text()
            print(json.dumps({"browser": browser.version, "login_payment_transfer_download_staff": "passed",
                              "video": media, "search": "passed", "scope": "fictional sandbox; self-signed destination certificate accepted only in this browser context"}), flush=True)
        finally:
            browser.close()


def provider_browser(output):
    from playwright.sync_api import sync_playwright
    assert os.geteuid() != 0
    output = Path(output)
    results = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path="/usr/bin/chromium", chromium_sandbox=True,
                                            args=["--disable-dev-shm-usage", "--no-proxy-server"])
        try:
            context = browser.new_context()  # Public providers require valid TLS; never ignore errors.
            for provider, url in [("google", "https://www.google.com/safesearch"),
                                  ("bing", "https://www.bing.com/account/general"),
                                  ("youtube", "https://www.youtube.com/check_content_restrictions")]:
                page = context.new_page()
                result = {"provider": provider, "requested_url": url, "status": "unverified"}
                try:
                    response = page.goto(url, wait_until="domcontentloaded", timeout=25000)
                    page.wait_for_timeout(2000)
                    text = page.locator("body").inner_text(timeout=5000)
                    rows = page.locator("tr").all_text_contents()
                    (output / (provider + "-status.txt")).write_text(text)
                    page.screenshot(path=str(output / (provider + "-status.png")))
                    result.update(http_status=response.status if response else None, final_url=page.url, table_rows=rows,
                                  review="Rendered status retained; no restricted-content quality or bypass claim")
                    if provider == "youtube" and any("DNS" in row and "Strict" in row for row in rows):
                        result["status"] = "strict_DNS_status_observed"
                except Exception as error:
                    result.update(error_type=type(error).__name__, error=str(error).splitlines()[0])
                results.append(result)
                page.close()
        finally:
            browser.close()
    print(json.dumps(results), flush=True)


def provider_checks(root, run, start, record, children):
    start(source="none", packet=True)
    config = root / "public-safesearch.conf"
    run("/opt/minifw_ai/venv/bin/python", "/opt/minifw_ai/app/minifw_ai/safesearch.py", "--output", str(config))
    resolver_directory = Path("/etc/netns/mf-client")
    assert not resolver_directory.exists(), "Preserve any existing client resolver configuration"
    resolver_directory.mkdir(parents=True)
    (resolver_directory / "resolv.conf").write_text("nameserver 10.10.0.53\n")
    try:
        run("ip", "addr", "add", "10.10.0.53/24", "dev", "mfcg")
        run("nft", "add", "table", "ip", "minifw_browser_internet")
        batch = ('add chain ip minifw_browser_internet postrouting { type nat hook postrouting priority srcnat; policy accept; }\n'
                 'add rule ip minifw_browser_internet postrouting ip saddr 10.10.0.20 oifname "ens3" counter masquerade\n')
        print("$ nft -f -\n" + batch, flush=True)
        result = subprocess.run(["nft", "-f", "-"], input=batch, text=True, capture_output=True)
        result.check_returncode()
        log = (root / "public-resolver.log").open("w")
        resolver = subprocess.Popen(["dnsmasq", "--keep-in-foreground", "--user=root", "--conf-file=" + str(config),
            "--no-resolv", "--no-hosts", "--bind-interfaces", "--listen-address=10.10.0.53", "--server=10.231.0.3",
            "--log-queries", "--log-facility=-"], stdout=log, stderr=log)
        children.append(resolver)
        time.sleep(.5)
        assert resolver.poll() is None
        for domain in ["www.google.com", "www.bing.com", "www.youtube.com"]:
            run("ip", "netns", "exec", "mf-client", "dig", "@10.10.0.53", domain, "A", "+noall", "+answer")
        result = run("ip", "netns", "exec", "mf-client", "runuser", "-u", "lab", "--",
                     "/opt/minifw_ai/venv/bin/python", __file__, "providers", str(root / "browser"), timeout=110)
        record("provider_browser_restriction_status", results=json.loads(result.stdout.splitlines()[-1]),
               topology="Client namespace -> isolated VM NAT -> public provider; certificate validation enabled")
    finally:
        run("nft", "delete", "table", "ip", "minifw_browser_internet", check=False)
        (resolver_directory / "resolv.conf").unlink(missing_ok=True)
        resolver_directory.rmdir()


def exercise(root, run, start, record, nft, ns, member, children):
    start(source="none", packet=True, ai=True)
    browser_output = root / "browser"
    browser_output.mkdir()
    run("chown", "lab:lab", str(browser_output))
    browser = run("ip", "netns", "exec", "mf-client", "runuser", "-u", "lab", "--",
                  "/opt/minifw_ai/venv/bin/python", __file__, "browser", str(browser_output), timeout=60)
    record("actual_browser_legitimate_workflows", **json.loads(browser.stdout.splitlines()[-1]))
    assert not member(), "Legitimate browser workflows must not isolate the client"

    # These labels describe controlled fixtures, not representative institutional traffic.
    scenarios = [("benign_http", "benign", ("http", "198.18.0.2", "8080", "/")),
                 ("benign_tls", "benign", ("tls", "198.18.0.2", "443", "TLSv1_3")),
                 ("benign_document_lesson", "benign", ("http", "198.18.0.2", "443", "/learning"))]
    corpus = []
    for name, label, args in scenarios:
        for repeat in range(3):
            events_path = root / "events.jsonl"
            previous = len(events_path.read_text().splitlines())
            ns(*args)
            time.sleep(.35)
            events = [json.loads(line) for line in events_path.read_text().splitlines()[previous:]]
            inferred = [event for event in events if event.get("mlp_status") == "inferred"]
            assert inferred, (name, "No measured inference")
            event = inferred[-1]
            assert event["mlp_mode"] == "shadow_only"
            corpus.append({"scenario": name, "repeat": repeat, "label": label,
                           "label_source": "controlled benign lab fixture", "features": event["mlp_features"],
                           "probability": event["mlp_probability"], "schema": event["mlp_schema"],
                           "timestamp": event.get("ts"), "edition": socket.gethostname()})
    (root / "labelled-corpus.json").write_text(json.dumps(corpus, indent=2))
    false_positives = sum(row["probability"] >= .5 for row in corpus)
    record("controlled_AI_quality", samples=len(corpus), false_positives=false_positives,
           false_positive_fraction=false_positives / len(corpus), representative=False,
           training_unchanged=True, enforcement="shadow_only; zero model score")

    # A real OpenVPN static-key tunnel tests a different VPN, not a provider hostname.
    # shortcut: this explicitly labelled obsolete static-key fixture is a coverage probe,
    # replace it with modern authenticated deployments before claiming VPN acceptance.
    start(source="none", packet=True, block_vpn=True)
    secret = root / "openvpn.key"
    run("openvpn", "--genkey", "secret", str(secret))
    secret.chmod(0o600)
    for namespace, own, peer in [("mf-server", "10.67.0.2", "10.67.0.1"),
                                 ("mf-client", "10.67.0.1", "10.67.0.2")]:
        command = ["ip", "netns", "exec", namespace, "openvpn", "--dev", "tun0", "--proto", "udp4",
                   "--port", "1194", "--ifconfig", own, peer, "--secret", str(secret),
                   "--cipher", "AES-256-CBC", "--auth", "SHA256", "--ping", "1", "--verb", "3"]
        if namespace == "mf-client":
            command += ["--remote", "198.18.0.2"]
        log = (root / (namespace + "-openvpn.log")).open("w")
        process = subprocess.Popen(command, stdout=log, stderr=log)
        children.append(process)
    time.sleep(2)
    probe = run("ip", "netns", "exec", "mf-client", "ping", "-I", "tun0", "-c", "2", "-W", "2", "10.67.0.2", check=False)
    assert probe.returncode == 0, "OpenVPN fixture must carry actual inner traffic"
    assert not member()
    nft("openvpn-coverage-gap")
    record("actual_OpenVPN_coverage", result="allowed", detected=False,
           fixture="deprecated static-key AES-256-CBC tunnel carrying inner ping",
           limitation="WireGuard recognition does not cover OpenVPN; no generic encrypted tunnel claim")
    for process in children[-2:]:
        process.terminate()
        process.wait(timeout=5)

    start()
    for name, args in [("alternate_DNS", ("dns", "198.18.0.2", "denied.lab.test")),
                       ("DoH", ("http", "198.18.0.2", "443", "/dns-query", "denied.lab.test")),
                       ("DoT", ("dot", "198.18.0.2", "denied.lab.test")),
                       ("direct_IP", ("http", "198.18.0.2", "8080", "/")),
                       ("IPv6", ("http", "fd42:18::2", "8080", "/"))]:
        ns(*args)
        record("extended_bypass_" + name, result="allowed", coverage="outside current name/IPv4 policy")

    guard_checks(root, run, start, record, nft, ns, member)
    operational_checks(root, run, start, record, nft, ns, member)
    provider_checks(root, run, start, record, children)


if __name__ == "__main__":
    assert socket.gethostname() in {"minifw-monday-education", "minifw-monday-financial"}
    assert sys.argv[1] in {"browser", "providers"}
    (browser_checks if sys.argv[1] == "browser" else provider_browser)(sys.argv[2])
