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
    # The dashboard runs as minifw-web: give the lab health folder the same setgid group model as /opt/minifw_ai/logs.
    import grp
    os.chown(root, 0, grp.getgrnam("minifw-web").gr_gid)
    os.chmod(root, 0o2750)
    override.write_text(f"[Service]\nBindReadOnlyPaths={root}:/run/minifw-lab-health\n"
                        "Environment=MINIFW_HEALTH_FILE=/run/minifw-lab-health/runtime-health.json\n")
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
                print("HEALTH_POLL", status, json.dumps(data), flush=True)
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
        database = "/var/lib/minifw-ai/minifw.db"
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
        pid = run("systemctl", "show", "minifw-ai-web", "-p", "MainPID", "--value").stdout.strip()
        process = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
        assert process["NoNewPrivs"].strip() == "1"
        assert process["Uid"].split()[0] != "0" and process["Gid"].split()[0] != "0"
        assert int(process["CapBnd"].strip(), 16) == 0 and int(process["CapEff"].strip(), 16) == 0
        restrictions = run("systemctl", "show", "minifw-ai-web", "-p", "User", "-p", "ProtectSystem",
                           "-p", "ProtectHome", "-p", "PrivateTmp", "-p", "NoNewPrivileges", "-p", "CapabilityBoundingSet").stdout
        record("web_service_restrictions", properties=restrictions, no_new_privileges=True,
               uid=process["Uid"].split()[0], capabilities="none (CapBnd=0, CapEff=0)",
               remaining="Dashboard can still edit policy/feeds by design; engine remains root")
        record("dashboard_unprivileged_smoke", **dashboard_smoke(run))
        rotation = Path("/opt/minifw_ai/logs/continuation-rotation.jsonl")
        state = rotation.with_suffix(".json")
        rotation.write_text('{"rotation":"control"}\n')
        state.write_text('{"state":"must remain"}')
        try:
            run("logrotate", "--force", "--state", str(root / "logrotate.state"), "/etc/logrotate.d/minifw-ai")
            assert rotation.read_bytes() == b"" and b'"control"' in Path(str(rotation) + ".1").read_bytes()
            assert json.loads(state.read_text())["state"] == "must remain"
            record("actual_log_rotation", append_log="rotated and truncated", state_json="preserved",
                   remaining="copytruncate has a possible concurrent-write loss window; disk-full/load behavior unverified")
        finally:
            rotation.unlink(missing_ok=True)
            Path(str(rotation) + ".1").unlink(missing_ok=True)
            state.unlink(missing_ok=True)
    finally:
        run("systemctl", "stop", "minifw-ai-web", check=False)
        override.unlink(missing_ok=True)
        run("systemctl", "daemon-reload", check=False)
        marker.unlink(missing_ok=True)
        with sqlite3.connect("/var/lib/minifw-ai/minifw.db") as connection:
            connection.execute("DROP TABLE IF EXISTS continuation_rehearsal")


def dashboard_smoke(run):
    """Log into the real dashboard as admin and exercise the paths that need file access."""
    import http.client
    import urllib.parse
    secrets = dict(line.split("=", 1) for line in Path("/etc/minifw/minifw.env").read_text().splitlines() if "=" in line)
    context = ssl._create_unverified_context()

    def call(method, path, body=None, cookie="", form=False):
        connection = http.client.HTTPSConnection("127.0.0.1", 8443, context=context, timeout=10)
        headers = {"Cookie": cookie} if cookie else {}
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
            body = urllib.parse.urlencode(body) if form else json.dumps(body)
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.getheader("Set-Cookie") or "", response.read(), response.getheader("Location") or ""

    def login(password):
        status, set_cookie, _, location = call("POST", "/auth/login", {"username": "admin", "password": password}, form=True)
        assert status == 303 and "access_token=" in set_cookie, ("login", status)  # never print the password or token
        return set_cookie.split(";", 1)[0], location

    def change(cookie, old, new):
        status, _, _, location = call("POST", "/auth/change-password", {"current_password": old, "new_password": new,
                                      "confirm_password": new}, cookie, form=True)
        assert status == 303 and location.startswith("/auth/login"), ("change-password", status, location)

    import secrets as token_source
    original = secrets["MINIFW_ADMIN_PASSWORD"].strip()
    temporary = "Lab-" + token_source.token_urlsafe(18)
    cookie, location = login(original)
    # A fresh install forces the admin to change the password before any admin page.
    assert location == "/auth/change-password", location
    status, _, _, location = call("GET", "/admin/", cookie=cookie)
    assert status == 303 and location == "/auth/change-password", ("forced change", status, location)
    change(cookie, original, temporary)  # a real database write by minifw-web
    cookie, location = login(temporary)
    assert location == "/admin/", location
    results = {"forced_password_change": "enforced, then completed (database write as minifw-web)", "login": "303 to /admin/"}
    try:
        results.update(dashboard_checks(call, cookie, run))
    finally:
        change(cookie, temporary, original)  # leave the documented installer password in place
    results["admin_password"] = "restored to the installer value; must_change_password now false"
    return results


def dashboard_checks(call, cookie, run):
    results = {}
    for path in ["/admin/", "/admin/api/events", "/admin/policy", "/admin/license"]:
        status, _, _, location = call("GET", path, cookie=cookie)
        assert status == 200, (path, status, location)
        results["GET " + path] = status
    status, _, body, _ = call("GET", "/admin/api/kernel-proof", cookie=cookie)
    proof = json.loads(body)
    assert status == 200 and proof["active"] is True, proof
    results["kernel_proof"] = proof["label"]
    feed = Path("/opt/minifw_ai/config/feeds/deny_domains.txt")
    domain = "dashboard-smoke.lab.test"
    assert call("POST", "/admin/deny-domain", {"domain": domain}, cookie)[0] == 200 and domain in feed.read_text()
    assert call("DELETE", "/admin/deny-domain", {"domain": domain}, cookie)[0] == 200 and domain not in feed.read_text()
    results["feed_add_delete"] = "deny_domains.txt written by minifw-web"
    # Compare the packaged units (the lab drop-in points the engine at a fixture policy).
    policies = {unit: next(line for line in Path(f"/etc/systemd/system/{unit}.service").read_text().splitlines()
                           if line.startswith("Environment=MINIFW_POLICY=")) for unit in ("minifw-ai", "minifw-ai-web")}
    assert len(set(policies.values())) == 1 and "/config/modes/" in policies["minifw-ai"], policies
    policy = Path(policies["minifw-ai"].split("=", 2)[2])
    original = policy.read_bytes()
    burst = json.loads(original).get("burst", {})
    values = {"dns_queries_per_minute_monitor": burst.get("dns_queries_per_minute_monitor", 30),
              "dns_queries_per_minute_block": burst.get("dns_queries_per_minute_block", 60)}
    try:
        status, _, _, _ = call("POST", "/admin/policy/burst", values, cookie)
        assert status == 200, ("policy save", status)
        assert json.loads(policy.read_text())["burst"]["dns_queries_per_minute_block"] == values["dns_queries_per_minute_block"]
    finally:
        policy.write_bytes(original)
    results["policy_save"] = f"{policy} (same file as engine MINIFW_POLICY); original bytes restored"
    return results


def guard_checks(root, run, start, record, nft, ns, member):
    python = "/opt/minifw_ai/venv/bin/python"
    start()
    try:
        # Lab DoH fixture lives at 198.18.0.2:443; the shipped public list must also parse and apply.
        doh_list = root / "doh-resolvers-lab.txt"
        doh_list.write_text(Path("/opt/minifw_ai/config/feeds/doh_resolvers.txt").read_text() + "198.18.0.2\n")
        run("env", "PYTHONPATH=/opt/minifw_ai/app", python, "-m", "minifw_ai.egress_guard", "--interface", "mfcg", "--block-ipv6",
            "--doh-list", str(doh_list))
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
        ns("http", "198.18.0.2", "443", "/dns-query", "denied.lab.test", allowed=False)
        ns("http", "198.18.0.2", "8080", "/")
        record("guarded_bypass_scope", DoT="blocked", IPv6="blocked by explicit full IPv6 forwarding denial",
               DoH="blocked to listed resolver address on 443; unlisted/self-hosted DoH not identified",
               direct_IP="allowed (non-443 port to the same address still allowed)", UDP_853="configured; no DoQ protocol acceptance",
               limitation="No generic HTTPS DoH identification, IPv6 inspection or all-tunnel claim")
        rules = run("nft", "-a", "list", "table", "inet", "minifw_egress").stdout
        (root / "egress-guard.nft").write_text(rules)
    finally:
        run("env", "PYTHONPATH=/opt/minifw_ai/app", python, "-m", "minifw_ai.egress_guard", "--remove", check=False)
    ns("http", "fd42:18::2", "8080", "/")
    ns("dot", "198.18.0.2", "approved.test")
    ns("http", "198.18.0.2", "443", "/dns-query", "approved.test")
    record("guard_removal_recovery", IPv6="allowed", DoT="allowed", DoH="allowed")


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
                    if provider == "youtube" and "DNS restrictions are on" in text and "Strict restricted for" in text:
                        result["status"] = "strict_DNS_status_observed"
                    if provider == "google" and "Pemfilteran aktif" in text and "Anda tidak dapat mengubah" in text:
                        result["status"] = "filtering_locked_observed"
                    if provider == "bing" and "requires a strict Bing SafeSearch setting" in text:
                        result.update(status="strict_regional_status_observed", attribution="Regional policy confounds DNS-only attribution")
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
        for phase in ["pinned", "unconfigured_control"]:
            if phase == "unconfigured_control":
                resolver.terminate()
                resolver.wait(timeout=5)
                control = root / "public-control.conf"
                control.write_text("")
                resolver = subprocess.Popen(["dnsmasq", "--keep-in-foreground", "--user=root", "--conf-file=" + str(control),
                    "--no-resolv", "--no-hosts", "--bind-interfaces", "--listen-address=10.10.0.53", "--server=10.231.0.3",
                    "--log-queries", "--log-facility=-"], stdout=log, stderr=log)
                children.append(resolver)
                time.sleep(.5)
                assert resolver.poll() is None
            output = root / ("browser-" + phase)
            output.mkdir()
            run("chown", "lab:lab", str(output))
            for domain in ["www.google.com", "www.bing.com", "www.youtube.com"]:
                run("ip", "netns", "exec", "mf-client", "dig", "@10.10.0.53", domain, "A", "+noall", "+answer")
            result = run("ip", "netns", "exec", "mf-client", "runuser", "-u", "lab", "--",
                         "/opt/minifw_ai/venv/bin/python", __file__, "providers", str(output), timeout=110)
            record("provider_browser_" + phase, results=json.loads(result.stdout.splitlines()[-1]),
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
