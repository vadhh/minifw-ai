import json
import random
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

_thread: threading.Thread | None = None
_stop_event = threading.Event()

MALICIOUS_DOMAINS = [
    "malware-payload.evil.ru", "c2-server.darkweb.onion", "ransomware-key.cryptolocked.net",
    "botnet-cmd.zombienet.xyz", "keylogger-upload.steal.io", "backdoor.rootkit.space",
    "coinhive.com", "xmr-pool.cryptojack.io", "monero-miner.web3hack.net",
    "g00gle-secure.login.ml", "paypa1-security.update.cf", "microsoft-365.reset.ga",
    "upload.data-exfil.cc", "files.stolen-docs.ru", "exfil.megaupload.xyz",
    "dns-tunnel.exfil.cc", "data.encode.base64.io", "cmd.shell.reverse.tk",
    "beacon.apt29.ru", "c2.lazarus.kr", "pivot.lateral.move.cn",
]
BENIGN_DOMAINS = [
    "google.com", "microsoft.com", "github.com", "stackoverflow.com",
    "youtube.com", "office365.com", "teams.microsoft.com", "slack.com",
]
ATTACK_REASONS = [
    ["dns_denied_domain", "hard_threat_gate"],
    ["mlp_threat_score", "asn_denied"],
    ["yara_match", "hard_threat_gate"],
    ["dns_tunnel", "burst_behavior"],
    ["tls_sni_denied_domain", "asn_denied"],
    ["ip_blocked", "hard_threat_gate"],
]
SEGMENTS = ["staff", "guest", "servers", "student", "iot"]


def _rand_ip():
    return f"10.{random.randint(0,5)}.{random.randint(1,30)}.{random.randint(2,254)}"


def _make_event(action: str, domain: str | None = None) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    is_block = action in ("block", "deny")
    return {
        "ts": now,
        "segment": random.choice(SEGMENTS),
        "client_ip": _rand_ip(),
        "domain": domain or (random.choice(MALICIOUS_DOMAINS) if is_block else random.choice(BENIGN_DOMAINS)),
        "action": action,
        "score": random.randint(85, 100) if is_block else random.randint(0, 25),
        "reasons": random.choice(ATTACK_REASONS) if is_block else [],
        "sector": "hospital",
        "severity": "critical" if is_block else "info",
    }


def _write_events(events: list[dict], path: Path):
    with open(path, "a") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")


def _simulator_loop(events_path: Path):
    """
    Continuous wave pattern:
      calm  (4-6 s): 1-3 benign + 0-1 block events
      spike (2-4 s): 15-35 block events — dramatic for demos
    """
    while not _stop_event.is_set():
        # — calm phase —
        calm_events = [_make_event("allow") for _ in range(random.randint(1, 3))]
        if random.random() < 0.3:
            calm_events.append(_make_event("block"))
        _write_events(calm_events, events_path)
        if _stop_event.wait(random.uniform(4, 6)):
            break

        # — spike phase —
        spike_count = random.randint(15, 35)
        spike_events = []
        burst_ip = _rand_ip()  # single attacker for dramatic feed
        burst_domain = random.choice(MALICIOUS_DOMAINS)
        for i in range(spike_count):
            # mix: 80% same attacker (visible burst), 20% other IPs
            if random.random() < 0.8:
                ev = _make_event("block", burst_domain)
                ev["client_ip"] = burst_ip
            else:
                ev = _make_event("block")
            spike_events.append(ev)
        _write_events(spike_events, events_path)
        if _stop_event.wait(random.uniform(2, 4)):
            break


def start(events_path: str = "logs/events.jsonl"):
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop_event.clear()
    path = Path(events_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _thread = threading.Thread(target=_simulator_loop, args=(path,), daemon=True, name="demo-attack-sim")
    _thread.start()


def stop():
    _stop_event.set()
    if _thread:
        _thread.join(timeout=5)
