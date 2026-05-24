import json
import os
import random
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

_thread: threading.Thread | None = None
_stop_event = threading.Event()

_DOMAINS: dict[str, dict[str, list[str]]] = {
    "hospital": {
        "malicious": [
            "ransomware-key.cryptolocked.net", "c2-server.darkweb.onion",
            "iomt-exfil.steal.io", "backdoor.rootkit.space",
            "patient-records.exfil.cc", "beacon.apt29.ru",
            "meditec-spoof.update.ml", "keylogger-upload.steal.io",
        ],
        "benign": [
            "epic.systems.com", "cerner.com", "microsoft.com",
            "office365.com", "teams.microsoft.com", "github.com",
        ],
    },
    "financial": {
        "malicious": [
            "banking-api.fake.ml", "swift-bypass.cc", "pci-exfil.ru",
            "card-dump.darkweb.onion", "pivot.lateral.move.cn",
            "c2.lazarus.kr", "coinhive.com", "xmr-pool.cryptojack.io",
        ],
        "benign": [
            "bloomberg.com", "reuters.com", "swift.com",
            "microsoft.com", "office365.com", "slack.com",
        ],
    },
    "establishment": {
        "malicious": [
            "pos-skimmer.darknet.ru", "supply-chain.inject.cc",
            "fake-update.retailsys.ml", "pivot.internal.move.cn",
            "data.stolen-retail.io", "botnet-cmd.zombienet.xyz",
        ],
        "benign": [
            "shopify.com", "stripe.com", "google.com",
            "microsoft.com", "slack.com", "github.com",
        ],
    },
    "gambling": {
        "malicious": [
            "payment-bypass.casino.ru", "money-laundering.node.cc",
            "bonus-abuse.fraud.io", "kyc-bypass.darkweb.onion",
            "chip-dump.fake.ml", "pivot.gambling-c2.cn",
        ],
        "benign": [
            "gamesys.co.uk", "playtech.com", "microsoft.com",
            "office365.com", "slack.com", "cloudflare.com",
        ],
    },
    "education": {
        "malicious": [
            "nordvpn-bypass.proxy.io", "vpn-tunnel-free.cc",
            "safesearch-bypass.proxy.ru", "filter-bypass.student.io",
            "bet365-unblock.casino.ml", "tiktok-proxy.bypass.cc",
            "adult-content.proxy.xyz", "unblock-sites.school.ru",
        ],
        "benign": [
            "khanacademy.org", "bbc.co.uk", "wikipedia.org",
            "microsoft.com", "office365.com", "teams.microsoft.com",
        ],
    },
    "legal": {
        "malicious": [
            "clio-encrypt.c2-server.ru", "opposing-counsel.harvest.io",
            "case-data.darkweb.onion", "wetransfer-legal.io",
            "privilege-breach.leak.cc", "client-data.dump.io",
            "lexisnexis-ransom.cc", "tor-exit-relay.onion-gw.net",
        ],
        "benign": [
            "westlaw.com", "lexisnexis.com", "courts.gov",
            "microsoft.com", "office365.com", "teams.microsoft.com",
            "practicepanther.com", "clio.com",
        ],
    },
}

_REASONS: dict[str, list[list[str]]] = {
    "hospital": [
        ["dns_denied_domain", "hard_threat_gate"],
        ["mlp_threat_score", "iomt_device_alert"],
        ["yara_match", "hard_threat_gate"],
        ["dns_tunnel", "burst_behavior"],
        ["tls_sni_denied_domain", "asn_denied"],
    ],
    "financial": [
        ["dns_denied_domain", "hard_threat_gate"],
        ["mlp_threat_score", "asn_denied"],
        ["yara_match", "hard_threat_gate"],
        ["tls_sni_denied_domain", "asn_denied"],
        ["ip_blocked", "hard_threat_gate"],
    ],
    "establishment": [
        ["dns_denied_domain", "hard_threat_gate"],
        ["mlp_threat_score", "burst_behavior"],
        ["yara_match", "hard_threat_gate"],
        ["ip_blocked", "asn_denied"],
        ["dns_tunnel", "burst_behavior"],
    ],
    "gambling": [
        ["dns_denied_domain", "hard_threat_gate"],
        ["mlp_threat_score", "asn_denied"],
        ["tls_sni_denied_domain", "hard_threat_gate"],
        ["ip_blocked", "asn_denied"],
        ["yara_match", "burst_behavior"],
    ],
    "education": [
        ["dns_denied_domain", "hard_threat_gate"],
        ["mlp_threat_score", "burst_behavior"],
        ["yara_match", "hard_threat_gate"],
        ["tls_sni_denied_domain", "asn_denied"],
        ["dns_tunnel", "burst_behavior"],
    ],
    "legal": [
        ["dns_denied_domain", "hard_threat_gate"],
        ["yara_match", "hard_threat_gate"],
        ["mlp_threat_score", "asn_denied"],
        ["tls_sni_denied_domain", "hard_threat_gate"],
        ["dns_tunnel", "burst_behavior"],
    ],
}

_DEFAULT_SECTOR = "hospital"
_SEGMENTS = ["staff", "guest", "servers", "student", "iot"]

_PRODUCT_MODE_TO_SECTOR = {
    "minifw_hospital": "hospital",
    "minifw_financial": "financial",
    "minifw_establishment": "establishment",
    "minifw_gambling": "gambling",
    "minifw_school": "education",
    "minifw_legal": "legal",
}

_PHASES = [
    (30, "BASELINE",   "normal"),
    (30, "ANOMALY",    "anomaly"),
    (20, "ESCALATION", "escalation"),
    (15, "ALERT",      "alert"),
    (25, "BLOCK",      "block"),
]


def _active_sector() -> str:
    pm = os.environ.get("PRODUCT_MODE", "").strip().lower()
    if pm in _PRODUCT_MODE_TO_SECTOR:
        return _PRODUCT_MODE_TO_SECTOR[pm]
    sector = os.environ.get("MINIFW_SECTOR", "").strip().lower()
    if sector in _DOMAINS:
        return sector
    return _DEFAULT_SECTOR


def _resolve_decision_owner(reasons: list[str]) -> str:
    if "hard_threat_gate" in reasons:
        return "Hard Gate"
    if "mlp_threat_score" in reasons:
        return "AI Engine (MLP)"
    if "yara_match" in reasons:
        return "YARA Scanner"
    return "Policy Engine"


def _rand_ip() -> str:
    return f"10.{random.randint(0, 5)}.{random.randint(1, 30)}.{random.randint(2, 254)}"


def _make_event(action: str, domain: str | None = None, score: int | None = None) -> dict:
    sector = _active_sector()
    domains = _DOMAINS.get(sector, _DOMAINS[_DEFAULT_SECTOR])
    reasons_table = _REASONS.get(sector, _REASONS[_DEFAULT_SECTOR])

    is_block = action in ("block", "deny")
    is_monitor = action == "monitor"

    chosen_domain = domain or (
        random.choice(domains["malicious"]) if (is_block or is_monitor)
        else random.choice(domains["benign"])
    )
    chosen_reasons = random.choice(reasons_table) if (is_block or is_monitor) else []

    if score is None:
        if is_block:
            score = random.randint(85, 100)
        elif is_monitor:
            score = random.randint(65, 84)
        else:
            score = random.randint(0, 25)

    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "segment": random.choice(_SEGMENTS),
        "client_ip": _rand_ip(),
        "domain": chosen_domain,
        "action": action,
        "score": score,
        "reasons": chosen_reasons,
        "sector": sector,
        "severity": "critical" if is_block else ("warning" if is_monitor else "info"),
        "trace_id": uuid.uuid4().hex[:8].upper(),
        "decision_owner": _resolve_decision_owner(chosen_reasons),
    }


def _write_events(events: list[dict], path: Path) -> None:
    with open(path, "a") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")


def _simulator_loop(events_path: Path) -> None:
    while not _stop_event.is_set():
        for duration, _phase_name, phase_key in _PHASES:
            phase_end = time.monotonic() + duration
            burst_ip = _rand_ip()
            burst_domain: str | None = None

            while time.monotonic() < phase_end and not _stop_event.is_set():
                events: list[dict] = []

                if phase_key == "normal":
                    events = [_make_event("allow") for _ in range(random.randint(1, 3))]
                    sleep = 3.0

                elif phase_key == "anomaly":
                    events = [_make_event("allow") for _ in range(random.randint(1, 2))]
                    events.append(_make_event("monitor", score=random.randint(40, 60)))
                    sleep = 5.0

                elif phase_key == "escalation":
                    events = [_make_event("allow")]
                    for _ in range(random.randint(2, 3)):
                        events.append(_make_event("monitor", score=random.randint(65, 80)))
                    sleep = 4.0

                elif phase_key == "alert":
                    events = [
                        _make_event("monitor", score=random.randint(75, 85))
                        for _ in range(random.randint(3, 5))
                    ]
                    sleep = 2.5

                else:  # block
                    sector = _active_sector()
                    domains = _DOMAINS.get(sector, _DOMAINS[_DEFAULT_SECTOR])
                    if burst_domain is None:
                        burst_domain = random.choice(domains["malicious"])
                    count = random.randint(10, 20)
                    for _ in range(count):
                        if random.random() < 0.8:
                            ev = _make_event("block", domain=burst_domain)
                            ev["client_ip"] = burst_ip
                        else:
                            ev = _make_event("block")
                        events.append(ev)
                    sleep = 2.0

                _write_events(events, events_path)
                if _stop_event.wait(sleep):
                    return


def start(events_path: str = "logs/events.jsonl") -> None:
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop_event.clear()
    path = Path(events_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _thread = threading.Thread(
        target=_simulator_loop, args=(path,), daemon=True, name="demo-attack-sim"
    )
    _thread.start()


def stop() -> None:
    _stop_event.set()
    if _thread:
        _thread.join(timeout=5)
