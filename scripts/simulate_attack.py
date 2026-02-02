#!/usr/bin/env python3
"""
MiniFW-AI Attack Simulation Script (Real-Time Mode)

This generates simulated network security events to test the dashboard.
It creates realistic attack scenarios and writes them 1-by-1 to allow 
real-time visualization.

Usage:
    # Run standard real-time simulation (1 event per second)
    python3 scripts/simulate_attack.py --output /opt/minifw_ai/logs/events.jsonl --events 50
    
    # Run fast burst simulation (0.1s delay)
    python3 scripts/simulate_attack.py --events 100 --delay 0.1
    
    # Overwrite existing logs and start fresh
    python3 scripts/simulate_attack.py --events 50 --overwrite
"""

import json
import random
import time
import argparse
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ============================================================================
# ATTACK SCENARIOS CONFIGURATION
# ============================================================================

MALICIOUS_DOMAINS = {
    "malware": [
        "malware-payload.evil.ru", "dropper.badactor.cn", "c2-server.darkweb.onion",
        "ransomware-key.cryptolocked.net", "botnet-cmd.zombienet.xyz",
        "trojan-loader.infected.biz", "keylogger-upload.steal.io",
        "backdoor.rootkit.space", "exploit-kit.hackzone.to",
        "fileless-malware.memonly.cc",
    ],
    "crypto_mining": [
        "coinhive.com", "minero.cc", "crypto-loot.pro", "coin-hive.com",
        "miner.eth-pool.xyz", "xmr-pool.cryptojack.io", "monero-miner.web3hack.net",
        "browser-mine.js.ninja", "pooled-mining.darknet.ru",
        "stealth-miner.shadow.cc",
    ],
    "phishing": [
        "g00gle-secure.login.ml", "facebook-verify.account.tk",
        "paypa1-security.update.cf", "microsoft-365.reset.ga",
        "apple-id.verify.gq", "instagram-login.secure.ml",
        "netflix-payment.update.tk", "amazon-order.confirm.cf",
        "twitter-suspended.verify.ga", "bank-security.update.gq",
    ],
    "exfiltration": [
        "upload.data-exfil.cc", "files.stolen-docs.ru", "dump.creditcard-db.cn",
        "leak.customer-data.xyz", "exfil.corporate-secrets.io",
        "transfer.sensitive-files.biz", "extract.passwords-db.net",
        "sync.private-keys.onion", "backup.stolen-creds.space",
        "archive.internal-docs.cc",
    ],
    "dns_tunneling": [
        "dGhpcyBpcyBhIHRlc3Q.tunnel.covert-channel.io",
        "c2VjcmV0LWRhdGE.dns.hidden-transfer.cc",
        "ZXhmaWwtcGF5bG9hZA.out.stealth-dns.net",
        "Y29tbWFuZC1hbmQtY29udHJvbA.c2.dark-channel.xyz",
        "aGlkZGVuLXRyYWZmaWM.vpn.tunnel-master.biz",
    ],
    "gambling": [
        "www.casino-royale-online.com", "play.slot-machines24.net",
        "bet.judionline-terbaik.xyz", "win.poker-stars-clone.cc",
        "jackpot.casino-mega-wins.io", "slots.golden-casino.biz",
        "roulette.vegas-online.tk", "blackjack.card-games24.ml",
    ],
    "command_control": [
        "beacon.apt29-infra.ru", "callback.lazarus-group.kp",
        "update.cozy-bear-ops.cn", "sync.fancy-bear-c2.net",
        "heartbeat.turla-implant.xyz", "checkin.apt41-server.io",
        "task.wizard-spider.cc", "response.sandworm-team.biz",
    ],
}

ATTACK_REASONS = {
    "malware": ["dns_denied_domain", "asn_denied"],
    "crypto_mining": ["dns_denied_domain", "burst_behavior"],
    "phishing": ["dns_denied_domain", "tls_sni_denied_domain"],
    "exfiltration": ["dns_denied_domain", "burst_behavior", "asn_denied"],
    "dns_tunneling": ["dns_denied_domain", "burst_behavior"],
    "gambling": ["dns_denied_domain"],
    "command_control": ["dns_denied_domain", "asn_denied", "tls_sni_denied_domain"],
}

SEGMENT_CONFIG = {
    "student": {"block_min": 40, "monitor_min": 20, "subnet_prefix": "10.10"},
    "staff": {"block_min": 80, "monitor_min": 60, "subnet_prefix": "10.20"},
    "admin": {"block_min": 90, "monitor_min": 70, "subnet_prefix": "10.30"},
    "default": {"block_min": 60, "monitor_min": 40, "subnet_prefix": "192.168"},
}


def generate_ip(segment: str) -> str:
    config = SEGMENT_CONFIG.get(segment, SEGMENT_CONFIG["default"])
    prefix = config["subnet_prefix"]
    
    if prefix == "10.10":
        return f"10.10.{random.randint(1, 254)}.{random.randint(1, 254)}"
    elif prefix == "10.20":
        return f"10.20.{random.randint(1, 254)}.{random.randint(1, 254)}"
    elif prefix == "10.30":
        return f"10.30.{random.randint(1, 254)}.{random.randint(1, 254)}"
    else:
        return f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"


def generate_timestamp(base_time: datetime = None, offset_seconds: int = 0) -> str:
    """Generate ISO formatted timestamp."""
    if base_time is None:
        base_time = datetime.now(timezone.utc)
    ts = base_time + timedelta(seconds=offset_seconds)
    return ts.isoformat()


def generate_attack_event(attack_type: str, segment: str = None, action: str = None) -> dict:
    """Generate a single attack event."""
    if segment is None:
        segment = random.choice(list(SEGMENT_CONFIG.keys()))
    
    config = SEGMENT_CONFIG[segment]
    client_ip = generate_ip(segment)
    
    domains = MALICIOUS_DOMAINS.get(attack_type, MALICIOUS_DOMAINS["malware"])
    domain = random.choice(domains)
    
    if action is None:
        action = random.choices(["block", "monitor", "allow"], weights=[0.6, 0.3, 0.1])[0]
    
    if action == "block":
        score = random.randint(config["block_min"], 100)
        reasons = ATTACK_REASONS.get(attack_type, ["dns_denied_domain"])
    elif action == "monitor":
        score = random.randint(config["monitor_min"], config["block_min"] - 1)
        reasons = ATTACK_REASONS.get(attack_type, ["dns_denied_domain"])[:1]
    else:
        score = random.randint(0, config["monitor_min"] - 1)
        reasons = []
    
    return {
        "ts": datetime.now(timezone.utc).isoformat(), # Always use CURRENT time for streaming
        "segment": segment,
        "client_ip": client_ip,
        "domain": domain,
        "action": action,
        "score": score,
        "reasons": reasons,
    }

def generate_burst_attack(client_ip: str, segment: str, num_requests: int = 50) -> list:
    events = []
    config = SEGMENT_CONFIG[segment]
    
    for i in range(num_requests):
        action = "monitor" if i < 5 else "block"
        score_range = (config["monitor_min"], config["block_min"] - 1) if i < 5 else (config["block_min"], 100)
        
        events.append({
            "ts": None, # Will be filled during send
            "segment": segment,
            "client_ip": client_ip,
            "domain": random.choice(MALICIOUS_DOMAINS["dns_tunneling"]),
            "action": action,
            "score": random.randint(*score_range),
            "reasons": ["burst_behavior"] if i < 5 else ["dns_denied_domain", "burst_behavior"],
        })
    return events

def run_simulation(
    output_path: str,
    num_events: int = 100,
    attack_mix: dict = None,
    include_scenarios: bool = True,
    append: bool = True,
    delay: float = 1.0 
):
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    if attack_mix is None:
        attack_mix = {
            "malware": 0.20, "crypto_mining": 0.10, "phishing": 0.20,
            "exfiltration": 0.10, "dns_tunneling": 0.10, "gambling": 0.15,
            "command_control": 0.15,
        }
    
    print(f"🔥 MiniFW-AI Real-Time Attack Simulator")
    print(f"=" * 50)
    print(f"📁 Output: {output_path}")
    print(f"📊 Events: {num_events}")
    print(f"⏱️  Delay: {delay}s per event")
    print(f"📌 Scenarios: {include_scenarios}")
    print(f"=" * 50)
    print("Hit Ctrl+C to stop simulation early.\n")

    attack_types = list(attack_mix.keys())
    weights = list(attack_mix.values())
    
    mode = "a" if append else "w"
    
    try:
        with open(output_file, mode) as f:
            # 1. Random Events Loop
            for i in range(num_events):
                attack_type = random.choices(attack_types, weights=weights)[0]
                event = generate_attack_event(attack_type=attack_type)
                
                # Write and Flush immediately
                f.write(json.dumps(event) + "\n")
                f.flush()
                
                # Visual Feedback
                print(f"[{i+1}/{num_events}] {event['ts']} | {event['action'].upper()} | {event['segment']} | {event['domain']}")
                
                if delay > 0:
                    time.sleep(delay)

            # 2. Scenarios (Bursts)
            if include_scenarios:
                print("\n🎭 Triggering Attack Scenarios (Burst Traffic)...\n")
                
                # Burst Scenario
                burst_ip = generate_ip("student")
                burst_events = generate_burst_attack(burst_ip, "student", num_requests=20)
                
                for idx, event in enumerate(burst_events):
                    event['ts'] = datetime.now(timezone.utc).isoformat()
                    f.write(json.dumps(event) + "\n")
                    f.flush()
                    print(f"[BURST {idx+1}/{len(burst_events)}] {event['ts']} | {event['action'].upper()} | {event['client_ip']} -> {event['domain']}")
                    # Bursts happen faster than normal traffic
                    time.sleep(0.1) 

    except KeyboardInterrupt:
        print("\n\n🛑 Simulation stopped by user.")
    
    print(f"\n✅ Simulation complete. Logs written to {output_path}")

def main():
    parser = argparse.ArgumentParser(description="MiniFW-AI Attack Simulation Script")
    
    parser.add_argument("-o", "--output", default="logs/events.jsonl", help="Path to events.jsonl")
    parser.add_argument("-n", "--events", type=int, default=100, help="Number of random events")
    parser.add_argument("--scenarios", action="store_true", help="Include burst attacks")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing file")
    # Default delay set to 1.0s for visibility
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between events (default: 1.0s)")
    
    args = parser.parse_args()
    
    run_simulation(
        output_path=args.output,
        num_events=args.events,
        include_scenarios=args.scenarios,
        append=not args.overwrite,
        delay=args.delay
    )

if __name__ == "__main__":
    main()