"""
MiniFW-AI Gambling mode demo injector.

Replays 5 threat scenarios in a continuous loop by appending dnsmasq-format
log lines to the shared volume.  The engine tails the same file.

GAMBLING_ONLY=1 → only queries matching gambling_domains.txt are scored;
all other deny-feed hits are suppressed in this regulatory mode.

Scenario map
------------
1  Benign (work traffic)        192.168.1.10   office   score=0     ALLOW
2  Employee — sports-betting    192.168.1.50   office   score=40    MONITOR
   gambling_domains hit → dns_denied(40) < office block(80)
3  Employee — online casino     192.168.1.75   office   score=40    MONITOR
   pokerstars.com — same score, second employee caught
4  Guest — betting site burst   172.16.1.99    guest    score=40+   BLOCK
   bet365 lookup → dns_denied(40) ≥ guest block(40) → nft block
5  Guest — generic *.casino     172.16.2.10    guest    score=40    BLOCK
   *.casino pattern match → immediate BLOCK on guest subnet

Scoring reference (establishment sector, GAMBLING_ONLY=1):
  dns_denied (gambling feed)  +40
  burst_behavior               +10
  office block_threshold        80  (monitor 45)
  guest  block_threshold        40  (monitor 20)
"""

import os
import time

DNS_LOG_PATH = os.environ.get("DNS_LOG_PATH", "/logs/dnsmasq.log")


def line(domain: str, ip: str) -> str:
    return f"dnsmasq[1]: query[A] {domain} from {ip}\n"


def main() -> None:
    print(f"[GAMBLING-INJECTOR] Writing to {DNS_LOG_PATH}", flush=True)
    # Wait for engine to open the log file during startup
    time.sleep(8)

    loop = 0
    with open(DNS_LOG_PATH, "a") as f:
        while True:
            loop += 1
            print(f"[GAMBLING-INJECTOR] Loop {loop}", flush=True)

            # ------------------------------------------------------------------
            # Scenario 1 — Benign work traffic (ALLOW, score=0)
            # Normal SaaS / productivity domain — not in gambling feed.
            # GAMBLING_ONLY=1 means non-gambling deny hits are ignored here.
            # ------------------------------------------------------------------
            f.write(line("office365.com", "192.168.1.10"))
            f.flush()
            time.sleep(1)

            # ------------------------------------------------------------------
            # Scenario 2 — Employee accessing sports-betting site (MONITOR, score=40)
            # williamhill.com matches gambling_domains.txt → dns_denied(40).
            # 192.168.1.50 is in office subnet; office block_threshold=80.
            # 40 < 80 → MONITOR (policy: warn, don't fire the employee yet).
            # Sales point: enforcement can be escalated to BLOCK via policy.json.
            # ------------------------------------------------------------------
            f.write(line("williamhill.com", "192.168.1.50"))
            f.flush()
            time.sleep(1)

            # ------------------------------------------------------------------
            # Scenario 3 — Second employee, online casino (MONITOR, score=40)
            # pokerstars.com in gambling_domains.txt → dns_denied(40).
            # 192.168.1.75 is office subnet → same threshold → MONITOR.
            # Two separate employees caught in same loop — shows per-IP tracking.
            # ------------------------------------------------------------------
            f.write(line("pokerstars.com", "192.168.1.75"))
            f.flush()
            time.sleep(1)

            # ------------------------------------------------------------------
            # Scenario 4 — Guest network burst on betting site (BLOCK, ×250)
            # bet365.com matches gambling_domains.txt.
            # 172.16.1.99 is in the guest subnet (172.16.1.0/24).
            # Guest block_threshold=40; dns_denied(40) >= 40 → BLOCK immediately.
            # Burst continues → burst_behavior(+10) → score climbs to 50.
            # Engine: nft add element inet minifw minifw_block_v4 {172.16.1.99}
            # ------------------------------------------------------------------
            print("[GAMBLING-INJECTOR] Burst scenario (guest, bet365)...", flush=True)
            for _ in range(250):
                f.write(line("bet365.com", "172.16.1.99"))
                f.flush()
                time.sleep(0.05)

            # ------------------------------------------------------------------
            # Scenario 5 — Wildcard pattern match on guest (BLOCK, score=40)
            # lucky777.casino — matches *.casino glob pattern in gambling_domains.txt.
            # 172.16.2.10 is guest subnet → BLOCK on first query.
            # Shows pattern-based enforcement (not just exact-domain list).
            # ------------------------------------------------------------------
            f.write(line("lucky777.casino", "172.16.2.10"))
            f.flush()
            time.sleep(1)

            print(f"[GAMBLING-INJECTOR] Loop {loop} done. Sleeping 15s.", flush=True)
            time.sleep(15)


if __name__ == "__main__":
    main()
