"""
MiniFW-AI SME/Establishment sector demo injector.

Replays 6 threat scenarios in a continuous loop by appending dnsmasq-format
log lines to the shared volume.  The engine tails the same file.

Scenario map
------------
1  Benign traffic          192.168.1.10   office   score=0    ALLOW
2  Phishing (office)       192.168.1.50   office   score=40   MONITOR
3  Ransomware C2 + YARA    192.168.1.100  office   score=75   MONITOR
4  Crypto miner C2 + YARA  192.168.1.200  office   score=75   MONITOR
5  Generic C2 beacon       10.0.0.50      office   score=40   MONITOR
6  Guest burst (×250)      172.16.1.99    guest    score=40+  BLOCK

Scoring reference (establishment sector — no threshold adjustment):
  dns_denied          +40
  yara match          +35
  burst_behavior      +10
  office block thr.    80  (monitor 45)
  guest  block thr.    40  (monitor 20)  <- dns_denied(40) >= 40 -> BLOCK
"""

import os
import time

DNS_LOG_PATH = os.environ.get("DNS_LOG_PATH", "/logs/dnsmasq.log")


def line(domain: str, ip: str) -> str:
    return f"dnsmasq[1]: query[A] {domain} from {ip}\n"


def main() -> None:
    print(f"[SME-INJECTOR] Writing to {DNS_LOG_PATH}", flush=True)
    # Wait for engine to open the log file during startup
    time.sleep(8)

    loop = 0
    with open(DNS_LOG_PATH, "a") as f:
        while True:
            loop += 1
            print(f"[SME-INJECTOR] Loop {loop}", flush=True)

            # ------------------------------------------------------------------
            # Scenario 1 — Benign (ALLOW, score=0)
            # Normal business traffic; not in any deny feed.
            # ------------------------------------------------------------------
            f.write(line("office365.com", "192.168.1.10"))
            f.flush()
            time.sleep(1)

            # ------------------------------------------------------------------
            # Scenario 2 — Phishing from employee workstation (MONITOR, score=40)
            # login-paypal-secure-verify.com is in deny_domains.txt
            # dns_denied(40) < office block_threshold(80) → MONITOR
            # Domain shown in plain text — no HIPAA redaction in SME mode.
            # ------------------------------------------------------------------
            f.write(line("login-paypal-secure-verify.com", "192.168.1.50"))
            f.flush()
            time.sleep(1)

            # ------------------------------------------------------------------
            # Scenario 3 — Ransomware C2 + YARA (MONITOR, score=75)
            # "Locky" in hostname fires SmeRansomware YARA rule (+35).
            # dns_denied(40) + yara(35) = 75 < office block(80) → MONITOR
            # Contrast with hospital: same score would be severity=critical
            # if from IoMT subnet. Here it's severity=info — standard workstation.
            # ------------------------------------------------------------------
            f.write(line("Locky.decrypt-files.net", "192.168.1.100"))
            f.flush()
            time.sleep(1)

            # ------------------------------------------------------------------
            # Scenario 4 — Cryptominer C2 + YARA (MONITOR, score=75)
            # "xmrig" triggers SmeCryptoMiner YARA rule (+35).
            # dns_denied(40) + yara(35) = 75 < office block(80) → MONITOR
            # ------------------------------------------------------------------
            f.write(line("xmrig-pool.crypto-mine.io", "192.168.1.200"))
            f.flush()
            time.sleep(1)

            # ------------------------------------------------------------------
            # Scenario 5 — Generic C2 beacon from internal server (MONITOR, score=40)
            # c2-data-collect.net in deny_domains.txt
            # 10.0.0.50 is in the office subnet (10.0.0.0/8).
            # dns_denied(40) < office block(80) → MONITOR
            # ------------------------------------------------------------------
            f.write(line("c2-data-collect.net", "10.0.0.50"))
            f.flush()
            time.sleep(1)

            # ------------------------------------------------------------------
            # Scenario 6 — Guest network burst (BLOCK, ×250)
            # ads-malware-tracker.net in deny_domains.txt.
            # 172.16.1.99 is in the guest subnet (172.16.1.0/24).
            # Guest block_threshold=40; dns_denied(40) >= 40 → BLOCK on first query.
            # Burst adds +10 → score climbs to 50.
            # Engine calls nft add element inet minifw minifw_block_v4 {172.16.1.99}
            # ------------------------------------------------------------------
            print("[SME-INJECTOR] Burst scenario (guest network)...", flush=True)
            for _ in range(250):
                f.write(line("ads-malware-tracker.net", "172.16.1.99"))
                f.flush()
                time.sleep(0.05)

            print(f"[SME-INJECTOR] Loop {loop} done. Sleeping 15s.", flush=True)
            time.sleep(15)


if __name__ == "__main__":
    main()
