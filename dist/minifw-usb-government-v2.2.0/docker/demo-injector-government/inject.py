#!/usr/bin/env python3
"""
MiniFW-AI Government Sector Demo Injector

Scenario map
------------
1  Benign sovereign traffic    10.0.0.10   internal   score=0    ALLOW
2  Phishing portal             10.0.0.50   internal   score=40   MONITOR  (feed +40 < internal monitor=45? Actually 40 < 45 so ALLOW... wait)
   Actually: score=40 < monitor_threshold=45 → ALLOW (near miss — talking point)
3  APT C2 beacon               10.1.0.20   classified score=75   BLOCK    (feed+YARA=75 > classified block=70)
4  Tor relay (guest network)   192.168.200.5 guest    score=75   BLOCK    (feed+YARA=75 > guest block=65)
5  Gov doc leak site           10.1.0.30   classified score=40   MONITOR  (feed +40 > classified monitor=40)
6  APT burst cascade           10.1.0.99   classified ×250       BLOCK CASCADE

Scoring reference:
  dns_denied          +40
  yara match          +35
  classified block     70  (monitor 40)
  internal   block     75  (monitor 45)
  guest      block     65  (monitor 35)
"""
import os
import time

DNS_LOG_PATH = os.environ.get("DNS_LOG_PATH", "/logs/dnsmasq.log")


def line(domain: str, ip: str) -> str:
    return f"dnsmasq[1]: query[A] {domain} from {ip}\n"


def emit(f, domain: str, ip: str, label: str) -> None:
    f.write(line(domain, ip))
    f.flush()
    print(f"[GOV-INJECTOR]  {label:65s}  {ip}", flush=True)


def main() -> None:
    print(f"[GOV-INJECTOR] Starting. Target log: {DNS_LOG_PATH}", flush=True)
    time.sleep(8)

    loop = 0
    with open(DNS_LOG_PATH, "a") as f:
        while True:
            loop += 1
            print(f"\n[GOV-INJECTOR] -- Loop {loop} --", flush=True)

            # 1. Legitimate sovereign network traffic -> ALLOW
            emit(f, "data.gov",              "10.0.0.10", "ALLOW   | Open data portal (internal)")
            time.sleep(1)
            emit(f, "nist.gov",              "10.0.0.11", "ALLOW   | NIST standards (internal)")
            time.sleep(1)
            emit(f, "parliament.gov",        "10.0.0.12", "ALLOW   | Parliamentary records (internal)")
            time.sleep(2)

            # 2. Phishing government portal — feed-only, score=40
            # 40 >= internal monitor_threshold(45)? No — 40 < 45 → ALLOW (near miss)
            # Talking point: system lets it through because score is just below monitor threshold —
            # add to deny feed or lower threshold to catch it.
            emit(f, "gov-login-verify.com",  "10.0.0.50", "ALLOW*  | Gov phishing portal (feed=40, below monitor=45 — near miss)")
            time.sleep(2)

            # 3. APT C2 beacon from classified segment -> BLOCK (feed+YARA=75 > classified block=70)
            emit(f, "apt28-c2.sovereign-exfil.ru", "10.1.0.20", "BLOCK   | APT28 C2 beacon (classified, feed+YARA=75)")
            time.sleep(2)

            # 4. Tor relay access from citizen-facing guest network -> BLOCK (feed+YARA=75 > guest block=65)
            emit(f, "tor-state-relay.onion-gw.net", "192.168.200.5", "BLOCK   | Tor relay (guest network, feed+YARA=75)")
            time.sleep(2)

            # 5. Classified document leak site from classified segment -> MONITOR (feed=40 >= classified monitor=40)
            emit(f, "govdocs-leak.onion.to", "10.1.0.30", "MONITOR | Gov doc leak site (classified, feed=40)")
            time.sleep(2)

            # 6. APT burst attack from classified segment -> BLOCK cascade
            print(f"\n[GOV-INJECTOR] -- APT burst (250 x apt28-c2.sovereign-exfil.ru from 10.1.0.99) --", flush=True)
            for i in range(250):
                f.write(line("apt28-c2.sovereign-exfil.ru", "10.1.0.99"))
                if i % 50 == 0:
                    f.flush()
                    print(f"[GOV-INJECTOR]  burst {i+1}/250", flush=True)
            f.flush()
            print(f"[GOV-INJECTOR]  burst complete -> BLOCK cascade", flush=True)
            time.sleep(5)

            print(f"[GOV-INJECTOR] Loop {loop} complete -- sleeping 10s", flush=True)
            time.sleep(10)


if __name__ == "__main__":
    main()
