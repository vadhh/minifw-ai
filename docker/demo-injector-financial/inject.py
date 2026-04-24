#!/usr/bin/env python3
"""
MiniFW-AI Financial Sector Demo Injector

Writes dnsmasq-format log lines to a shared volume so the engine processes them.
Demonstrates PCI-DSS threat detection: banking trojans, card skimmers, crypto fraud,
credential harvesting, and Tor/anonymizer blocking.

Scenario outcomes (with financial_fraud.txt + crypto_scams.txt + deny_domains.txt):
  1. swift.com / 10.50.0.1              → ALLOW   (legitimate SWIFT traffic)
  2. secure-bankofamerica-login.com / 192.168.1.100 → BLOCK score=80 (banking phishing)
  3. emotet-c2.net / 10.50.0.5         → BLOCK score=80 (banking trojan C2, trading floor)
  4. xmrig-pool.net / 192.168.1.50     → BLOCK score=80 (crypto miner C2)
  5. pay-ransom-btc.io / 10.50.0.10    → BLOCK score=80 (ransomware payment domain)
  6. login-paypal-secure-verify.com / 192.168.100.50 → BLOCK (phishing on guest network)
  7. Card skimmer burst: js-cdn-analytics.com / 10.50.0.5 → BLOCK x200 (trading floor)
"""
import os
import time

DNS_LOG_PATH = os.environ.get("DNS_LOG_PATH", "/logs/dnsmasq.log")


def make_line(domain: str, ip: str) -> str:
    return f"dnsmasq[1]: query[A] {domain} from {ip}\n"


def emit(f, domain: str, ip: str, label: str) -> None:
    f.write(make_line(domain, ip))
    f.flush()
    print(f"[FIN-INJECTOR]  {label:50s}  {ip}")


def main() -> None:
    print(f"[FIN-INJECTOR] Starting. Target log: {DNS_LOG_PATH}")
    time.sleep(8)

    loop = 0
    with open(DNS_LOG_PATH, "a") as f:
        while True:
            loop += 1
            print(f"\n[FIN-INJECTOR] ── Loop {loop} ──────────────────────────────────")

            # 1. Legitimate SWIFT inter-bank traffic → ALLOW
            emit(f, "swift.com", "10.50.0.1", "ALLOW   | SWIFT inter-bank communication")
            time.sleep(1)

            # 2. Banking phishing page from internal workstation → BLOCK
            #    secure-bankofamerica-login.com in financial_fraud.txt [PHISHING-BANK]
            #    192.168.1.100 in internal subnet (block_threshold=80)
            #    dns_denied=+40, sni_weight=+35 → score=80 → BLOCK
            emit(f, "secure-bankofamerica-login.com", "192.168.1.100",
                 "BLOCK   | banking phishing from internal workstation")
            time.sleep(1)

            # 3. Emotet banking trojan C2 from trading floor → BLOCK
            #    emotet-c2.net in financial_fraud.txt [BANKING-TROJAN-C2]
            #    10.50.0.5 in trading subnet (block_threshold=80, tightest enforcement)
            emit(f, "emotet-c2.net", "10.50.0.5",
                 "BLOCK   | Emotet C2 from trading floor (PCI-DSS critical)")
            time.sleep(1)

            # 4. Crypto miner C2 from internal host → BLOCK
            #    xmrig-pool.net in crypto_scams.txt [CRYPTO-MINING C2]
            emit(f, "xmrig-pool.net", "192.168.1.50",
                 "BLOCK   | crypto miner C2 (resource theft)")
            time.sleep(1)

            # 5. Ransomware payment domain from trading floor → BLOCK
            #    pay-ransom-btc.io in crypto_scams.txt [RANSOMWARE-CRYPTO]
            emit(f, "pay-ransom-btc.io", "10.50.0.10",
                 "BLOCK   | ransomware payment domain (trading floor)")
            time.sleep(1)

            # 6. PayPal phishing on guest network → BLOCK
            #    login-paypal-secure-verify.com in deny_domains.txt
            #    guest block_threshold=65; dns_denied=40 >= 35 → MONITOR; with sni → BLOCK
            emit(f, "login-paypal-secure-verify.com", "192.168.100.50",
                 "BLOCK   | PayPal phishing on guest/visitor network")
            time.sleep(1)

            # 7. Card skimmer burst from trading floor → sustained BLOCK event
            #    js-cdn-analytics.com in financial_fraud.txt [CARD-SKIMMER]
            #    200 queries from trading floor to make dashboard event count dramatic
            print(f"[FIN-INJECTOR]  {'BLOCK   | card skimmer burst x200 (trading floor)':50s}  10.50.0.5")
            for _ in range(200):
                f.write(make_line("js-cdn-analytics.com", "10.50.0.5"))
                f.flush()
                time.sleep(0.05)

            print(f"[FIN-INJECTOR] Loop {loop} complete. Sleeping 15s...")
            time.sleep(15)


if __name__ == "__main__":
    main()
