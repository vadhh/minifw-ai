#!/usr/bin/env python3
"""
MiniFW-AI Legal Sector Demo Injector

Writes dnsmasq-format log lines to a shared volume so the firewall engine
processes them and generates visible block/monitor/allow events on the dashboard.
"""
import os
import time

DNS_LOG_PATH = os.environ.get("DNS_LOG_PATH", "/logs/dnsmasq.log")


def line(domain: str, ip: str) -> str:
    return f"dnsmasq[1]: query[A] {domain} from {ip}\n"


def emit(f, domain: str, ip: str, label: str) -> None:
    f.write(line(domain, ip))
    f.flush()
    print(f"[LEGAL-INJECTOR]  {label:60s}  {ip}", flush=True)


def main() -> None:
    print(f"[LEGAL-INJECTOR] Starting. Target log: {DNS_LOG_PATH}", flush=True)
    time.sleep(8)

    loop = 0
    with open(DNS_LOG_PATH, "a") as f:
        while True:
            loop += 1
            print(f"\n[LEGAL-INJECTOR] -- Loop {loop} --", flush=True)

            # 1. Legitimate legal research traffic -> ALLOW
            emit(f, "westlaw.com",      "10.20.0.10",   "ALLOW   | Westlaw legal research (partner)")
            time.sleep(1)
            emit(f, "lexisnexis.com",   "10.20.0.11",   "ALLOW   | LexisNexis research (partner)")
            time.sleep(1)
            emit(f, "courts.gov",       "10.20.1.10",   "ALLOW   | Federal court docket (associate)")
            time.sleep(2)

            # 2. Unauthorized cloud upload from paralegal -> MONITOR (feed +40, score=40 > monitor=38 < block=70)
            emit(f, "wetransfer-legal.io", "10.20.2.10", "MONITOR | Unauthorized cloud upload (paralegal, score=40)")
            time.sleep(2)

            # 3. Tor exit node from client meeting room -> BLOCK (feed+YARA=75 > client block=62)
            emit(f, "tor-exit-relay.onion-gw.net", "192.168.200.5", "BLOCK   | Tor exit relay (client room, score=75)")
            time.sleep(2)

            # 4. Ransomware C2 from associate net -> BLOCK (feed+YARA=75 > associate block=72)
            emit(f, "clio-encrypt.c2-server.ru", "10.20.1.20", "BLOCK   | Ransomware C2 beacon (associate, score=75)")
            time.sleep(2)

            # 5. Privilege breach from paralegal -> BLOCK (feed+YARA=75 > paralegal block=70)
            emit(f, "opposing-counsel.harvest.io", "10.20.2.50", "BLOCK   | Privilege violation (paralegal, score=75)")
            time.sleep(2)

            # 6. Ransomware burst attack -> BLOCK cascade
            print(f"\n[LEGAL-INJECTOR] -- Ransomware burst (200 x clio-encrypt.c2-server.ru) --", flush=True)
            for i in range(200):
                f.write(line("clio-encrypt.c2-server.ru", "10.20.1.99"))
                if i % 50 == 0:
                    f.flush()
                    print(f"[LEGAL-INJECTOR]  burst {i+1}/200", flush=True)
            f.flush()
            print(f"[LEGAL-INJECTOR]  burst complete -> BLOCK cascade", flush=True)
            time.sleep(5)

            print(f"[LEGAL-INJECTOR] Loop {loop} complete -- sleeping 10s", flush=True)
            time.sleep(10)


if __name__ == "__main__":
    main()
