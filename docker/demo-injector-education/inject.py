#!/usr/bin/env python3
"""
MiniFW-AI Education Sector Demo Injector

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
    print(f"[EDU-INJECTOR]  {label:55s}  {ip}", flush=True)


def main() -> None:
    print(f"[EDU-INJECTOR] Starting. Target log: {DNS_LOG_PATH}", flush=True)
    time.sleep(8)

    loop = 0
    with open(DNS_LOG_PATH, "a") as f:
        while True:
            loop += 1
            print(f"\n[EDU-INJECTOR] -- Loop {loop} --", flush=True)

            # 1. Legitimate student study traffic -> ALLOW
            emit(f, "khanacademy.org",      "10.10.0.10",      "ALLOW   | Khan Academy (student study)")
            time.sleep(1)
            emit(f, "bbc.co.uk",            "10.10.0.11",      "ALLOW   | BBC news/education")
            time.sleep(1)
            emit(f, "wikipedia.org",        "10.10.0.12",      "ALLOW   | Wikipedia research")
            time.sleep(2)

            # 2. Social media attempt from student network -> MONITOR score=40
            emit(f, "instagram.com",        "10.10.0.20",      "MONITOR | Social media (student net, score=40)")
            time.sleep(2)

            # 3. VPN bypass attempt from student -> MONITOR (score=40 < 70)
            emit(f, "nordvpn.com",          "10.10.0.50",      "MONITOR | VPN bypass attempt (student net)")
            time.sleep(1)

            # 4. VPN bypass with YARA match -> BLOCK (score=75 > student block_threshold=70)
            emit(f, "nordvpn-bypass.proxy.io", "10.10.0.50",   "BLOCK   | YARA VPN proxy (student, score=75)")
            time.sleep(2)

            # 5. Content filter bypass from guest -> BLOCK (YARA +35, score=75 > guest block=60)
            emit(f, "filter-bypass.student.io", "192.168.100.10", "BLOCK | Content filter bypass (guest, YARA)")
            time.sleep(2)

            # 6. Gambling site attempt from student -> MONITOR
            emit(f, "bet365.com",           "10.10.0.100",     "MONITOR | Gambling site (student net, score=40)")
            time.sleep(1)

            # 7. VPN burst attack -> BLOCK cascade (200 requests)
            print(f"\n[EDU-INJECTOR] -- VPN burst (200 x nordvpn-bypass.proxy.io) --", flush=True)
            for i in range(200):
                f.write(line("nordvpn-bypass.proxy.io", "10.10.0.200"))
                if i % 50 == 0:
                    f.flush()
                    print(f"[EDU-INJECTOR]  burst {i+1}/200", flush=True)
            f.flush()
            print(f"[EDU-INJECTOR]  burst complete -> BLOCK cascade", flush=True)
            time.sleep(5)

            print(f"[EDU-INJECTOR] Loop {loop} complete -- sleeping 10s", flush=True)
            time.sleep(10)


if __name__ == "__main__":
    main()
