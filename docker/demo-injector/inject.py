#!/usr/bin/env python3
"""
MiniFW-AI Hospital Demo Injector

Writes dnsmasq-format log lines to a shared volume file that the engine
tails (MINIFW_DNS_SOURCE=file). Runs a continuous scenario loop so the
dashboard stays populated.

Parser (collector_dnsmasq.py:parse_dnsmasq) only requires:
  ' query[' in line  AND  ' from ' in line
No syslog timestamp prefix is needed.

Scenario outcomes (with demo-policy.json + hospital sector):
  1. windows.update.com   / 192.168.1.1  → ALLOW   score=0   severity=info
  2. lockbit-blog.com     / 10.20.0.5    → MONITOR score=40  severity=critical (IoMT)
  3. my-chart-login.com   / 192.168.1.50 → MONITOR score=40  severity=info
  4. RyukReadMe.example.com / 10.20.1.10 → MONITOR score=75  severity=critical (YARA+DNS+IoMT)
  5. ehr-software-update.com / 10.20.0.5 → MONITOR score=40  severity=critical (IoMT)
  6. medrecords-transfer.io / 172.16.0.99 → BLOCK  score=40  (mednet, 250 events)

All hospital events: domain=[REDACTED] (HIPAA redaction).
"""
import os
import time

DNS_LOG_PATH = os.environ.get("DNS_LOG_PATH", "/logs/dnsmasq.log")


def make_line(domain: str, ip: str) -> str:
    return f"dnsmasq[1]: query[A] {domain} from {ip}\n"


def emit(f, domain: str, ip: str, label: str) -> None:
    f.write(make_line(domain, ip))
    f.flush()
    print(f"[INJECTOR]  {label:45s}  {ip}")


def main() -> None:
    print(f"[INJECTOR] Starting. Target log: {DNS_LOG_PATH}")
    # The engine opens dnsmasq.log during startup and seeks to EOF.
    # Wait for the engine health check to pass (depends_on handles this),
    # then add a small buffer so the seek happens before we write.
    time.sleep(8)

    loop = 0
    with open(DNS_LOG_PATH, "a") as f:
        while True:
            loop += 1
            print(f"\n[INJECTOR] ── Loop {loop} ─────────────────────────────────────")

            # 1. Benign workstation query → ALLOW (score=0)
            emit(f, "windows.update.com",     "192.168.1.1",  "ALLOW  | benign update check")
            time.sleep(1)

            # 2. LockBit C2 from IoMT device → MONITOR, severity=critical, [REDACTED]
            #    lockbit-blog.com is in healthcare_threats.txt
            #    10.20.0.5 is in iomt_subnets → iomt_device_alert fires
            emit(f, "lockbit-blog.com",        "10.20.0.5",   "MONITOR critical | LockBit C2 from IoMT")
            time.sleep(1)

            # 3. Fake MyChart login from workstation → MONITOR, severity=info, [REDACTED]
            #    my-chart-login.com is in healthcare_threats.txt [PHISHING]
            #    192.168.1.50 is NOT in iomt_subnets → no severity boost
            emit(f, "my-chart-login.com",      "192.168.1.50", "MONITOR info   | phishing from workstation")
            time.sleep(1)

            # 4. YARA + DNS combo from IoMT → score=75, MONITOR, severity=critical
            #    RyukReadMe.example.com is in healthcare_threats.txt → dns_denied (+40)
            #    YARA scans f"{domain} {sni}".encode() → "RyukReadMe" triggers
            #    MedicalRansomware rule (nocase) → yara_score=100 → +35
            #    10.20.1.10 is in iomt_subnets → iomt_device_alert + severity=critical
            emit(f, "RyukReadMe.example.com",  "10.20.1.10",  "MONITOR critical | YARA MedicalRansomware + DNS")
            time.sleep(1)

            # 5. EHR ransomware C2 from IoMT → MONITOR, severity=critical, [REDACTED]
            #    ehr-software-update.com is in healthcare_threats.txt [RANSOMWARE-C2]
            emit(f, "ehr-software-update.com", "10.20.0.5",   "MONITOR critical | EHR C2 from IoMT")
            time.sleep(1)

            # 6. Data broker burst from mednet → BLOCK
            #    medrecords-transfer.io is in healthcare_threats.txt [DATABROKER]
            #    172.16.0.99 is in mednet (172.16.0.0/16)
            #    mednet block_threshold=45; after hospital adj (-5) effective=40
            #    dns_denied=40 >= 40 → BLOCK on query #1
            #    250 queries sent to make the event count dramatic in the dashboard
            print(f"[INJECTOR]  {'BLOCK   | mednet data broker burst (250 queries)':45s}  172.16.0.99")
            for i in range(250):
                f.write(make_line("medrecords-transfer.io", "172.16.0.99"))
                f.flush()
                time.sleep(0.05)   # 250 queries over ~12 seconds

            print(f"[INJECTOR] Loop {loop} complete. Sleeping 15s before next loop...")
            time.sleep(15)


if __name__ == "__main__":
    main()
