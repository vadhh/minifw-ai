#!/usr/bin/env python3
"""
MiniFW-AI Hospital Sector Demo Injector

Writes dnsmasq-format log lines to a shared volume so the firewall engine
processes them and generates visible block/monitor/allow events on the dashboard.

Scenario outcomes (with hospital policy + healthcare_threats.txt feed):
  1. epic.com             / 192.168.1.1   → ALLOW   score=0   (benign EHR vendor)
  2. cerner.com           / 192.168.1.2   → ALLOW   score=0   (benign EHR vendor)
  3. microsoft.com        / 192.168.1.3   → ALLOW   score=0   (benign OS update)
  4. lockbit-blog.com     / 10.20.0.5     → MONITOR score=40  severity=critical (IoMT)
  5. my-chart-login.com   / 192.168.1.50  → MONITOR score=40  severity=info (phishing)
  6. RyukReadMe.example.com / 10.20.1.10  → MONITOR score=75  severity=critical (YARA+DNS+IoMT)
  7. ehr-software-update.com / 10.20.0.5  → MONITOR score=40  severity=critical (IoMT)
  8. medrecords-transfer.io burst / 172.16.0.99 → BLOCK cascade (mednet, score=50)

All hospital events: domain=[REDACTED] (HIPAA redaction active).
"""
import os
import time

DNS_LOG_PATH = os.environ.get("DNS_LOG_PATH", "/logs/dnsmasq.log")


def line(domain: str, ip: str) -> str:
    return f"dnsmasq[1]: query[A] {domain} from {ip}\n"


def emit(f, domain: str, ip: str, label: str) -> None:
    f.write(line(domain, ip))
    f.flush()
    print(f"[HOSP-INJECTOR]  {label:55s}  {ip}", flush=True)


def main() -> None:
    print(f"[HOSP-INJECTOR] Starting. Target log: {DNS_LOG_PATH}", flush=True)
    time.sleep(8)

    loop = 0
    with open(DNS_LOG_PATH, "a") as f:
        while True:
            loop += 1
            print(f"\n[HOSP-INJECTOR] -- Loop {loop} --", flush=True)

            # 1. Legitimate EHR / clinical system traffic -> ALLOW
            emit(f, "epic.com",               "192.168.1.1",  "ALLOW   | Epic EHR (clinical workstation)")
            time.sleep(1)
            emit(f, "cerner.com",             "192.168.1.2",  "ALLOW   | Cerner EHR (clinical workstation)")
            time.sleep(1)
            emit(f, "microsoft.com",          "192.168.1.3",  "ALLOW   | Microsoft update (workstation)")
            time.sleep(2)

            # 2. LockBit C2 from IoMT device -> MONITOR, severity=critical
            #    lockbit-blog.com in healthcare_threats.txt -> dns_denied (+40)
            #    10.20.0.5 in iomt_subnets -> iomt_device_alert fires
            emit(f, "lockbit-blog.com",        "10.20.0.5",   "MONITOR | LockBit C2 from IoMT device (critical)")
            time.sleep(2)

            # 3. Fake MyChart login from workstation -> MONITOR, severity=info
            #    my-chart-login.com in healthcare_threats.txt -> dns_denied (+40)
            emit(f, "my-chart-login.com",      "192.168.1.50","MONITOR | Fake MyChart phishing (workstation)")
            time.sleep(1)

            # 4. YARA + DNS combo from IoMT -> score=75, MONITOR, severity=critical
            #    RyukReadMe in healthcare_threats.txt -> dns_denied (+40)
            #    YARA MedicalRansomware rule fires (+35) -> total 75
            #    10.20.1.10 in iomt_subnets -> iomt_device_alert + severity=critical
            emit(f, "RyukReadMe.example.com",  "10.20.1.10",  "MONITOR | YARA MedicalRansomware + IoMT alert (critical)")
            time.sleep(2)

            # 5. EHR ransomware C2 from IoMT -> MONITOR, severity=critical
            #    ehr-software-update.com in healthcare_threats.txt -> dns_denied (+40)
            emit(f, "ehr-software-update.com", "10.20.0.5",   "MONITOR | EHR ransomware C2 from IoMT (critical)")
            time.sleep(1)

            # 6. Medical data broker burst from mednet -> BLOCK cascade
            #    medrecords-transfer.io in healthcare_threats.txt -> dns_denied (+40)
            #    172.16.0.99 in mednet (172.16.0.0/16), block_threshold=45
            #    dns_denied(40) + burst(10) = 50 > 45 -> BLOCK
            print(f"\n[HOSP-INJECTOR] -- Mednet data broker burst (200 x medrecords-transfer.io) --", flush=True)
            for i in range(200):
                f.write(line("medrecords-transfer.io", "172.16.0.99"))
                if i % 50 == 0:
                    f.flush()
                    print(f"[HOSP-INJECTOR]  burst {i+1}/200", flush=True)
            f.flush()
            print(f"[HOSP-INJECTOR]  burst complete -> BLOCK cascade", flush=True)
            time.sleep(5)

            print(f"[HOSP-INJECTOR] Loop {loop} complete -- sleeping 10s", flush=True)
            time.sleep(10)


if __name__ == "__main__":
    main()
