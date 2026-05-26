# Attack Score Timeline — St. Roch Memorial Hospital
**Demo run:** 2026-05-26  
**Scenario:** Dual-vector: IoMT ransomware + PHI exfiltration

---

## Attacker 1 — Patient Monitor 172.16.2.50 (mednet segment)

**Block threshold for mednet: 45** (vs 80 for internal, 85 for general)

```
09:00:01  192.168.1.20  emr.stroch.hospital.net         score  19  ████░░░░░░░░░░░░░░░░  ALLOW
09:00:12  172.16.1.10   pacs.stroch.hospital.net         score  21  ████░░░░░░░░░░░░░░░░  ALLOW
09:00:23  192.168.1.21  hl7.stroch.hospital.net          score  18  ████░░░░░░░░░░░░░░░░  ALLOW
09:00:34  192.168.1.22  pharmacy.stroch.hospital.net     score  20  ████░░░░░░░░░░░░░░░░  ALLOW
09:00:45  172.16.1.11   fhir.stroch.hospital.net         score  22  ████░░░░░░░░░░░░░░░░  ALLOW
...
09:01:30  172.16.2.50   c2.iomt-backdoor.net             score  33  ███████░░░░░░░░░░░░░  MONITOR  ← anomaly: IoMT calling external
09:01:36  172.16.2.50   drop.medfware-c2.io              score  39  ████████░░░░░░░░░░░░  MONITOR  ← firmware exploit C2
09:01:42  172.16.2.50   exfil.ransom-hospital.net        score  43  █████████░░░░░░░░░░░  MONITOR  ← ransomware staging
09:01:48  172.16.2.50   exfil.ransom-hospital.net        score  47  ██████████░░░░░░░░░░  BLOCK    ← score 47 > mednet threshold 45
```

**Total time from first signal to block: 18 seconds**

The mednet threshold of 45 is the key number here. Without IoMT segmentation, the
general threshold of 80–85 would have applied. The device would have continued
escalating for another 33 points — enough time to encrypt EMR data or disable
clinical monitoring systems.

---

## Attacker 2 — Clinical Workstation 192.168.1.75 (internal segment)

**Block threshold for internal: 80**

```
09:03:00  192.168.1.75  harvest.phi-stealer.net          score  52  ███████████░░░░░░░░░  MONITOR  ← credential harvesting tool
09:03:06  192.168.1.75  api.phi-dump.io                  score  64  █████████████░░░░░░░  MONITOR  ← FHIR bulk export abuse
09:03:12  192.168.1.75  drop.patient-exfil.net           score  75  ███████████████░░░░░  MONITOR  ← patient data staging
09:03:18  192.168.1.75  drop.patient-exfil.net           score  82  ████████████████░░░░  BLOCK    ← score 82 > internal threshold 80
```

**Total time from first signal to block: 18 seconds**

The attacker's credential harvest came from a phishing email opened three hours earlier.
The FHIR query pattern — bulk `/$export` request against the patient record API —
was the signal that elevated the score from 52 to 64. The staging host then moved
it from 64 to 75. The block fired before the first byte of patient data reached
the external drop zone.

---

## Evidence Summary

| Metric                  | Attacker 1 (IoMT)      | Attacker 2 (PHI)       |
|-------------------------|------------------------|------------------------|
| Source IP               | 172.16.2.50            | 192.168.1.75           |
| Segment                 | mednet                 | internal               |
| Block threshold         | 45                     | 80                     |
| Score at block          | 47                     | 82                     |
| Time to block           | 18 seconds             | 18 seconds             |
| PHI / EMR exposed       | 0 bytes                | 0 bytes                |
| Clinical ops affected   | None                   | None                   |
| HIPAA trace ID          | HIPAA-PHI-D3B16F5A     | HIPAA-PHI-17F5AD9E     |
| Human intervention      | None                   | None                   |
