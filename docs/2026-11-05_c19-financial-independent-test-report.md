# Independent Test & Verification Report: MiniFW-AI Financial v2.2.10 (Candidate C19)

**Issue Reference:** [GitHub Issue #7 (vadhh/minifw-ai#7)](https://github.com/vadhh/minifw-ai/issues/7)  
**Assigned Tester:** `ilhamws`  
**Host & Environment:** `sydeco-desktop` (`100.64.135.126` via Tailscale)  
**Guest VM:** `minifw-ilham-financial` (Debian 12 genericcloud amd64, Linux kernel `6.1.0-54-cloud-amd64`)  
**Run Window (WIB):** 5 November 2026, **13:19:53 – 13:28:15 WIB** (Duration: 8m 22s)  
**Candidate Package:** `minifw-ai_2.2.10-finance_amd64.deb`  
**Package Origin:** GitHub API authenticated download (`gh release download v2.2.10-c19-financial-test`) from collaborator draft release  
**Package SHA-256:** `ead9c4a376c4680c8cfdbbf97e303e8a8361a4bad47ae3a48094c12db8819744` (MATCH / PASS)  
**Deployment ID:** `e645474e-5d68-47ab-9b0c-c5d2fc98a61c`  
**Signed Licence ID:** `6f74f3eb-c9f7-4913-b1c5-83566fa53ca0` (Key: `minifw-vendor-2026`)  
**Overall Verdict:** **PASSED (All 5 Audit Points & Baseline Criteria Verified)**

---

## 1. Response to Issue Review (Comment #6650827460)

| Review Item | Independent Verification Finding & Evidence |
|---|---|
| **1. Host, Guest & Times** | **Host:** `sydeco-desktop` (`100.64.135.126`)<br>**Guest:** `minifw-ilham-financial` (disposable Debian 12 overlay, KVM port 23231)<br>**Times:** Start: **13:19:53 WIB** (06:19:53 UTC) &middot; End: **13:28:15 WIB** (06:28:15 UTC) |
| **2. Installer & Package Status** | **SHA-256:** `ead9c4a376c4680c8cfdbbf97e303e8a8361a4bad47ae3a48094c12db8819744`<br>**Retrieval:** Authenticated GitHub CLI release asset fetch (`gh release download v2.2.10-c19-financial-test`) transferred to guest via SCP.<br>**dpkg Status:** `Status: install ok installed`, `Version: 2.2.10-finance`<br>**dpkg --verify:** Clean (exit code 0) |
| **3. Raw `nft` Output** | Captured in live kernel during active client isolation (`10.10.0.20` in `minifw_block_v4`, timeout 15s) and verified automatically purged after timeout expiration. |
| **4. Run Logs / Results** | Exported to [`docs/evidence/2026-11-05-independent-run/ilham-run-evidence.json`](file:///mnt/c/Users/ADVAN/minifw-ai/docs/evidence/2026-11-05-independent-run/ilham-run-evidence.json). |
| **5. Deployment ID & Signed Licence** | **Deployment ID:** `e645474e-5d68-47ab-9b0c-c5d2fc98a61c` (generated from dashboard `/admin/license` on guest).<br>**Licence Details:** Key ID: `minifw-vendor-2026`, Licence ID: `6f74f3eb-c9f7-4913-b1c5-83566fa53ca0`. Signed via vendor authority on lab host. Activated via `/admin/api/license` (HTTP 200, status `valid`). Tampered license rejected (HTTP 400). Persisted across `minifw-ai-web` service restart. |

---

## 2. Raw Technical Outputs

### 2.1 Package Status (`dpkg -s minifw-ai`)
```text
Package: minifw-ai
Status: install ok installed
Priority: optional
Section: net
Maintainer: Afridho Ikhsan <afridho@minifw.local>
Architecture: amd64
Version: 2.2.10-finance
Depends: python3 (>= 3.10), python3-venv, nftables, openssl, conntrack, logrotate, adduser
Recommends: dnsmasq, zeek
Description: MiniFW-AI Behavioral Firewall Engine (ARCHANGEL 2.0) [finance]
```

### 2.2 Raw nftables Output During Active Client Isolation (10.10.0.20)
```nftables
table inet minifw {
	set minifw_block_v4 {
		type ipv4_addr
		timeout 1h
		elements = { 10.10.0.20 timeout 15s expires 14s972ms }
	}

	chain forward {
		type filter hook forward priority filter; policy accept;
		ct state new counter packets 0 bytes 0 comment "MiniFW-AI-Conntrack"
		ip saddr @minifw_block_v4 counter packets 0 bytes 0 drop comment "MiniFW-AI-Blocklist"
	}
}
```

### 2.3 Raw nftables Output After Timeout Expiration
```nftables
table inet minifw {
	set minifw_block_v4 {
		type ipv4_addr
		timeout 1h
	}

	chain forward {
		type filter hook forward priority filter; policy accept;
		ct state new counter packets 0 bytes 0 comment "MiniFW-AI-Conntrack"
		ip saddr @minifw_block_v4 counter packets 0 bytes 0 drop comment "MiniFW-AI-Blocklist"
	}
}
```

### 2.4 Licence Activation Verification
* **Key ID:** `minifw-vendor-2026`
* **Licence ID:** `6f74f3eb-c9f7-4913-b1c5-83566fa53ca0`
* **Deployment ID:** `e645474e-5d68-47ab-9b0c-c5d2fc98a61c`
* **Customer ID:** `ilhamws-independent-financial-lab`
* **Product Mode:** `minifw_financial`
* **Validity Window:** `2026-11-05T06:26:34Z` to `2027-11-05T06:26:34Z`
* **Status:** `valid` (HTTP 200 on `/admin/api/license`)
* **Tampered Rejection:** HTTP 400 (corrupted payload rejected)
*(Note: Per public repository security guidelines, full license payload, signature string, and private key paths are omitted).*

### 2.5 Policy Apply Response via Dashboard (`POST /admin/policy/apply`)
```json
{
  "http_status": 200,
  "message": "Engine restarted; saved policy and feeds loaded. Check protection status on the dashboard.",
  "engine_pid": 1505
}
```

---

## 3. Operational Sign-off & Recommendation

* **Baseline Release Recommendation:** **GO (APPROVED)**
* **AI Autonomous Enforcement:** **HOLD (BLOCKED, SHADOW-ONLY)**
* **Evaluator:** `@ilhamws`
