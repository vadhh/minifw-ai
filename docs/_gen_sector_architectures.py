#!/usr/bin/env python3
"""Generate architecture SVGs for every sector (hospital, education, government, legal, establishment)."""

import os

F = "Arial,Helvetica,sans-serif"

def e(tag, **attrs):
    attr_str = " ".join(f'{k.replace("_","-")}="{v}"' for k, v in attrs.items())
    return f"<{tag} {attr_str}/>"

def el(tag, content, **attrs):
    attr_str = " ".join(f'{k.replace("_","-")}="{v}"' for k, v in attrs.items())
    return f'<{tag} {attr_str}>{content}</{tag}>'

def rect(x, y, w, h, fill, stroke, rx=6, sw=1.5, extra=""):
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}" {extra}/>'

def txt(x, y, content, size=9, fill="#333", weight="normal", anchor="start"):
    return f'<text x="{x}" y="{y}" font-size="{size}" fill="{fill}" font-weight="{weight}" text-anchor="{anchor}" font-family="{F}">{content}</text>'

def badge(x, y, label, fill):
    return rect(x, y, 76, 13, fill, fill, rx=4, sw=1.5) + "\n" + txt(x+38, y+9, label, size=7, fill="#fff", weight="bold", anchor="middle")

ARROW = '<defs><marker id="arrowhead" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="#555"/></marker><filter id="shadow" x="-5%" y="-5%" width="115%" height="115%"><feDropShadow dx="1" dy="1" stdDeviation="2" flood-opacity="0.12"/></filter></defs>'

def build_svg(cfg):
    s = cfg
    lines = []
    a = lines.append

    W, H = 1200, 820
    a(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">')
    a(ARROW)

    # BG
    a(rect(0, 0, W, H, "#f4f6f9", "#f4f6f9", rx=0, sw=0))
    # Header
    a(rect(0, 0, W, 58, s["header_fill"], s["header_fill"], rx=0, sw=0))
    a(txt(600, 26, f'MiniFW-AI — {s["sector_name"]} Sector Architecture', size=18, fill="#fff", weight="bold", anchor="middle"))
    a(txt(600, 46, s["subtitle"], size=12, fill=s["header_sub"], weight="normal", anchor="middle"))

    # ── NETWORK LAYER ──────────────────────────────────────
    a(rect(20, 70, 790, 90, "#fff", "#adb5bd", extra='filter="url(#shadow)"'))
    a(rect(28, 78, 160, 22, "#1e3a5f", "#1e3a5f", rx=4))
    a(txt(108, 93, "NETWORK LAYER", size=10, fill="#fff", weight="bold", anchor="middle"))
    segs = s["segments"]
    xs = [36, 290, 544]
    colors = [s["seg1_color"], s["seg2_color"], s["seg3_color"]]
    for i, (seg, x, c) in enumerate(zip(segs, xs, colors)):
        a(rect(x, 102, 234, 48, "#f8f9fa", c, rx=5))
        a(txt(x+117, 122, seg[0], size=11, fill=c, weight="bold", anchor="middle"))
        a(txt(x+117, 137, seg[1], size=9, fill="#555", weight="normal", anchor="middle"))

    # Arrows down
    for x in [153, 407, 661]:
        a(f'<line x1="{x}" y1="150" x2="{x}" y2="178" stroke="#555" stroke-width="1.5" marker-end="url(#arrowhead)"/>')

    # ── COLLECTION LAYER ──────────────────────────────────
    a(rect(20, 178, 790, 74, "#fff", "#adb5bd", extra='filter="url(#shadow)"'))
    a(rect(28, 186, 170, 22, "#1e3a5f", "#1e3a5f", rx=4))
    a(txt(113, 201, "COLLECTION LAYER", size=10, fill="#fff", weight="bold", anchor="middle"))
    cols = [("#e7f3ff", "#0d6efd", "DNS Backend", "dnsmasq · journald · UDP · none", 36, 153),
            ("#e7f3ff", "#0d6efd", "Flow Collector", "conntrack / nf_conntrack fallback", 290, 407),
            ("#e7f3ff", "#0d6efd", "Zeek / SNI", "TLS SNI extraction", 544, 661)]
    for fill, stroke, title, sub, x, cx in cols:
        a(rect(x, 208, 234, 36, fill, stroke, rx=5))
        a(txt(cx, 224, title, size=10, fill=stroke, weight="bold", anchor="middle"))
        a(txt(cx, 237, sub, size=9, fill="#444", anchor="middle"))

    a(f'<line x1="415" y1="252" x2="415" y2="270" stroke="#555" stroke-width="1.5" marker-end="url(#arrowhead)"/>')
    a(txt(505, 266, "DNS events + flows", size=9, fill="#777", anchor="middle"))

    # ── DETECTION PIPELINE ────────────────────────────────
    a(rect(20, 272, 790, 218, "#fff", "#adb5bd", extra='filter="url(#shadow)"'))
    a(rect(28, 280, 220, 22, "#1e3a5f", "#1e3a5f", rx=4))
    a(txt(138, 295, "DETECTION PIPELINE  (Scoring Engine)", size=10, fill="#fff", weight="bold", anchor="middle"))

    steps = [
        ("#d4edda", "#28a745", "#155724", "Feed Matcher",
         "DNS/IP/ASN deny-feed lookup — threat intelligence", "+40 pts", 302),
        ("#d1ecf1", "#17a2b8", "#0c5460", "Burst Tracker",
         "Query-per-minute spike detection — volumetric", "+10 pts", 338),
        ("#fff3cd", "#fd7e14", "#856404", "Hard Gates",
         "PPS / bot / burst override — forces score to 100", "→ 100", 374),
        ("#ede7ff", "#6f42c1", "#3d1d8a", "MLP Detector",
         "Neural network — behavioural threat probability", "+30 pts", 410),
        ("#fce4ec", "#e83e8c", "#6d0a3a", "YARA Scanner",
         s["yara_desc"], "+35 pts", 446),
    ]
    for bg, stroke, fg, title, desc, pts, y in steps:
        a(rect(32, y, 766, 30, bg, stroke, rx=4))
        a(rect(36, y+5, 20, 20, stroke, stroke, rx=4))
        a(txt(46, y+19, str(steps.index((bg,stroke,fg,title,desc,pts,y))+1), size=10, fill="#fff", weight="bold", anchor="middle"))
        a(txt(70, y+19, title, size=11, fill=fg, weight="bold"))
        a(txt(200, y+19, desc, size=9, fill="#444"))
        a(rect(730, y+5, 60, 20, stroke, stroke, rx=4))
        a(txt(760, y+19, pts, size=9, fill="#fff", weight="bold", anchor="middle"))

    # ── POLICY DECISION ───────────────────────────────────
    a(rect(20, 502, 790, 68, "#fff", "#adb5bd", extra='filter="url(#shadow)"'))
    a(rect(28, 510, 150, 22, "#1e3a5f", "#1e3a5f", rx=4))
    a(txt(103, 525, "POLICY DECISION", size=10, fill="#fff", weight="bold", anchor="middle"))
    # Three outcomes
    decisions = [
        (40, "#d4edda", "#28a745", "#155724", "ALLOW", s["allow_range"]),
        (295, "#fff3cd", "#ffc107", "#856404", "MONITOR", s["monitor_range"]),
        (550, "#f8d7da", "#dc3545", "#721c24", "BLOCK", s["block_range"]),
    ]
    for x, bg, stroke, fg, label, rng in decisions:
        a(rect(x, 530, 230, 32, bg, stroke, rx=5))
        a(txt(x+115, 544, label, size=13, fill=fg, weight="bold", anchor="middle"))
        a(txt(x+115, 556, rng, size=9, fill=fg, anchor="middle"))

    a(f'<line x1="665" y1="562" x2="665" y2="584" stroke="#dc3545" stroke-width="1.5" marker-end="url(#arrowhead)"/>')

    # ── ENFORCEMENT ───────────────────────────────────────
    a(rect(20, 582, 790, 62, "#fff", "#adb5bd", extra='filter="url(#shadow)"'))
    a(rect(28, 590, 160, 22, "#1e3a5f", "#1e3a5f", rx=4))
    a(txt(108, 605, "ENFORCEMENT  (kernel)", size=10, fill="#fff", weight="bold", anchor="middle"))
    enf = [
        (36, "#fff5f5", "#dc3545", "nftables", "kernel-level packet drop"),
        (228, "#fff5f5", "#dc3545", "ipset", "IP blocklist  (86400s TTL)"),
        (420, "#f8f9fa", "#6c757d", "Audit Log", "JSONL audit trail"),
        (612, "#f8f9fa", "#6c757d", "Event Log", "JSONL event stream"),
    ]
    for x, bg, stroke, title, sub in enf:
        a(rect(x, 612, 180, 26, bg, stroke, rx=4))
        a(txt(x+90, 623, title, size=10, fill=stroke, weight="bold", anchor="middle"))
        a(txt(x+90, 634, sub, size=8, fill="#555", anchor="middle"))

    # ── SECTOR OVERLAY ────────────────────────────────────
    a(rect(20, 658, 790, 56, "#1e3a5f", "#1e3a5f"))
    a(txt(32, 672, f'SECTOR OVERLAY — {s["sector_name"].upper()}', size=10, fill="#8eb8e5", weight="bold"))
    overlay = [
        (32, "PRODUCT_MODE", s["product_mode"]),
        (224, "policy.json", "thresholds · weights · segments"),
        (416, s["yara_file"], s["yara_rules_desc"]),
        (608, "feeds/", "deny_domains · deny_ips · deny_asns"),
    ]
    for x, label, val in overlay:
        a(txt(x, 690, label, size=9, fill="#8eb8e5", weight="bold"))
        a(txt(x, 704, val, size=8, fill="#c8d8f0"))

    # ── WEB ADMIN PANEL (right column) ───────────────────
    a(rect(832, 70, 348, 648, "#fff", "#adb5bd", extra='filter="url(#shadow)"'))
    a(rect(840, 78, 200, 22, "#1e3a5f", "#1e3a5f", rx=4))
    a(txt(940, 93, "WEB ADMIN DASHBOARD", size=10, fill="#fff", weight="bold", anchor="middle"))
    a(txt(840, 110, "FastAPI  ·  AdminLTE 3  ·  SQLite  ·  JWT+TOTP", size=9, fill="#555"))
    a(txt(840, 124, s["dashboard_url"], size=9, fill="#0d6efd"))

    # Stats row
    stats = [(842, s["stat_allow"], "#28a745", "Allowed"),
             (926, s["stat_block"], "#dc3545", "Blocked"),
             (1010, s["stat_monitor"], "#ffc107", "Monitored"),
             (1094, s["stat_total"], "#17a2b8", "Total")]
    for x, val, c, label in stats:
        a(rect(x, 132, 78, 46, "#fff", c, rx=4))
        a(txt(x+39, 153, str(val), size=15, fill=c, weight="bold", anchor="middle"))
        a(txt(x+39, 168, label, size=8, fill=c, anchor="middle"))

    # Event rows
    a(txt(840, 196, "Recent Events  ●LIVE", size=10, fill="#333", weight="bold"))
    for i, (ts, domain, score, action, c) in enumerate(s["events"]):
        y = 202 + i * 26
        bg = "#fff" if i % 2 == 0 else "#f8f9fa"
        a(rect(840, y, 332, 24, bg, "#dee2e6", rx=2, sw=0.5))
        a(txt(848, y+15, ts, size=8, fill="#888"))
        a(txt(904, y+15, domain, size=8, fill="#333"))
        a(txt(1076, y+15, f"▸{score}", size=8, fill=c, weight="bold"))
        ac = "#dc3545" if action == "Blocked" else ("#ffc107" if action == "Monitor" else "#28a745")
        a(rect(1124, y+4, 50, 16, ac, ac, rx=4))
        a(txt(1149, y+15, action, size=7, fill="#fff", weight="bold", anchor="middle"))

    # Score breakdown panel
    bp_y = 202 + len(s["events"]) * 26
    a(rect(840, bp_y, 332, 116, "#f8f9fa", "#dee2e6", rx=4))
    a(txt(848, bp_y+14, f'Score Breakdown — BLOCK event  score {s["block_score"]}/100', size=9, fill="#333", weight="bold"))
    breakdowns = [
        ("#28a745", "Feed Matcher", s["bd_feed"], s["bd_feed"]),
        ("#e83e8c", "YARA Scanner", s["bd_yara"], s["bd_yara"]),
        ("#6f42c1", "MLP Detector", s["bd_mlp"], s["bd_mlp"]),
        ("#17a2b8", "Burst Tracker", s["bd_burst"], s["bd_burst"]),
    ]
    for j, (c, label, pts, bar_w) in enumerate(breakdowns):
        yy = bp_y + 26 + j * 22
        a(txt(848, yy, f"{label}  +{pts}", size=9, fill=c))
        max_bar = 112
        bw = max(2, int(bar_w / 40 * max_bar))
        a(rect(1012, yy-12, bw, 14, c, c, rx=2))

    # Firewall status
    fw_y = bp_y + 128
    a(rect(840, fw_y, 332, 102, "#f8f9fa", "#dee2e6", rx=4))
    a(txt(848, fw_y+14, "Firewall Status", size=10, fill="#333", weight="bold"))
    fw_rows = [
        (fw_y+37, "Firewall Engine", "#28a745", "Active"),
        (fw_y+55, "Detection Mode", "#6f42c1", "AI Enhanced"),
        (fw_y+73, s["compliance_label"], "#dc3545", "Enforcing"),
        (fw_y+91, "Threat Intelligence", "#0d6efd", "Active"),
    ]
    for y, label, c, val in fw_rows:
        a(txt(848, y, label, size=9, fill="#555"))
        a(badge(1090, y-10, val, c))

    # AI Synthesis panel
    ai_y = fw_y + 112
    a(rect(840, ai_y, 332, 50, "#ede7ff", "#6f42c1", rx=4))
    a(txt(848, ai_y+14, "AI Threat Synthesis Panel", size=10, fill="#3d1d8a", weight="bold"))
    a(txt(848, ai_y+28, "Detection · kernel enforcement · AI reasoning", size=9, fill="#555"))
    a(txt(848, ai_y+40, "Auth: JWT + TOTP + bcrypt  |  RBAC", size=8, fill="#888"))

    # State manager
    sm_y = ai_y + 60
    a(rect(840, sm_y, 332, 52, "#fff3cd", "#ffc107", rx=4))
    a(txt(848, sm_y+14, "State Manager", size=9, fill="#856404", weight="bold"))
    a(txt(848, sm_y+28, "BASELINE → AI_ENHANCED_PROTECTION", size=9, fill="#856404"))
    a(txt(848, sm_y+40, "Auto-transition on DNS telemetry health", size=8, fill="#856404"))

    # Legend
    lg_y = sm_y + 62
    a(rect(840, lg_y, 332, 56, "#fff", "#dee2e6", rx=4))
    a(txt(848, lg_y+12, "Legend", size=9, fill="#333", weight="bold"))
    leg = [(848, "#28a745", "Allow/Safe"), (960, "#ffc107", "Monitor"),
           (1072, "#dc3545", "Block/Critical"), (848+112+112, "#6f42c1", "AI Component"),
           (960, "#e83e8c", "YARA Scanner")]
    for x, c, label in [(848,"#28a745","Allow/Safe"),(960,"#ffc107","Monitor"),(1072,"#dc3545","Block/Critical")]:
        a(rect(x, lg_y+22, 10, 10, c, c, rx=2))
        a(txt(x+14, lg_y+31, label, size=8, fill="#333"))
    for x, c, label in [(848,"#6f42c1","AI Component"),(960,"#e83e8c","YARA Scanner")]:
        a(rect(x, lg_y+42, 10, 10, c, c, rx=2))
        a(txt(x+14, lg_y+51, label, size=8, fill="#333"))

    # Connector line
    a('<line x1="832" y1="380" x2="810" y2="614" stroke="#adb5bd" stroke-width="1" stroke-dasharray="4,3" marker-end="url(#arrowhead)"/>')

    a("</svg>")
    return "\n".join(lines)


SECTORS = {
    "hospital": {
        "sector_name": "Hospital",
        "subtitle": "HIPAA Compliance  ·  IoMT Protection  ·  AI-Powered Behavioral Firewall  ·  v2.2.0",
        "header_fill": "#1a3a2a",
        "header_sub": "#8eb8a5",
        "product_mode": "minifw_hospital",
        "seg1_color": "#ef4444",
        "seg2_color": "#3b82f6",
        "seg3_color": "#10b981",
        "segments": [
            ("MedNet  (IoMT)", "172.16.0.x  block@45  (pacemakers · monitors · infusion)"),
            ("Internal LAN", "192.168.1.x  block@80  (staff · EMR · PACS)"),
            ("Patient WiFi", "10.10.0.x  block@35  (guest devices)"),
        ],
        "yara_desc": "Hospital rules: IoMT backdoor · PHI exfil · ransomware payload",
        "yara_file": "hospital_rules.yar",
        "yara_rules_desc": "6 YARA rules · HIPAA tagged",
        "allow_range": "score < 35",
        "monitor_range": "score 35–44 (MedNet) / 35–79 (Internal)",
        "block_range": "score ≥ 45 (MedNet)  ≥ 80 (Internal)",
        "dashboard_url": "http://localhost:8000   admin / Hospital1!",
        "stat_allow": 23, "stat_block": 2, "stat_monitor": 6, "stat_total": 31,
        "events": [
            ("07:12:47", "c2.iomt-backdoor.net",      82,  "Blocked", "#dc3545"),
            ("07:12:41", "drop.medfware-c2.io",        75,  "Monitor", "#ffc107"),
            ("07:12:35", "harvest.phi-stealer.net",    47,  "Blocked", "#dc3545"),
            ("07:12:22", "exfil.ransom-hospital.net",  40,  "Monitor", "#ffc107"),
            ("07:12:08", "emr.stroch.hospital.net",     0,  "Allowed", "#28a745"),
        ],
        "block_score": 82,
        "bd_feed": 40, "bd_yara": 35, "bd_mlp": 7, "bd_burst": 0,
        "compliance_label": "HIPAA Mode",
    },
    "education": {
        "sector_name": "Education",
        "subtitle": "SafeSearch Enforcement  ·  Content Policy  ·  AI-Powered Behavioral Firewall  ·  v2.2.0",
        "header_fill": "#3b2800",
        "header_sub": "#f59e0b",
        "product_mode": "minifw_school",
        "seg1_color": "#f59e0b",
        "seg2_color": "#3b82f6",
        "seg3_color": "#10b981",
        "segments": [
            ("Student Net", "192.168.2.x  block@70  (pupil devices · BYOD)"),
            ("Staff Net", "192.168.1.x  block@80  (teacher · admin · SIS)"),
            ("Guest WiFi", "172.16.1.x  block@60  (visitor / parent devices)"),
        ],
        "yara_desc": "Education rules: VPN proxy bypass · SafeSearch bypass · content filter",
        "yara_file": "education_rules.yar",
        "yara_rules_desc": "3 YARA rules · SafeSearch tagged",
        "allow_range": "score < 60",
        "monitor_range": "score 60–69 (Student) / 60–79 (Staff)",
        "block_range": "score ≥ 70 (Student)  ≥ 60 (Guest)",
        "dashboard_url": "https://localhost:8447   admin / Education1!",
        "stat_allow": 18, "stat_block": 2, "stat_monitor": 4, "stat_total": 24,
        "events": [
            ("09:05:22", "vpn-bypass.proxtunnel.io",           75,  "Blocked", "#dc3545"),
            ("09:05:15", "login-paypal-secure-verify.com",     75,  "Blocked", "#dc3545"),
            ("09:05:08", "safesearch-bypass.vpnhide.net",      40,  "Monitor", "#ffc107"),
            ("09:04:55", "contentfilter-bypass.anonymize.io",  40,  "Monitor", "#ffc107"),
            ("09:04:40", "office365.com",                       0,  "Allowed", "#28a745"),
        ],
        "block_score": 75,
        "bd_feed": 40, "bd_yara": 35, "bd_mlp": 0, "bd_burst": 0,
        "compliance_label": "SafeSearch Mode",
    },
    "government": {
        "sector_name": "Government",
        "subtitle": "Data Sovereignty  ·  APT Defence  ·  AI-Powered Behavioral Firewall  ·  v2.2.0",
        "header_fill": "#1e1a3a",
        "header_sub": "#a78bfa",
        "product_mode": "minifw_government",
        "seg1_color": "#8b5cf6",
        "seg2_color": "#3b82f6",
        "seg3_color": "#6b7280",
        "segments": [
            ("Classified Net", "172.16.10.x  block@70  (classified endpoints · SCIF)"),
            ("Internal LAN", "192.168.1.x  block@45  (staff · services · printers)"),
            ("Guest / DMZ", "10.0.0.x  block@35  (visitor · untrusted)"),
        ],
        "yara_desc": "Government rules: APT C2 · Tor relay · data leak · phishing portal",
        "yara_file": "government_rules.yar",
        "yara_rules_desc": "4 YARA rules · Sovereignty tagged",
        "allow_range": "score < 35",
        "monitor_range": "score 35–44 (Internal) / 35–69 (Classified)",
        "block_range": "score ≥ 70 (Classified)  ≥ 35 (Guest)",
        "dashboard_url": "https://localhost:8449   admin / Government1!",
        "stat_allow": 20, "stat_block": 2, "stat_monitor": 5, "stat_total": 27,
        "events": [
            ("10:14:30", "apt28-c2.ru-beacon.net",          100,  "Blocked", "#dc3545"),
            ("10:14:20", "tor-relay-gov.exit.net",           75,  "Blocked", "#dc3545"),
            ("10:14:10", "classified-exfil.gov-drop.io",    40,  "Monitor", "#ffc107"),
            ("10:13:55", "phishing-portal.gov-verify.ru",   40,  "Monitor", "#ffc107"),
            ("10:13:40", "gov.uk",                            0,  "Allowed", "#28a745"),
        ],
        "block_score": 100,
        "bd_feed": 40, "bd_yara": 35, "bd_mlp": 25, "bd_burst": 0,
        "compliance_label": "Sovereignty Mode",
    },
    "legal": {
        "sector_name": "Legal",
        "subtitle": "Attorney–Client Privilege  ·  ACP Protection  ·  AI-Powered Behavioral Firewall  ·  v2.2.0",
        "header_fill": "#0a1e3a",
        "header_sub": "#7dd3fc",
        "product_mode": "minifw_legal",
        "seg1_color": "#0ea5e9",
        "seg2_color": "#3b82f6",
        "seg3_color": "#6b7280",
        "segments": [
            ("Partner Net", "192.168.1.x  block@85  (senior partners · billing)"),
            ("Associate Net", "192.168.2.x  block@72  (associates · Clio · matter mgmt)"),
            ("Client Room", "172.16.1.x  block@62  (client devices · visitor WiFi)"),
        ],
        "yara_desc": "Legal rules: ransomware C2 · data exfil · privilege violation · Tor relay",
        "yara_file": "legal_rules.yar",
        "yara_rules_desc": "4 YARA rules · ACP tagged",
        "allow_range": "score < 62",
        "monitor_range": "score 62–71 (Assoc) / 62–84 (Partner)",
        "block_range": "score ≥ 85 (Partner)  ≥ 72 (Assoc)  ≥ 62 (Client)",
        "dashboard_url": "https://localhost:8448   admin / Legal1!",
        "stat_allow": 15, "stat_block": 2, "stat_monitor": 3, "stat_total": 20,
        "events": [
            ("11:08:15", "clio-ransomware.c2-beacon.io",   75,  "Blocked", "#dc3545"),
            ("11:08:07", "tor-exit-legal.relay.net",       75,  "Blocked", "#dc3545"),
            ("11:07:58", "api.legal-exfil.io",             40,  "Monitor", "#ffc107"),
            ("11:07:44", "privilege-violate.exfil.ru",     40,  "Monitor", "#ffc107"),
            ("11:07:30", "clio.com",                         0,  "Allowed", "#28a745"),
        ],
        "block_score": 75,
        "bd_feed": 40, "bd_yara": 35, "bd_mlp": 0, "bd_burst": 0,
        "compliance_label": "ACP Mode",
    },
    "establishment": {
        "sector_name": "Establishment",
        "subtitle": "Dual-Threshold Policy  ·  Guest WiFi Protection  ·  AI-Powered Behavioral Firewall  ·  v2.2.0",
        "header_fill": "#0a2e1a",
        "header_sub": "#6ee7b7",
        "product_mode": "minifw_establishment",
        "seg1_color": "#10b981",
        "seg2_color": "#f59e0b",
        "seg3_color": "#6b7280",
        "segments": [
            ("Office LAN", "192.168.1.x  block@80  (staff · known devices)"),
            ("POS / DMZ", "10.0.1.x  block@70  (POS terminals · payment infra)"),
            ("Guest WiFi", "172.16.1.x  block@40  (unknown devices · zero-tolerance)"),
        ],
        "yara_desc": "SME rules: ransomware C2 · crypto miner · credential theft",
        "yara_file": "sme_rules.yar",
        "yara_rules_desc": "3 YARA rules · SME tagged",
        "allow_range": "score < 40",
        "monitor_range": "score 40–79 (Office) / 40–69 (POS)",
        "block_range": "score ≥ 80 (Office)  ≥ 40 (Guest)",
        "dashboard_url": "https://localhost:8444   admin / SME_Demo1!",
        "stat_allow": 21, "stat_block": 2, "stat_monitor": 4, "stat_total": 27,
        "events": [
            ("09:00:50", "login-paypal-secure-verify.com",  100,  "Blocked", "#dc3545"),
            ("09:00:40", "login-paypal-secure-verify.com",   40,  "Blocked", "#dc3545"),
            ("09:00:30", "xmrig.c2-miner.io",               75,  "Monitor", "#ffc107"),
            ("09:00:20", "locky-decrypt-files.xyz",          75,  "Monitor", "#ffc107"),
            ("09:00:01", "office365.com",                     0,  "Allowed", "#28a745"),
        ],
        "block_score": 100,
        "bd_feed": 40, "bd_yara": 35, "bd_mlp": 25, "bd_burst": 0,
        "compliance_label": "Guest Policy Engine",
    },
}

TARGETS = {
    "hospital":      "docs/demo-evidence/hospital/report/architecture-hospital.svg",
    "education":     "docs/demo-evidence/education/report/architecture-education.svg",
    "government":    "docs/demo-evidence/government/report/architecture-government.svg",
    "legal":         "docs/demo-evidence/legal/report/architecture-legal.svg",
    "establishment": "docs/demo-evidence/establishment/report/architecture-establishment.svg",
}

for sector, path in TARGETS.items():
    os.makedirs(os.path.dirname(path), exist_ok=True)
    svg = build_svg(SECTORS[sector])
    with open(path, "w") as f:
        f.write(svg)
    print(f"Written: {path}")
