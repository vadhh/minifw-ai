#!/usr/bin/env python3
"""Generate docs/architecture-all-sectors.svg — MiniFW-AI sector overview diagram."""

import xml.etree.ElementTree as ET

W, H = 1400, 900

def svg_root():
    root = ET.Element("svg", xmlns="http://www.w3.org/2000/svg",
                       width=str(W), height=str(H), viewBox=f"0 0 {W} {H}")
    defs = ET.SubElement(root, "defs")
    # Gradient background
    lg = ET.SubElement(defs, "linearGradient", id="bg", x1="0", y1="0", x2="0", y2="1")
    ET.SubElement(lg, "stop", offset="0%", style="stop-color:#0d1117")
    ET.SubElement(lg, "stop", offset="100%", style="stop-color:#161b22")
    # Drop shadow filter
    flt = ET.SubElement(defs, "filter", id="shadow", x="-5%", y="-5%", width="110%", height="110%")
    ET.SubElement(flt, "feDropShadow", dx="2", dy="3", stdDeviation="4",
                  **{"flood-color": "#000000", "flood-opacity": "0.5"})
    return root

def rect(parent, x, y, w, h, rx="8", fill="#1f2937", stroke="#374151", sw="1.5", **kw):
    ET.SubElement(parent, "rect", x=str(x), y=str(y), width=str(w), height=str(h),
                  rx=rx, fill=fill, stroke=stroke,
                  **{"stroke-width": sw}, **kw)

def text(parent, x, y, content, size=14, fill="#f9fafb", weight="normal", anchor="middle", **kw):
    t = ET.SubElement(parent, "text", x=str(x), y=str(y),
                      **{"font-family": "monospace, Courier New",
                         "font-size": str(size),
                         "font-weight": weight,
                         "fill": fill,
                         "text-anchor": anchor}, **kw)
    t.text = content

def line(parent, x1, y1, x2, y2, stroke="#4b5563", sw="1.5", dash=""):
    attrs = {"x1": str(x1), "y1": str(y1), "x2": str(x2), "y2": str(y2),
             "stroke": stroke, "stroke-width": sw}
    if dash:
        attrs["stroke-dasharray"] = dash
    ET.SubElement(parent, "line", **attrs)

def arrow(parent, x1, y1, x2, y2, stroke="#6b7280", sw="1.5"):
    # Simple arrow line (arrowhead via marker would need defs — just draw line)
    line(parent, x1, y1, x2, y2, stroke=stroke, sw=sw)
    # Small arrowhead triangle approximation
    ET.SubElement(parent, "polygon",
                  points=f"{x2},{y2} {x2-6},{y2-4} {x2-6},{y2+4}",
                  fill=stroke)

root = svg_root()

# Background
ET.SubElement(root, "rect", x="0", y="0", width=str(W), height=str(H),
              fill="url(#bg)")

# Title
text(root, W//2, 42, "MiniFW-AI — Sector Deployment Overview", size=22,
     weight="bold", fill="#e5e7eb")
text(root, W//2, 68, "v2.2.0  ·  6 Sectors  ·  Behavioral DNS Firewall Engine", size=13,
     fill="#6b7280")

# ── Core Engine Box (center top) ──────────────────────────────────────────
EX, EY, EW, EH = 490, 95, 420, 130
rect(root, EX, EY, EW, EH, rx="10", fill="#1e3a5f", stroke="#3b82f6", sw="2",
     filter="url(#shadow)")
text(root, EX + EW//2, EY + 26, "MiniFW-AI Core Engine", size=16,
     weight="bold", fill="#93c5fd")
text(root, EX + EW//2, EY + 50, "DNS event → Feed Matcher → Burst Tracker", size=11, fill="#9ca3af")
text(root, EX + EW//2, EY + 67, "→ Hard Gates → MLP Detector → YARA Scanner", size=11, fill="#9ca3af")
text(root, EX + EW//2, EY + 84, "→ score_and_decide() → nftables enforce", size=11, fill="#9ca3af")
text(root, EX + EW//2, EY + 104, "Score weights: feed+40  TLS+35  ASN+15  burst+10  MLP+30  YARA+35", size=10, fill="#6b7280")

# ── Policy Layer ──────────────────────────────────────────────────────────
PY = 255
rect(root, 490, PY, 420, 36, rx="6", fill="#1a2e1a", stroke="#22c55e", sw="1.5")
text(root, 700, PY + 23, "policy.json  — per-segment block/monitor thresholds", size=12,
     fill="#86efac", weight="bold")

# Connector: engine → policy
line(root, 700, EY + EH, 700, PY, stroke="#3b82f6", sw="1.5", dash="4 3")

# ── Sector cards ──────────────────────────────────────────────────────────
# 3 top row + 3 bottom row, centred under the engine/policy stack
SECTORS = [
    # name, accent_color, port, package_type, key_thresholds, trace_prefix
    ("Hospital",      "#ef4444", "8000 / 8443", "Standalone + Docker",
     "mednet:45  internal:80  iomt:85", "HIPAA-PHI-*"),
    ("Education",     "#f59e0b", "8447",         "Docker",
     "student:70  guest:60  staff:80", "EDU-SAFE-*"),
    ("Government",    "#8b5cf6", "8449",         "Docker",
     "classified:70  internal:45  guest:35", "GOV-SOV-*"),
    ("Legal",         "#0ea5e9", "8448",         "Docker",
     "partner:85  associate:72  client:62", "LEGAL-ACP-*"),
    ("Establishment", "#10b981", "8444",         "Docker",
     "office:80  DMZ:70  guest:40", "SME-EST-*"),
    ("Finance",       "#f97316", "8443 (HTTPS)", "Standalone",
     "trading:85  teller:70  ATM:60", "SWIFT-MT103-*"),
]

CARD_W, CARD_H = 390, 145
COLS = 3
GAP_X, GAP_Y = 30, 28
START_X = (W - COLS * CARD_W - (COLS - 1) * GAP_X) // 2
START_Y = 325

for i, (name, color, port, pkg_type, thresholds, trace) in enumerate(SECTORS):
    col = i % COLS
    row = i // COLS
    cx = START_X + col * (CARD_W + GAP_X)
    cy = START_Y + row * (CARD_H + GAP_Y)

    # Card background
    rect(root, cx, cy, CARD_W, CARD_H, rx="8",
         fill="#111827", stroke=color, sw="2", filter="url(#shadow)")

    # Colour accent bar
    rect(root, cx, cy, CARD_W, 6, rx="0", fill=color, stroke=color, sw="0")

    # Sector name
    text(root, cx + CARD_W//2, cy + 28, f"{name} Sector", size=15,
         weight="bold", fill=color)

    # Port + package type
    text(root, cx + CARD_W//2, cy + 48,
         f"Port {port}  ·  {pkg_type}", size=11, fill="#d1d5db")

    # Thresholds
    text(root, cx + CARD_W//2, cy + 68, "Block thresholds:", size=10, fill="#6b7280")
    text(root, cx + CARD_W//2, cy + 84, thresholds, size=10, fill="#9ca3af")

    # Trace ID format
    text(root, cx + CARD_W//2, cy + 104, f"Trace: {trace}", size=10, fill="#6b7280")

    # Credentials hint
    cred_map = {
        "Hospital": "admin / Hospital1!",
        "Education": "admin / Education1!",
        "Government": "admin / Government1!",
        "Legal": "admin / Legal1!",
        "Establishment": "admin / SME_Demo1!",
        "Finance": "admin / Finance1!",
    }
    text(root, cx + CARD_W//2, cy + 123, cred_map[name], size=10, fill="#4b5563")

    # Connector from policy bar to top of card (only if card top row)
    if row == 0:
        mid_cx = cx + CARD_W // 2
        line(root, mid_cx, PY + 36, mid_cx, cy, stroke=color, sw="1", dash="3 3")
    # Second row: connect from first row card bottom (skip for simplicity — draw bracket line)
    if row == 1:
        mid_cx = cx + CARD_W // 2
        # Horizontal line from policy area centre down to a bracket, then down to card
        bx = 700  # policy centre x
        bracket_y = START_Y + CARD_H + GAP_Y // 2
        line(root, mid_cx, bracket_y, mid_cx, cy, stroke=color, sw="1", dash="3 3")

# Horizontal bracket for second row
bracket_y2 = START_Y + CARD_H + GAP_Y // 2
lx = START_X + CARD_W // 2
rx_ = START_X + 2 * (CARD_W + GAP_X) + CARD_W // 2
line(root, lx, bracket_y2, rx_, bracket_y2, stroke="#374151", sw="1", dash="3 3")
line(root, 700, PY + 36, 700, bracket_y2, stroke="#374151", sw="1", dash="3 3")

# ── Legend ──────────────────────────────────────────────────────────────
LX, LY = 30, H - 95
rect(root, LX, LY, 310, 80, rx="6", fill="#111827", stroke="#374151", sw="1")
text(root, LX + 10, LY + 18, "Legend", size=12, weight="bold", fill="#9ca3af", anchor="start")
text(root, LX + 10, LY + 36, "Standalone = Python venv, no Docker required", size=10, fill="#6b7280", anchor="start")
text(root, LX + 10, LY + 52, "Docker = Docker Compose + prebuilt image tar", size=10, fill="#6b7280", anchor="start")
text(root, LX + 10, LY + 68, "Thresholds = per-segment block score (0–100)", size=10, fill="#6b7280", anchor="start")

# ── Enforcement note ──────────────────────────────────────────────────────
NX = W - 320
rect(root, NX, LY, 290, 80, rx="6", fill="#111827", stroke="#374151", sw="1")
text(root, NX + 10, LY + 18, "Enforcement", size=12, weight="bold", fill="#9ca3af", anchor="start")
text(root, NX + 10, LY + 36, "ALLOW  → pass, no log entry", size=10, fill="#6b7280", anchor="start")
text(root, NX + 10, LY + 52, "MONITOR → log event, no block (below threshold)", size=10, fill="#6b7280", anchor="start")
text(root, NX + 10, LY + 68, "BLOCK  → ipset + nftables DROP, JSONL audit log", size=10, fill="#6b7280", anchor="start")

# Watermark
text(root, W//2, H - 12, "MiniFW-AI  v2.2.0  |  2026-05-26  |  vadhh",
     size=10, fill="#374151")

# ── Write file ───────────────────────────────────────────────────────────
tree = ET.ElementTree(root)
ET.indent(tree, space="  ")
out = "/home/sydeco/minifw-ai/docs/architecture-all-sectors.svg"
tree.write(out, xml_declaration=True, encoding="unicode")
print(f"Written: {out}")
