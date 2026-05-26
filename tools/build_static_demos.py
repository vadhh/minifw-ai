#!/usr/bin/env python3
"""Build static HTML demo pages for each minifw-ai sector dist package."""

from pathlib import Path
import json
import shutil

REPO_ROOT = Path(__file__).parent.parent

SECTORS = {
    "financial": {
        "dist_path": REPO_ROOT / "dist/minifw-usb-financial-standalone-v2.2.0",
        "evidence_path": REPO_ROOT / "docs/demo-evidence/financial",
        "product_name": "MINIFW-AI_FINANCIAL",
        "tagline": "PCI-DSS / Trading Floor Protection",
        "accent": "#1a3a5c",
        "accent_light": "#2a5a9c",
    },
    "hospital": {
        "dist_path": REPO_ROOT / "dist/minifw-usb-hospital-standalone-v2.2.0",
        "evidence_path": REPO_ROOT / "docs/demo-evidence/hospital",
        "product_name": "MINIFW-AI_HEALTHCARE",
        "tagline": "HIPAA / IoMT Protection",
        "accent": "#0d6b6b",
        "accent_light": "#1a9a9a",
    },
    "education": {
        "dist_path": REPO_ROOT / "dist/minifw-usb-education-v2.2.0",
        "evidence_path": REPO_ROOT / "docs/demo-evidence/education",
        "product_name": "MINIFW-AI_SCHOOLS",
        "tagline": "SafeSearch / Student Network Protection",
        "accent": "#b45309",
        "accent_light": "#d97706",
    },
    "legal": {
        "dist_path": REPO_ROOT / "dist/minifw-usb-legal-v2.2.0",
        "evidence_path": REPO_ROOT / "docs/demo-evidence/legal",
        "product_name": "MINIFW-AI_LEGAL",
        "tagline": "Attorney-Client Privilege Protection",
        "accent": "#1e3a5f",
        "accent_light": "#2e5a8f",
    },
}

VERSION = "v2.2.0"
GPG_KEY = "BDB471E1FB46F58A"


def caption_from_filename(filename: str) -> str:
    """Derive a human-readable caption from a screenshot filename."""
    stem = Path(filename).stem
    # Strip leading index number (e.g. "01-", "08-")
    parts = stem.split("-", 1)
    text = parts[1] if len(parts) == 2 and parts[0].isdigit() else stem
    # Replace dashes and underscores with spaces, title-case
    return text.replace("-", " ").replace("_", " ").title()


def render_html(
    cfg: dict,
    screenshots: list,        # list of (relative_filename, caption) tuples
    block_events: list,        # list of parsed event dicts
    has_arch_svg: bool,
    version: str,
    gpg_key: str,
) -> str:
    accent = cfg["accent"]
    accent_light = cfg["accent_light"]
    product_name = cfg["product_name"]
    tagline = cfg["tagline"]

    # --- screenshots section ---
    screenshots_html = ""
    if screenshots:
        items = ""
        for filename, caption in screenshots:
            items += f"""
        <div class="screenshot-item">
          <img src="screenshots/{filename}" alt="{caption}" loading="lazy">
          <p class="caption">{caption}</p>
        </div>"""
        screenshots_html = f"""
    <section>
      <h2>DEMO WALKTHROUGH</h2>
      <div class="screenshot-grid">{items}
      </div>
    </section>"""

    # --- architecture section ---
    arch_html = ""
    if has_arch_svg:
        arch_html = """
    <section>
      <h2>ARCHITECTURE</h2>
      <img src="architecture.svg" alt="System Architecture" class="arch-svg">
    </section>"""

    # --- block events table ---
    def action_class(action: str) -> str:
        return {"block": "action-block", "monitor": "action-monitor", "allow": "action-allow"}.get(
            action.lower(), ""
        )

    rows = ""
    for ev in block_events:
        ts = ev.get("ts", "")[:19].replace("T", " ")
        segment = ev.get("segment", "—")
        domain = ev.get("domain", "—")
        score = ev.get("score", "—")
        action = ev.get("action", "—")
        cls = action_class(action)
        rows += f"""
        <tr>
          <td class="mono">{ts}</td>
          <td>{segment}</td>
          <td class="mono">{domain}</td>
          <td class="score">{score}</td>
          <td class="{cls}">{action.upper()}</td>
        </tr>"""

    events_html = f"""
    <section>
      <h2>BLOCK EVENT LOG</h2>
      <table>
        <thead>
          <tr><th>Timestamp</th><th>Segment</th><th>Domain</th><th>Score</th><th>Action</th></tr>
        </thead>
        <tbody>{rows}
        </tbody>
      </table>
    </section>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{product_name} — Static Demo</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: #0f1117;
      color: #e2e8f0;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 15px;
      line-height: 1.6;
    }}
    header {{
      background: {accent};
      border-bottom: 3px solid {accent_light};
      padding: 2rem 2.5rem;
    }}
    header h1 {{
      font-size: 1.8rem;
      font-weight: 700;
      letter-spacing: 0.05em;
      color: #fff;
    }}
    header .tagline {{
      color: rgba(255,255,255,0.75);
      font-size: 0.95rem;
      margin-top: 0.25rem;
    }}
    header .badge {{
      display: inline-block;
      background: {accent_light};
      color: #fff;
      font-size: 0.75rem;
      font-weight: 600;
      padding: 0.2rem 0.6rem;
      border-radius: 4px;
      margin-top: 0.5rem;
      letter-spacing: 0.08em;
    }}
    main {{ max-width: 1200px; margin: 0 auto; padding: 2rem 2.5rem; }}
    section {{ margin-bottom: 3rem; }}
    h2 {{
      font-size: 0.75rem;
      font-weight: 700;
      letter-spacing: 0.15em;
      color: {accent_light};
      text-transform: uppercase;
      border-bottom: 1px solid #1e2535;
      padding-bottom: 0.5rem;
      margin-bottom: 1.5rem;
    }}
    .arch-svg {{ width: 100%; max-width: 900px; display: block; margin: 0 auto; }}
    .screenshot-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(480px, 1fr));
      gap: 1.5rem;
    }}
    .screenshot-item img {{
      width: 100%;
      border: 1px solid #1e2535;
      border-radius: 6px;
      display: block;
    }}
    .caption {{
      font-size: 0.82rem;
      color: #94a3b8;
      margin-top: 0.5rem;
      text-align: center;
    }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
    th {{
      text-align: left;
      padding: 0.5rem 0.75rem;
      background: #1a1f2e;
      color: #64748b;
      font-size: 0.75rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      border-bottom: 1px solid #1e2535;
    }}
    td {{
      padding: 0.5rem 0.75rem;
      border-bottom: 1px solid #1a1f2e;
      color: #cbd5e1;
    }}
    tr:hover td {{ background: #131825; }}
    .mono {{ font-family: 'Courier New', monospace; font-size: 0.82rem; }}
    .score {{ font-weight: 700; color: #e2e8f0; text-align: right; }}
    .action-block {{ color: #f87171; font-weight: 700; }}
    .action-monitor {{ color: #fbbf24; font-weight: 600; }}
    .action-allow {{ color: #34d399; }}
    footer {{
      border-top: 1px solid #1e2535;
      padding: 1.5rem 2.5rem;
      font-size: 0.78rem;
      color: #475569;
      display: flex;
      gap: 2rem;
      flex-wrap: wrap;
    }}
  </style>
</head>
<body>
  <header>
    <h1>{product_name}</h1>
    <div class="tagline">{tagline}</div>
    <div class="badge">{version} · STATIC DEMO</div>
  </header>
  <main>
    {arch_html}
    {screenshots_html}
    {events_html}
  </main>
  <footer>
    <span>Sector lock: {cfg.get("sector_lock_name", product_name.lower())}</span>
    <span>Version: {version}</span>
    <span>GPG: {gpg_key}</span>
  </footer>
</body>
</html>"""


def load_block_events(evidence_path: Path) -> list:
    events_file = evidence_path / "logs/block-events.jsonl"
    if not events_file.exists():
        return []
    events = []
    for line in events_file.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return events


def collect_screenshots(evidence_path: Path) -> list:
    """Return sorted list of (filename, caption) tuples for available PNGs."""
    screenshots_dir = evidence_path / "screenshots"
    if not screenshots_dir.exists():
        return []
    pngs = sorted(
        p for p in screenshots_dir.iterdir()
        if p.suffix.lower() == ".png"
    )
    result = []
    for p in pngs:
        caption = caption_from_filename(p.name)
        result.append((p.name, caption))
    return result


def build_sector(sector: str, cfg: dict):
    static_dir = cfg["dist_path"] / "static"
    static_dir.mkdir(parents=True, exist_ok=True)

    evidence_path = cfg["evidence_path"]

    # Copy architecture SVG
    svg_src = evidence_path / f"report/architecture-{sector}.svg"
    has_arch_svg = svg_src.exists()
    if has_arch_svg:
        shutil.copy2(svg_src, static_dir / "architecture.svg")

    # Collect and copy screenshots
    screenshots = collect_screenshots(evidence_path)
    if screenshots:
        dest_screenshots = static_dir / "screenshots"
        dest_screenshots.mkdir(exist_ok=True)
        src_screenshots = evidence_path / "screenshots"
        for filename, _ in screenshots:
            shutil.copy2(src_screenshots / filename, dest_screenshots / filename)

    # Load block events
    block_events = load_block_events(evidence_path)

    # Add sector_lock_name to cfg for footer
    sector_lock_map = {
        "financial": "minifw_financial",
        "hospital": "minifw_hospital",
        "education": "minifw_school",
        "legal": "minifw_legal",
    }
    cfg["sector_lock_name"] = sector_lock_map.get(sector, sector)

    html = render_html(
        cfg=cfg,
        screenshots=screenshots,
        block_events=block_events,
        has_arch_svg=has_arch_svg,
        version=VERSION,
        gpg_key=GPG_KEY,
    )

    (static_dir / "index.html").write_text(html, encoding="utf-8")


def build_all():
    for sector, cfg in SECTORS.items():
        print(f"Building {cfg['product_name']}...")
        build_sector(sector, cfg)
        print(f"  → {cfg['dist_path']}/static/index.html")


if __name__ == "__main__":
    build_all()
