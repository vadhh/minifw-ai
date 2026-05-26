"""Tests for tools/build_static_demos.py"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from tools.build_static_demos import SECTORS, VERSION, GPG_KEY, build_sector, render_html


def test_sectors_have_required_keys():
    required = {"dist_path", "evidence_path", "product_name", "tagline", "accent", "accent_light"}
    for name, cfg in SECTORS.items():
        missing = required - set(cfg.keys())
        assert not missing, f"Sector '{name}' missing keys: {missing}"


def test_render_html_contains_product_name():
    cfg = SECTORS["financial"]
    html = render_html(
        cfg=cfg,
        screenshots=[],
        block_events=[],
        has_arch_svg=False,
        version=VERSION,
        gpg_key=GPG_KEY,
    )
    assert "MINIFW-AI_FINANCIAL" in html


def test_render_html_contains_tagline():
    cfg = SECTORS["financial"]
    html = render_html(
        cfg=cfg,
        screenshots=[],
        block_events=[],
        has_arch_svg=False,
        version=VERSION,
        gpg_key=GPG_KEY,
    )
    assert "PCI-DSS / Trading Floor Protection" in html


def test_render_html_contains_version():
    cfg = SECTORS["legal"]
    html = render_html(
        cfg=cfg,
        screenshots=[],
        block_events=[],
        has_arch_svg=False,
        version=VERSION,
        gpg_key=GPG_KEY,
    )
    assert VERSION in html


def test_render_html_with_block_events_renders_table():
    cfg = SECTORS["legal"]
    events = [
        {
            "ts": "2026-05-26T09:00:25",
            "segment": "client",
            "client_ip": "192.168.200.5",
            "domain": "tor-exit-relay.onion-gw.net",
            "action": "block",
            "score": 75,
        }
    ]
    html = render_html(
        cfg=cfg,
        screenshots=[],
        block_events=events,
        has_arch_svg=False,
        version=VERSION,
        gpg_key=GPG_KEY,
    )
    assert "tor-exit-relay.onion-gw.net" in html
    assert "75" in html


def test_render_html_block_action_has_red_class():
    cfg = SECTORS["legal"]
    events = [
        {
            "ts": "2026-05-26T09:00:25",
            "segment": "client",
            "client_ip": "192.168.200.5",
            "domain": "bad.example.com",
            "action": "block",
            "score": 75,
        }
    ]
    html = render_html(
        cfg=cfg,
        screenshots=[],
        block_events=events,
        has_arch_svg=False,
        version=VERSION,
        gpg_key=GPG_KEY,
    )
    assert 'action-block' in html


def test_render_html_screenshot_section_absent_when_no_screenshots():
    cfg = SECTORS["hospital"]
    html = render_html(
        cfg=cfg,
        screenshots=[],
        block_events=[],
        has_arch_svg=False,
        version=VERSION,
        gpg_key=GPG_KEY,
    )
    assert "DEMO WALKTHROUGH" not in html


def test_render_html_screenshot_section_present_when_screenshots():
    cfg = SECTORS["financial"]
    screenshots = [("01-dashboard-clean-baseline.png", "Dashboard clean baseline")]
    html = render_html(
        cfg=cfg,
        screenshots=screenshots,
        block_events=[],
        has_arch_svg=False,
        version=VERSION,
        gpg_key=GPG_KEY,
    )
    assert "DEMO WALKTHROUGH" in html
    assert "Dashboard clean baseline" in html
