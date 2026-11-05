"""Packaged systemd units must not be rewritten by postinst (dpkg --verify must stay clean)."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_engine_unit_ships_environment_file():
    for unit in ("minifw-ai.service", "minifw-ai-web.service"):
        text = (ROOT / "systemd" / unit).read_text()
        assert "EnvironmentFile=/etc/minifw/minifw.env" in text, unit


def test_postinst_does_not_edit_packaged_units():
    build = (ROOT / "scripts" / "build_deb.sh").read_text()
    postinst = build.split("DEBIAN/postinst", 1)[1].split("POSTINST", 2)[1]
    assert not re.search(r"sed -i[^\n]*\n?[^\n]*/etc/systemd/system/minifw-ai", postinst)
