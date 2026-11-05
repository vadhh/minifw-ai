"""Read-only verification of the exact separately tested Monday candidates."""

import hashlib
import io
import json
import subprocess
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BASE = "2bae0856c99b0789f7f2848d460999bc83a3a1c4"


def sha(data):
    return hashlib.sha256(data).hexdigest()


for edition, sector in [("education", "education"), ("financial", "finance")]:
    folder = ROOT / "dist/monday-corrections"
    source = folder / f"minifw-ai-{edition}-v2.2.10-source-assessment.zip"
    package = folder / edition / f"minifw-ai_2.2.10-{sector}_amd64.deb"
    print("ARTIFACT", sha(source.read_bytes()), source.relative_to(ROOT))
    print("ARTIFACT", sha(package.read_bytes()), package.relative_to(ROOT))
    with zipfile.ZipFile(source) as archive:
        assert archive.testzip() is None
        prefix = source.stem + "/"
        manifest = json.loads(archive.read(prefix + "MANIFEST.json"))
        assert manifest["base_commit"] == BASE
        assert manifest["sector"] == sector
        compared = 0
        for name, expected in manifest["files"].items():
            content = archive.read(prefix + name)
            assert sha(content) == expected, name
            original = ROOT / name
            if original.is_file():
                current = original.read_bytes()
                if name in manifest["normalized_lf_files"]:
                    current = current.replace(b"\r\n", b"\n")
                assert current == content, name
                compared += 1
        print("SOURCE_VERIFIED", edition, BASE, len(manifest["files"]), "hashes", compared, "repository comparisons")
    metadata = subprocess.check_output(["dpkg-deb", "--field", str(package)], text=True)
    assert "Package: minifw-ai\n" in metadata
    assert f"Version: 2.2.10-{sector}\n" in metadata
    assert "Architecture: amd64\n" in metadata
    payload = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(package)])
    with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
        members = archive.getmembers()
        assert all(member.uid == member.gid == 0 for member in members)
        checked = 0
        for name in ["main.py", "collector_flow.py", "collector_runtime.py", "collector_dnsmasq.py",
                     "collector_zeek.py", "enforce.py", "feeds.py", "utils/mlp_engine.py"]:
            relative = "app/minifw_ai/" + name
            content = archive.extractfile("./opt/minifw_ai/" + relative).read()
            committed = subprocess.check_output(["git", "show", BASE + ":" + relative], cwd=ROOT)
            assert content == committed, relative
            checked += 1
        model = archive.extractfile("./opt/minifw_ai/models/mlp_model.pkl").read()
        assert model == (ROOT / "models/mlp_model.pkl").read_bytes()
        service = archive.extractfile("./etc/systemd/system/minifw-ai.service").read().decode()
        assert f"MINIFW_SECTOR={sector}" in service
        print("PACKAGE_VERIFIED", edition, "root-owned entries", len(members), "committed core files", checked,
              "model", sha(model))
print("PASS: artifact identity and integrity; operational acceptance is separate")
