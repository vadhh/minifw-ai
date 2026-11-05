"""Check the declared source and every package payload file against its source input."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[3]
DIST = ROOT / "dist/v2210-c16-candidates"
with tarfile.open(DIST / "source.tar.gz") as archive:
    source = {member.name: archive.extractfile(member).read() for member in archive.getmembers() if member.isfile()}
manifest = json.loads(source["SOURCE-IDENTITY.json"])
for name, expected in manifest["files"].items():
    assert hashlib.sha256(source[name]).hexdigest() == expected, name
for name, data in source.items():
    if name == "SOURCE-IDENTITY.json" or name in manifest["inputs"]:
        continue
    original = subprocess.check_output(["git", "show", manifest["base_commit"] + ":" + name], cwd=ROOT)
    if name in manifest["transformations"]["CRLF_to_LF"]:
        original = original.replace(b"\r\n", b"\n")
    assert original == data, ("Undeclared source difference", name)
print("SOURCE_IDENTITY_PASS", manifest["base_commit"], len(manifest["files"]), "files")
for edition, sector, mode in [("education", "education", "minifw_school"), ("financial", "finance", "minifw_financial")]:
    package = DIST / edition / f"minifw-ai_2.2.10-{sector}_amd64.deb"
    assert subprocess.check_output(["dpkg-deb", "-f", str(package), "Version"], text=True).strip() == "2.2.10-" + sector
    payload = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(package)])
    checked = 0
    with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
        for member in archive.getmembers():
            assert member.uid == member.gid == 0, member.name
            if not member.isfile():
                continue
            name = member.name.removeprefix("./")
            data = archive.extractfile(member).read()
            if name.startswith("opt/minifw_ai/"):
                relative = name.removeprefix("opt/minifw_ai/")
                assert data == source[relative], relative
            elif name.startswith("etc/systemd/system/"):
                text = data.decode()
                assert f"Environment=MINIFW_POLICY=/opt/minifw_ai/config/modes/{mode}/policy.json" in text
                assert f"Environment=PRODUCT_MODE={mode}" in text
                assert "User=minifw-web" in text if "-web.service" in name else "User=root" in text
            else:
                assert name == "etc/logrotate.d/minifw-ai", name
                assert data == source["scripts/minifw-ai.logrotate"]
            checked += 1
    print("PAYLOAD_SOURCE_MATCH_ROOT_OWNERSHIP", edition, checked, hashlib.sha256(package.read_bytes()).hexdigest())
