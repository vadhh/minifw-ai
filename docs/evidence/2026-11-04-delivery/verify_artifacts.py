"""Verify C18 source provenance and every Debian payload against its declared input."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[3]
DIST = ROOT / "dist/v2210-c18-candidates"
def read_source(path):
    with tarfile.open(path) as archive:
        return {m.name: archive.extractfile(m).read() for m in archive.getmembers() if m.isfile()}

source = read_source(DIST / "source.tar.gz")
manifest = json.loads(source["SOURCE-IDENTITY.json"])
parent = ROOT / "dist/v2210-c16-candidates/source.tar.gz"
assert hashlib.sha256(parent.read_bytes()).hexdigest() == manifest["parent_source_sha256"]
previous = read_source(parent)
previous_manifest = json.loads(previous["SOURCE-IDENTITY.json"])
assert manifest["c16_inputs"] == previous_manifest["inputs"]
assert set(source) == set(manifest["files"]) | {"SOURCE-IDENTITY.json"}
for name, expected in manifest["files"].items():
    assert hashlib.sha256(source[name]).hexdigest() == expected, name
    if name not in manifest["wednesday_inputs"]:
        assert source[name] == previous[name], ("undeclared difference", name)
for name, expected in manifest["inputs"].items():
    if name in manifest["wednesday_inputs"]:
        assert hashlib.sha256(source[name]).hexdigest() == expected, ("input hash", name)
    else:
        # C16 input hashes precede its declared CRLF-to-LF transformations.
        assert expected == previous_manifest["inputs"][name], ("parent input hash", name)
print("SOURCE_PROVENANCE_PASS", manifest["candidate"], len(manifest["files"]), "files")
for edition, sector, mode in [("education", "education", "minifw_school"), ("financial", "finance", "minifw_financial")]:
    package = DIST / f"minifw-ai_2.2.10-{sector}_amd64.deb"
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
                assert data == source[name.removeprefix("opt/minifw_ai/")], name
            elif name in {"etc/systemd/system/minifw-ai-apply.path", "etc/systemd/system/minifw-ai-apply.service"}:
                assert data == source["systemd/" + Path(name).name]
            elif name.startswith("etc/systemd/system/"):
                text = source["systemd/" + Path(name).name].decode()
                if name.endswith("minifw-ai-web.service"):
                    text = text.replace("Environment=PYTHONPATH=/opt/minifw_ai/app\n",
                                        f"Environment=PYTHONPATH=/opt/minifw_ai/app\nEnvironment=MINIFW_SECTOR={sector}\nEnvironment=PRODUCT_MODE={mode}\n")
                else:
                    text = text.replace("Environment=MINIFW_SECTOR=establishment", f"Environment=MINIFW_SECTOR={sector}\nEnvironment=PRODUCT_MODE={mode}")
                text = text.replace("Environment=MINIFW_POLICY=/opt/minifw_ai/config/policy.json",
                                    f"Environment=MINIFW_POLICY=/opt/minifw_ai/config/modes/{mode}/policy.json")
                assert data.decode() == text, name
            else:
                assert name == "etc/logrotate.d/minifw-ai", name
                assert data == source["scripts/minifw-ai.logrotate"]
            checked += 1
    print("PAYLOAD_SOURCE_ROOT_OWNERSHIP_PASS", edition, checked, hashlib.sha256(package.read_bytes()).hexdigest())
