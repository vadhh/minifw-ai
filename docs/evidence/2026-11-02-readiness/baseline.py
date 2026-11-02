"""Read-only provenance audit. Run from the repository with Python 3."""

import hashlib
import importlib.util
import io
import json
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if "--save" in sys.argv:
    sys.stdout = (Path(__file__).parent / "baseline.log").open("w")
    sys.stderr = sys.stdout


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


print("OBSERVED_UTC", datetime.now(timezone.utc).isoformat())
print("HOST", platform.platform(), "PYTHON", sys.version.split()[0])
print("REPO", git("remote", "get-url", "origin"))
print("BRANCH", git("branch", "--show-current"), "HEAD", git("rev-parse", "HEAD"))
print("WORKTREE\n" + git("status", "--short"))
print("TRACKED_DIFF\n" + git("diff", "--stat"))
for tool in ["python3", "uv", "pytest", "nft", "dpkg-deb", "docker", "systemctl"]:
    print("TOOL", tool, shutil.which(tool))
for mod in ["pytest", "numpy", "pandas", "sklearn", "yara"]:
    print("MODULE", mod, bool(importlib.util.find_spec(mod)))
for directory in [ROOT / "build", ROOT / "dist"]:
    print("STANDALONE_DEBS", str(directory.relative_to(ROOT)),
          [str(p.relative_to(ROOT)) for p in directory.rglob("*.deb")])

for artifact in sorted((ROOT / "dist/production-assessment").glob("*.zip")):
    print("\nARCHIVE", artifact.name, "SHA256", sha(artifact.read_bytes()))
    with zipfile.ZipFile(artifact) as z:
        print("ZIP_CRC", z.testzip())
        build_manifests = [json.loads(z.read(n)) for n in z.namelist() if n.endswith("BUILD_MANIFEST.json")]
        for name in z.namelist():
            if name.endswith(".deb"):
                data = z.read(name)
                print("NESTED_DEB", name, "SHA256", sha(data))
                if shutil.which("dpkg-deb"):
                    with tempfile.NamedTemporaryFile(suffix=".deb") as deb:
                        deb.write(data)
                        deb.flush()
                        result = subprocess.run(
                            ["dpkg-deb", "--field", deb.name, "Package", "Version", "Architecture"],
                            text=True, capture_output=True, check=False,
                        )
                        print("DEB_METADATA", result.returncode, result.stdout.strip(), result.stderr.strip())
                        for build_manifest in build_manifests:
                            print("DEB_SHA_MATCHES_MANIFEST", sha(data) == build_manifest["deb_sha256"])
                            payload = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", deb.name])
                            with tarfile.open(fileobj=io.BytesIO(payload)) as tar:
                                actual = {m.name.removeprefix("./"): sha(tar.extractfile(m).read())
                                          for m in tar.getmembers() if m.isfile()}
                            expected = build_manifest.get("installed_files_sha256", {})
                            print("INSTALLED_PAYLOAD_HASHES", len(expected), "MISMATCHES",
                                  [p for p, h in expected.items() if actual.get(p) != h])
            if name.endswith(("MANIFEST.json", "BUILD_MANIFEST.json")):
                manifest = json.loads(z.read(name))
                print("MANIFEST", name, json.dumps({
                    k: v for k, v in manifest.items() if k not in {"files", "installed_files_sha256"}
                }, sort_keys=True))
                if isinstance(manifest.get("files"), dict):
                    prefix = name.rsplit("/", 1)[0] + "/"
                    bad_archive, bad_worktree, checked = [], [], 0
                    for relative, expected in manifest["files"].items():
                        member = prefix + relative
                        if not build_manifests and (member not in z.namelist() or sha(z.read(member)) != expected):
                            bad_archive.append(relative)
                        current = ROOT / relative
                        if current.is_file():
                            data = current.read_bytes()
                            if relative in manifest.get("normalized_lf_files", []):
                                data = data.replace(b"\r\n", b"\n")
                            checked += 1
                            if sha(data) != expected:
                                bad_worktree.append(relative)
                    print("MANIFEST_HASHES", len(manifest["files"]), "ARCHIVE_MISMATCHES", bad_archive)
                    if build_manifests:
                        print("SOURCE_MANIFEST_NOTE source files are provenance, not embedded ZIP members; Debian payload checked separately")
                    print("CURRENT_REPO_COMPARISONS", checked, "MISMATCHES", bad_worktree)
                    for relative in ["app/minifw_ai/main.py", "app/minifw_ai/collector_flow.py",
                                     "app/minifw_ai/enforce.py", "models/mlp_model.pkl"]:
                        if relative in manifest["files"]:
                            base = subprocess.check_output(["git", "show", "HEAD:" + relative], cwd=ROOT)
                            print("UNCHANGED_FROM_HEAD", relative, sha(base) == manifest["files"][relative])

print("\nEXISTING_TMP_PYTHONS", [str(p) for p in Path('/private/tmp').glob('*/*/python*')
      if p.parent.name == 'bin'])
