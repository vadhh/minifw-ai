#!/usr/bin/env bash
set -euo pipefail
edition="$1"
[[ "$(hostname)" == "minifw-monday-$edition" ]] || exit 1
[[ "$(systemd-detect-virt)" == kvm || "$(systemd-detect-virt)" == qemu ]] || exit 1
sector=education
mode=minifw_school
if [[ "$edition" == financial ]]; then sector=finance; mode=minifw_financial; fi
source_dir="/home/lab/v2210-c12-candidate/minifw-ai-${edition}-v2.2.10-source-assessment"
cd "$source_dir"
sha256sum -c SHA256SUMS > /var/tmp/minifw-source-verification.log
python3 - <<'PY'
import json
from pathlib import Path
m=json.loads(Path('MANIFEST.json').read_text())
print('VERIFIED_SOURCE', m['version'], m['sector'], m['base_commit'], len(m['files']), 'files')
print('INCLUDED_LOCAL_CHANGES', m['included_local_changes'])
PY
python3 - <<'PY'
from pathlib import Path
for folder in ['scripts', 'systemd']:
 for p in Path(folder).iterdir():
  if p.suffix in {'.sh', '.service'}:
   p.write_bytes(p.read_bytes().replace(b'\r\n', b'\n'))
PY
bash scripts/build_deb.sh "$sector" 2.2.10
deb="$source_dir/build/minifw-ai_2.2.10-${sector}_amd64.deb"
dpkg-deb --field "$deb" Package Version Architecture
sha256sum "$deb"
timedatectl set-timezone Asia/Jakarta
systemctl stop minifw-ai minifw-ai-web dnsmasq
# Retain only cached Python dependencies, not the previous package's configuration/database.
[[ ! -e /var/tmp/minifw-lab-cached-venv ]] || exit 1
mv /opt/minifw_ai/venv /var/tmp/minifw-lab-cached-venv
dpkg --purge minifw-ai
mkdir -p /opt/minifw_ai
mv /var/tmp/minifw-lab-cached-venv /opt/minifw_ai/venv
umask 077
set +e
MINIFW_SECTOR="$sector" PRODUCT_MODE="$mode" dpkg --force-confnew -i "$deb" > /var/tmp/minifw-candidate-install-private.log 2>&1
result=$?
set -e
python3 - <<'PY'
from pathlib import Path
import re
for line in Path('/var/tmp/minifw-candidate-install-private.log').read_text(errors='replace').splitlines():
 print('[credential line redacted]' if re.search(r'password|secret|token', line, re.I) else line)
PY
printf 'nameserver 10.231.0.3\n' > /etc/resolv.conf
systemctl show minifw-ai minifw-ai-web -p ActiveState -p MainPID -p ExecMainStatus
systemctl stop minifw-ai minifw-ai-web dnsmasq
exit "$result"
