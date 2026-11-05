"""Read-only strict identity gate for the C14 v2.2.10 candidates (no unit-file allowance)."""
import hashlib
import io
import socket
import subprocess
import sys
import tarfile
from pathlib import Path

edition, package = sys.argv[1:]
assert edition in {'education', 'financial'}
assert socket.gethostname() == 'minifw-monday-' + edition
sector = 'finance' if edition == 'financial' else 'education'
expected_version = '2.2.10-' + sector
expected_hash = {'education': 'f43f87c393c65a2eaabe08c37f831262ad425c6e069f4e74328719b5cd37754d',
                 'financial': 'eac5a56af3ce1b0c0aecad52ac7e1465b418049dd8446d5143763592e0b7b53c'}[edition]
actual_hash = hashlib.sha256(Path(package).read_bytes()).hexdigest()
assert actual_hash == expected_hash, 'Wrong candidate package hash'
installed = subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', 'minifw-ai'], text=True).strip()
assert installed == expected_version, ('Wrong installed version', installed)
for field, expected in [('Package', 'minifw-ai'), ('Version', expected_version), ('Architecture', 'amd64')]:
    actual = subprocess.check_output(['dpkg-deb', '-f', package, field], text=True).strip()
    assert actual == expected, (field, actual)
print('V2210_IDENTITY_GATE_PASS', socket.gethostname(), installed, actual_hash, flush=True)
payload = subprocess.check_output(['dpkg-deb', '--fsys-tarfile', package])
matched = 0
with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
    for member in archive.getmembers():
        name = member.name.removeprefix('./')
        if member.isfile() and (name.startswith('opt/minifw_ai/app/') or name.startswith('opt/minifw_ai/models/')
                                or name.startswith('opt/minifw_ai/config/modes/') or name.startswith('opt/minifw_ai/scripts/')
                                or name in {'etc/systemd/system/minifw-ai.service', 'etc/systemd/system/minifw-ai-web.service', 'etc/logrotate.d/minifw-ai'}):
            data = archive.extractfile(member).read()
            assert Path('/' + name).read_bytes() == data, ('Installed file differs', name)
            matched += 1
print('INSTALLED_PAYLOAD_MATCH', matched, 'application/model/policy/script/unit/logrotate files', flush=True)
