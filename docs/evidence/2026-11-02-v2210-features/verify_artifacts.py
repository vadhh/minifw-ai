"""Verify final v2.2.10 feature artifacts against actual committed and local source."""
import hashlib
import io
import json
import subprocess
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BASE = '411c39f55e932b76bb92ba8c485e01cac3611ff9'
DIST = ROOT / 'dist/v2210-feature-candidates'


def sha(data):
    return hashlib.sha256(data).hexdigest()


for edition, sector in [('education', 'education'), ('financial', 'finance')]:
    source = DIST / f'minifw-ai-{edition}-v2.2.10-source-assessment.zip'
    package = DIST / edition / f'minifw-ai_2.2.10-{sector}_amd64.deb'
    print('SOURCE', edition, sha(source.read_bytes()))
    print('PACKAGE', edition, sha(package.read_bytes()))
    with zipfile.ZipFile(source) as archive:
        assert archive.testzip() is None
        prefix = source.stem + '/'
        manifest = json.loads(archive.read(prefix + 'MANIFEST.json'))
        assert manifest['base_commit'] == BASE and manifest['sector'] == sector
        compared = 0
        for name, expected in manifest['files'].items():
            data = archive.read(prefix + name)
            assert sha(data) == expected, name
            path = ROOT / name
            if path.is_file():
                current = path.read_bytes()
                if name in manifest['normalized_lf_files']:
                    current = current.replace(b'\r\n', b'\n')
                assert current == data, name
                compared += 1
        print('SOURCE_MATCH', len(manifest['files']), 'hashes;', compared, 'repository comparisons;', BASE)
    for field, expected in [('Package', 'minifw-ai'), ('Version', '2.2.10-' + sector), ('Architecture', 'amd64')]:
        assert subprocess.check_output(['dpkg-deb', '-f', str(package), field], text=True).strip() == expected
    data = subprocess.check_output(['dpkg-deb', '--fsys-tarfile', str(package)])
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        assert all(member.uid == member.gid == 0 for member in archive.getmembers())
        files = ['main.py', 'collector_flow.py', 'collector_runtime.py', 'collector_dnsmasq.py', 'collector_zeek.py',
                 'collector_packets.py', 'safesearch.py', 'enforce.py', 'feeds.py', 'state_manager.py',
                 'utils/mlp_engine.py', 'sector_config.py', 'events.py']
        for name in files:
            relative = 'app/minifw_ai/' + name
            content = archive.extractfile('./opt/minifw_ai/' + relative).read()
            assert content == subprocess.check_output(['git', 'show', BASE + ':' + relative], cwd=ROOT), relative
        for name in ['mlp_model.pkl', 'mlp_packet14.pkl']:
            content = archive.extractfile('./opt/minifw_ai/models/' + name).read()
            assert content == (ROOT / 'models' / name).read_bytes(), name
            print('MODEL', name, sha(content))
        print('PAYLOAD_MATCH', len(files), 'committed core modules; two models; root ownership')
print('PASS identity/integrity; live acceptance and classification quality are separate evidence')
