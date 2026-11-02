import ast
import hashlib
import json
import math
import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[3]
evidence = root / 'docs/evidence/2026-11-02-v2210-features'
configs = {
 'education': ('20261102T074146Z', '20261102T074230Z', 23, 'd9ce4d6f64bebc2e71df1332d0a45faed7507846a5ecf3770413c2ed4ab85a68'),
 'financial': ('20261102T074248Z', '20261102T074333Z', 22, 'c2362a9d498f47049e0d93ff993d34d113f78db8ccef80fa90e237917ff145ec'),
}
for edition, (meta_stamp, core_stamp, core_count, digest) in configs.items():
    folder = evidence / edition
    run = folder / 'runs' / ('minifw-monday-' + edition + '-' + meta_stamp)
    rows = json.loads((run / 'results.json').read_text())
    assert len(rows) == 23
    actual = {row['test']: row['actual'] for row in rows}
    assert len([name for name in actual if name.startswith('restricted_DNS_')]) == 12
    for name in ['TLS10_enforcement', 'WireGuard_enforcement']:
        assert actual[name]['client'] == '10.10.0.20' and actual[name]['forwarded'] == 'blocked'
    assert actual['ordinary_UDP_not_a_tunnel']['detected'] is False
    sample = actual['measured_packet_model_inference']
    assert sample['schema'] == 'packet14-v1' and sample['mode'] == 'shadow_only'
    assert sample['enforcement_score'] == 0 and len(sample['features']) == 14
    assert all(math.isfinite(value) for value in sample['features'])
    assert sample['DNS'] == 'disabled'
    assert 'EXIT_CODE 1' in (folder / 'model-quality-failed.log').read_text()
    assert 'PREDICTED threat' in (folder / 'model-quality-failed.log').read_text()
    assert (run / 'package.sha256').read_text().startswith(digest)
    core = folder / 'runs' / ('minifw-monday-' + edition + '-' + core_stamp)
    assert len(json.loads((core / 'results.json').read_text())) == core_count
    assert (core / 'package.sha256').read_text().startswith(digest)
    events = [json.loads(line) for line in (run / 'events.jsonl').read_text().splitlines()]
    assert any(row['sni'] == 'lab.test' and row['dst_ip'] == '198.18.0.2' and row['dst_port'] == 443 for row in events)
    assert all(not row['sni'] for row in events if row['dst_port'] in {8080, 51820})
    assert not any(row.get('mlp_mode') == 'shadow_only' and any(reason.startswith('mlp_threat_score') for reason in row['reasons']) for row in events)
    print('PASS', edition, 'final package identity, 23 feature/coverage records,', core_count, 'core records; quality FAIL explicitly retained')
report = root / 'docs/2026-11-02_correction-minifwai-report.md'
text = report.read_text()
section = text.split('## Consolidated requirement matrix', 1)[1].split('## Financial rule-input inventory', 1)[0]
rows = [line for line in section.splitlines() if line.startswith('| ')][2:]
assert len(rows) == 40
statuses = {'Verified complete', 'Implemented, verification pending', 'In progress', 'Blocked', 'Not started'}
for line in rows:
    values = [value.strip() for value in line.split('|')[1:-1]]
    assert len(values) == 9 and values[2] in statuses, values
for commit in re.findall(r'`([a-f0-9]{40})`', text):
    subprocess.run(['git', 'cat-file', '-e', commit + '^{commit}'], cwd=root, check=True)
for path in [report, evidence / 'README.md', root / 'docs/v2210-metadata-controls.md']:
    for link in re.findall(r'\]\(([^)]+)\)', path.read_text()):
        if not link.startswith(('https:', 'http:')):
            assert (path.parent / link.split('#')[0]).exists(), (path.name, link)
files = sorted(path for path in evidence.rglob('*') if path.is_file() and path.name != 'SHA256SUMS')
for path in files:
    assert not path.is_symlink() and path.suffix not in {'.key', '.pem', '.db', '.sqlite3', '.pcap', '.pcapng'}, path
    data = path.read_bytes()
    assert not re.search(rb'-----BEGIN [A-Z ]*PRIVATE KEY-----', data), path
    assert not re.search(rb'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', data), path
(evidence / 'SHA256SUMS').write_text('\n'.join(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+str(path.relative_to(evidence)) for path in files)+'\n')
dist = root / 'dist/v2210-feature-candidates'
artifacts = sorted([*dist.glob('*.zip'), *dist.glob('*/*.deb')])
assert len(artifacts) == 4
(dist/'SHA256SUMS').write_text('\n'.join(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+str(path.relative_to(dist)) for path in artifacts)+'\n')
print('PASS 40 requirement rows/statuses; Git identities; file links; public evidence exclusions;', len(files), 'evidence hashes and 4 artifact hashes')
