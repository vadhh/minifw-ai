"""Realistic-paced labelled lab corpus on C19 (AI shadow only). Fictional sandbox; not institution traffic.

Labels are per connection, from each actor's own log, joined later to the gateway's flow records by client IP and port.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

edition, package, source = sys.argv[1:]
assert edition in {'education', 'financial'} and socket.gethostname() == 'minifw-monday-' + edition and os.geteuid() == 0
assert subprocess.check_output(['systemd-detect-virt'], text=True).strip() in {'kvm', 'qemu'}
sys.path.insert(0, str(Path(source) / 'testing'))
import lab_gateway_acceptance as gateway
import lab_extended_acceptance as extended

STATE = Path('/opt/minifw_ai/logs/deployment_state.json')
CLIENT_SCRIPT = Path(__file__).with_name('corpus_client.py')
SEED = 1000 if edition == 'education' else 2000
# (kind, ip, connections-or-visits, start offset seconds)
PLAN = [('human', '10.10.0.31', 60, 0), ('human', '10.10.0.32', 60, 5), ('human', '10.10.0.33', 60, 10), ('human', '10.10.0.34', 60, 15),
        ('tool', '10.10.0.41', 60, 60), ('tool', '10.10.0.42', 60, 200),
        ('slow', '10.10.0.43', 20, 30), ('slow', '10.10.0.44', 20, 250)]


def exercise(root, run, start, record, nft, ns, member, children):
    STATE.unlink(missing_ok=True)  # Let AI run in shadow so model probabilities are recorded; harness restores state.
    start(source='none', packet=True, ai=True)
    capture = root / f'{edition}-realistic.pcap'
    capture_log = (root / 'realistic-capture.log').open('w')
    tcpdump = subprocess.Popen(['tcpdump', '--immediate-mode', '-B', '8192', '-U', '-n', '-i', 'mfcg', '-w', str(capture),
                                'net', '10.10.0.0/24', 'and', 'host', '198.18.0.2', 'and', 'tcp', 'port', '443'],
                               stdout=capture_log, stderr=capture_log)
    children.append(tcpdump)
    for _, ip, _, _ in PLAN:
        run('ip', '-n', 'mf-client', 'addr', 'add', ip + '/24', 'dev', 'mfc0')
    time.sleep(.5)
    actors = []
    for index, (kind, ip, count, offset) in enumerate(PLAN):
        out = root / f'actor-{ip}.jsonl'
        actors.append(subprocess.Popen(['ip', 'netns', 'exec', 'mf-client', '/usr/bin/python3', str(CLIENT_SCRIPT), kind, ip,
                                        str(SEED + index), str(count), str(offset), str(out), str(Path(source) / 'testing')]))
    children.extend(actors)
    deadline = time.monotonic() + 25 * 60
    isolated = {}
    while any(actor.poll() is None for actor in actors):
        assert time.monotonic() < deadline, 'Corpus actors did not finish'
        for _, ip, _, _ in PLAN:
            if ip not in isolated and subprocess.run(['nft', 'get', 'element', 'inet', 'minifw', 'minifw_block_v4', '{', ip, '}'],
                                                     capture_output=True).returncode == 0:
                isolated[ip] = time.time()
        time.sleep(1)
    time.sleep(3)  # Let the sensor flush the last flows and tcpdump drain.
    tcpdump.send_signal(signal.SIGINT)
    tcpdump.wait(timeout=10)
    capture_log.close()
    connections = [json.loads(line) for ip in {p[1] for p in PLAN} for line in (root / f'actor-{ip}.jsonl').read_text().splitlines()]
    counts = {}
    for row in connections:
        key = row['kind'] + ('_error' if row['error'] else '')
        counts[key] = counts.get(key, 0) + 1
    manifest = dict(edition=edition, package_sha256=hashlib.sha256(Path(package).read_bytes()).hexdigest(), plan=PLAN,
                    capture=capture.name, capture_sha256=hashlib.sha256(capture.read_bytes()).hexdigest(),
                    connections=counts, isolated_by_baseline=isolated, AI='C19 shadow only',
                    label_source='per-connection actor logs (kind/ip/port/start); human=benign, tool/slow=malicious',
                    representative=False,
                    limitations=['Fictional sandbox server and one lab network', 'Lab server is HTTP/1.0: one TLS connection per request',
                                 'Scripted human pacing is an approximation of people, not observed users'])
    (root / 'realistic-corpus-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    record('realistic_lab_corpus', **{k: v for k, v in manifest.items() if k not in {'plan', 'limitations'}})


extended.exercise = exercise
gateway.acceptance(edition, package, extended=True)
