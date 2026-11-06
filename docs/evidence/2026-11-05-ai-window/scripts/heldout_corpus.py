"""Held-out labelled lab corpus on C19 with the shipped collector config (conntrack flows, DNS file source; AI shadow only).

Fictional sandbox; not institution traffic. Derived from 2026-11-05-ai-decision/scripts/lab_realistic_corpus.py with new
seeds, addresses, actors and offsets. Labels are per connection, from each actor's own log, joined later to the gateway's
records by client IP and source port.
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
CLIENT_SCRIPT = Path(__file__).with_name('heldout_client.py')
SEED = 3000 if edition == 'education' else 4000
START = dict(source='file', packet=False, ai=True)  # Shipped collectors: dnsmasq log + conntrack 5 s polls; no packet sensor.
# (kind, ip, connections-or-visits, start offset seconds)
PLAN = [('human', '10.10.0.51', 60, 3), ('human', '10.10.0.52', 60, 11), ('human', '10.10.0.53', 60, 19),
        ('human', '10.10.0.54', 60, 27), ('human', '10.10.0.55', 60, 36), ('human', '10.10.0.56', 60, 44),
        ('tool', '10.10.0.57', 60, 95), ('tool', '10.10.0.58', 60, 340), ('tool1', '10.10.0.59', 60, 170),
        ('slow', '10.10.0.60', 20, 50), ('slow', '10.10.0.61', 20, 280), ('poller', '10.10.0.62', 300, 120)]


def exercise(root, run, start, record, nft, ns, member, children):
    STATE.unlink(missing_ok=True)  # Let AI run in shadow; this driver restores the original state file afterwards.
    start(**START)
    capture = root / f'{edition}-heldout.pcap'
    capture_log = (root / 'heldout-capture.log').open('w')
    tcpdump = subprocess.Popen(['tcpdump', '--immediate-mode', '-B', '8192', '-U', '-n', '-i', 'mfcg', '-w', str(capture),
                                'net', '10.10.0.0/24', 'and', 'host', '198.18.0.2', 'and', 'tcp', 'port', '443'],
                               stdout=capture_log, stderr=capture_log)
    children.append(tcpdump)
    for _, ip, _, _ in PLAN:
        run('ip', '-n', 'mf-client', 'addr', 'add', ip + '/24', 'dev', 'mfc0')
    time.sleep(.5)
    run('sysctl', 'net.netfilter.nf_conntrack_acct')
    started = time.time()
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
    time.sleep(12)  # Two more conntrack polls so the last connections are observed; tcpdump drains.
    finished = time.time()
    tcpdump.send_signal(signal.SIGINT)
    tcpdump.wait(timeout=10)
    capture_log.close()
    connections = [json.loads(line) for ip in {p[1] for p in PLAN} for line in (root / f'actor-{ip}.jsonl').read_text().splitlines()]
    counts = {}
    for row in connections:
        key = row['kind'] + ('_error' if row['error'] else '')
        counts[key] = counts.get(key, 0) + 1
    manifest = dict(edition=edition, package_sha256=hashlib.sha256(Path(package).read_bytes()).hexdigest(), plan=PLAN,
                    seed_base=SEED, start=START, collector='conntrack 5 s polls (no packet interface); DNS source file (lab dnsmasq log)',
                    run_start=started, run_end=finished,
                    capture=capture.name, capture_sha256=hashlib.sha256(capture.read_bytes()).hexdigest(),
                    connections=counts, isolated_by_baseline=isolated, AI='C19 shadow only', held_out=True,
                    label_source='per-connection actor logs (kind/ip/port/start); human/poller=benign, tool/tool1/slow=malicious',
                    representative=False,
                    limitations=['Fictional sandbox server and one lab network', 'Lab server is HTTP/1.0: one TLS connection per request',
                                 'Scripted human pacing is an approximation of people, not observed users',
                                 'Actors connect to the server IP directly, so the DNS log stays empty',
                                 'Harness sets ip_timeout_seconds=15, so a blocked client can be released and re-blocked',
                                 'isolated_by_baseline records only the first block seen per IP by a 1 s nft poll'])
    (root / 'heldout-corpus-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    record('heldout_lab_corpus', **{k: v for k, v in manifest.items() if k not in {'plan', 'limitations'}})


extended.exercise = exercise
state_before = STATE.read_bytes() if STATE.exists() else None
state_mode = STATE.stat().st_mode & 0o777 if state_before is not None else None
try:
    gateway.acceptance(edition, package, extended=True)
finally:
    # The harness restores deployment_state.json only in metadata mode; leave it exactly as found.
    if state_before is None:
        STATE.unlink(missing_ok=True)
    else:
        STATE.write_bytes(state_before)
        STATE.chmod(state_mode)
    print('DEPLOYMENT_STATE_RESTORED', 'absent' if state_before is None else hashlib.sha256(state_before).hexdigest(), flush=True)
