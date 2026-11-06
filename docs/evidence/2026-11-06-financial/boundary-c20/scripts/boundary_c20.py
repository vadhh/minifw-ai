"""6 Nov C20 attack-rate boundary and benign-automation test on minifw-monday-financial. Root only, lab guest only.

Uses the installed service as shipped: real policy and /etc/minifw/minifw.env are edited in place (backups kept in
/var/tmp/boundary-c20/orig, root-only, never copied to evidence) and restored byte-for-byte by `restore`.
Topology, sandbox server and DNS feeder are the 5 Nov lab ones (lab_gateway_acceptance.py, DNS_LOOP from lab_c20_ai.py).
Usage: boundary_c20.py setup | run LABEL [main|replicas] | restore  (each via systemd-run, logs in out/)
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

assert socket.gethostname() == 'minifw-monday-financial' and os.geteuid() == 0
assert subprocess.check_output(['systemd-detect-virt'], text=True).strip() in {'kvm', 'qemu'}
W = Path('/var/tmp/boundary-c20')
OUT, ORIG = W / 'out', W / 'orig'
POLICY = Path('/opt/minifw_ai/config/modes/minifw_financial/policy.json')
ENV = Path('/etc/minifw/minifw.env')
STATE = Path('/opt/minifw_ai/logs/deployment_state.json')
DNSLOG = Path('/var/log/dnsmasq.log')
EVENTS = Path('/opt/minifw_ai/logs/events.jsonl')
HARNESS = '/var/tmp/c20/src-current/testing/lab_gateway_acceptance.py'
MODEL_SHA = 'd06ce40ea3276d2cedac9e354075c4aa74aa3987e08b35e40a95451d4e69d6ee'
APPROVAL = f'MINIFW_AI_ENFORCE_MODEL_SHA256={MODEL_SHA}\n'
FEEDER = '10.10.0.70'
DURATION = 150
# (case, ip, seconds between new connections, mode)
ATTACK = [(f'attack_{r}pm', f'10.10.0.{100 + r if r < 100 else r}', 60 / r, 'new') for r in (30, 33, 35, 36, 37, 38, 39, 45, 60)]
BENIGN = [('a_poller_1s', '10.10.0.201', 1.0, 'new'), ('b_poller_2s', '10.10.0.202', 2.0, 'new'),
          ('c_monitor_10s', '10.10.0.203', 10.0, 'new'), ('d_keepalive_1s', '10.10.0.204', 1.0, 'keepalive'),
          ('e_exempt_poller_1s', '10.10.0.205', 1.0, 'new')]
# Replicates near the boundary: three addresses per rate, phase-offset against the 5 s polls.
REPLICAS = [(f'rep_{r}pm_{j}', f'10.10.0.{170 + 3 * i + j}', 60 / r, 'new') for i, r in enumerate((36, 37, 38)) for j in range(3)]
CASES = ATTACK + BENIGN
IPS = [c[1] for c in CASES + REPLICAS]
POLICY_EDITS = [  # (old, new): the only policy changes. Lab client range 10.10.0.128/25 -> internal (more specific than dmz /24).
    ('"internal": ["192.168.1.0/24", "10.0.0.0/8"],', '"internal": ["192.168.1.0/24", "10.0.0.0/8", "10.10.0.128/25"],'),
    ('"exempt": [],', '"exempt": ["10.10.0.205/32"],'),  # Needed by case (e) only.
]
DNS_LOOP = '''import socket,struct,sys,time
q=struct.pack("!HHHHHH",4321,0x100,1,0,0,0)+b"\\x06feeder\\x08approved\\x04test\\x00\\x00\\x01\\x00\\x01"
while True:
 try:
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(1); s.bind((sys.argv[1],0)); s.sendto(q,("10.10.0.1",53)); s.recvfrom(512); s.close()
 except OSError: pass
 time.sleep(4)
'''
KEEP = ('ts', 'client_ip', 'dst_ip', 'dst_port', 'segment', 'action', 'reasons', 'decision_owner', 'score',
        'ai_window_n60', 'ai_window_probability', 'ai_window_mode', 'ai_window_model_sha256')


def run(*cmd, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    print('$', ' '.join(cmd), '->', r.returncode, (r.stdout + r.stderr).strip()[:400], flush=True)
    if check:
        r.check_returncode()
    return r.stdout


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def stamp():
    return time.strftime('%Y-%m-%dT%H:%M:%S%z')


def facts(label):
    """Non-secret state: hashes, env variable names only, approval line count, services, set contents."""
    env_names = [line.split('=', 1)[0] for line in ENV.read_text().splitlines() if '=' in line and not line.startswith('#')]
    lines = [f'# {label} {stamp()}', run('dpkg-query', '-W', 'minifw-ai').strip(),
             f'policy_sha256={sha(POLICY)}', f'env_sha256={sha(ENV)}', f'env_variable_names={env_names}',
             f'env_approval_lines={ENV.read_text().count("MINIFW_AI_ENFORCE_MODEL_SHA256")}',
             f'state_file_sha256={sha(STATE) if STATE.exists() else "absent"}',
             f'dnsmasq_log_sha256={sha(DNSLOG)}']
    lines += [f'{u} {run("systemctl", "is-active", u, check=False).strip()}' for u in ('minifw-ai', 'minifw-ai-web', 'dnsmasq')]
    lines.append(run('nft', 'list', 'table', 'inet', 'minifw', check=False))
    (OUT / f'{label}.txt').write_text('\n'.join(lines) + '\n')


def setup():
    assert not ORIG.exists(), 'backups exist: restore first'
    OUT.mkdir(parents=True, exist_ok=True)
    ORIG.mkdir(mode=0o700)
    for path in (POLICY, ENV, STATE, DNSLOG):
        if path.exists():
            (ORIG / path.name).write_bytes(path.read_bytes())
    (ORIG / 'modes.json').write_text(json.dumps({p.name: p.stat().st_mode & 0o777 for p in (STATE,) if p.exists()}))
    facts('pre-test')
    run('ip', 'netns', 'add', 'mf-client')
    run('ip', 'netns', 'add', 'mf-server')
    for gw, peer, ns, v4, gw4 in [('mfcg', 'mfc0', 'mf-client', '10.10.0.20/24', '10.10.0.1/24'),
                                 ('mfsg', 'mfs0', 'mf-server', '198.18.0.2/24', '198.18.0.1/24')]:
        run('ip', '-n', ns, 'link', 'set', 'lo', 'up')
        run('ip', 'link', 'add', gw, 'type', 'veth', 'peer', 'name', peer)
        run('ip', 'link', 'set', peer, 'netns', ns)
        run('ip', 'addr', 'add', gw4, 'dev', gw)
        run('ip', 'link', 'set', gw, 'up')
        run('ip', '-n', ns, 'addr', 'add', v4, 'dev', peer)
        run('ip', '-n', ns, 'link', 'set', peer, 'up')
        run('ip', '-n', ns, 'route', 'add', 'default', 'via', gw4.split('/')[0])
    for ip in IPS + [FEEDER]:
        run('ip', '-n', 'mf-client', 'addr', 'add', ip + '/24', 'dev', 'mfc0')
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=lab.test',
        '-keyout', str(W / 'server.key'), '-out', str(W / 'server.crt'))
    run('systemd-run', '--unit=bc20-server', 'ip', 'netns', 'exec', 'mf-server', '/usr/bin/python3', HARNESS, 'server',
        str(W / 'server.crt'), str(W / 'server.key'))
    run('systemd-run', '--unit=bc20-dns', '/usr/sbin/dnsmasq', '--conf-file=/dev/null', '--keep-in-foreground', '--user=root',
        '--no-resolv', '--no-hosts', '--bind-interfaces', '--interface=mfcg', '--listen-address=10.10.0.1',
        '--address=/#/198.18.0.2', '--log-queries', f'--log-facility={DNSLOG}', f'--pid-file={W}/dns.pid')
    run('systemd-run', '--unit=bc20-feeder', 'ip', 'netns', 'exec', 'mf-client', '/usr/bin/python3', '-c', DNS_LOOP, FEEDER)
    text = POLICY.read_text()
    for old, new in POLICY_EDITS:
        assert text.count(old) == 1, old
        text = text.replace(old, new)
    json.loads(text)
    with POLICY.open('w') as f:  # Same inode: owner and mode unchanged.
        f.write(text)
    assert 'MINIFW_AI_ENFORCE_MODEL_SHA256' not in ENV.read_text()
    with ENV.open('a') as f:
        f.write(APPROVAL if ENV.read_text().endswith('\n') else '\n' + APPROVAL)
    (OUT / 'policy.diff').write_text(subprocess.run(['diff', '-u', str(ORIG / POLICY.name), str(POLICY)],
                                                    capture_output=True, text=True).stdout)
    (OUT / 'env.diff').write_text(f'+{APPROVAL}(only line added to /etc/minifw/minifw.env; other values not recorded)\n')
    time.sleep(2)
    for unit in ('bc20-server', 'bc20-dns', 'bc20-feeder'):
        assert run('systemctl', 'is-active', unit, check=False).strip() == 'active', unit
    facts('post-setup')


def element_map():
    data = json.loads(subprocess.run(['nft', '-j', 'list', 'set', 'inet', 'minifw', 'minifw_block_v4'], capture_output=True, text=True).stdout or '{}')
    found = {}
    for item in data.get('nftables', []):
        for e in item.get('set', {}).get('elem', []):
            if isinstance(e, dict):
                found[e['elem']['val']] = {k: v for k, v in e['elem'].items() if k != 'val'}
            else:
                found[e] = {}
    return found


def test(label, which):
    cases = CASES if which == 'main' else REPLICAS
    out_dir = OUT / label
    out_dir.mkdir()
    ips = [c[1] for c in cases]
    for ip in IPS:
        run('nft', 'delete', 'element', 'inet', 'minifw', 'minifw_block_v4', '{', ip, '}', check=False)
    mark = len(EVENTS.read_text().splitlines())
    since = time.strftime('%Y-%m-%d %H:%M:%S')
    run('systemctl', 'stop', 'minifw-ai')
    for ip in IPS:
        run('conntrack', '-D', '-s', ip, check=False)
    STATE.unlink(missing_ok=True)  # Controlled initial AI_ENHANCED (as 5 Nov); original bytes restored by `restore`.
    run('systemctl', 'start', 'minifw-ai')
    until = time.monotonic() + 60
    while f'sha256={MODEL_SHA}' not in run('journalctl', '-u', 'minifw-ai', '--since', since, '--no-pager', '-o', 'cat', check=False):
        assert time.monotonic() < until, 'model not loaded'
        time.sleep(.5)
    time.sleep(11)  # Engine ignores flows first seen in its first 10 s (window built just after the model loads).
    launched = time.time()
    procs = [subprocess.Popen(['ip', 'netns', 'exec', 'mf-client', '/usr/bin/python3', str(W / 'rate_client.py'), ip,
                               str(period), str(DURATION), str(out_dir / f'client-{case}.jsonl'), mode,
                               str(1.7 * int(case[-1])) if case.startswith('rep_') else '0'])
             for case, ip, period, mode in cases]
    first, snaps, last = {}, [], None
    while any(p.poll() is None for p in procs) or time.time() < launched + DURATION + 8:
        now = time.time()
        elems = element_map()
        for ip in ips:
            if ip in elems and ip not in first:
                first[ip] = dict(seen=now, element=elems[ip])
        key = sorted(elems)
        if key != last:
            snaps.append(f'## {stamp()} ({now:.1f})\n' + run('nft', 'list', 'set', 'inet', 'minifw', 'minifw_block_v4', check=False))
            last = key
        time.sleep(.5)
    snaps.append(f'## final {stamp()}\n' + run('nft', 'list', 'set', 'inet', 'minifw', 'minifw_block_v4', check=False))
    (out_dir / 'nft-snapshots.txt').write_text('\n'.join(snaps))
    time.sleep(6)  # Last conntrack poll.
    journal = run('journalctl', '-u', 'minifw-ai', '--since', since, '--no-pager', '-o', 'short-iso', check=False)
    (out_dir / 'journal-minifw-ai.txt').write_text('\n'.join(x for x in journal.splitlines() if 'SECRET' not in x and 'PASSWORD' not in x))
    rows = [json.loads(x) for x in EVENTS.read_text().splitlines()[mark:]]
    picked = [{k: r.get(k) for k in KEEP} for r in rows if r.get('client_ip') in ips]
    (out_dir / 'events-test-ips.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in picked))
    feeder_events = sum(r.get('client_ip') == FEEDER for r in rows)
    results = []
    for case, ip, period, mode in cases:
        client = [json.loads(x) for x in (out_dir / f'client-{case}.jsonl').read_text().splitlines()]
        start = client[0]['start']
        mine = [r for r in picked if r['client_ip'] == ip]
        scored = [r for r in mine if r['ai_window_n60'] is not None]
        probs = [r for r in scored if r['ai_window_probability'] is not None]
        blocks = [r for r in mine if r['action'] == 'block']
        hit = first.get(ip)
        results.append(dict(
            case=case, ip=ip, rate_per_min=round(60 / period, 2), mode=mode, duration_s=DURATION,
            attempts=len(client), connected_ok=sum(c['status'] is not None for c in client),
            failed=sum(c['error'] is not None for c in client), first_failure_s=next(
                (round(c['start'] - start, 1) for c in client if c['error']), None),
            isolated=hit is not None, seconds_to_isolation=round(hit['seen'] - start, 1) if hit else None,
            nft_element=hit['element'] if hit else None, events=len(mine),
            max_n60=max((r['ai_window_n60'] for r in scored), default=None),
            max_probability=max((r['ai_window_probability'] for r in probs), default=None),
            segments=sorted({r['segment'] for r in mine if r['segment']}), modes=sorted({r['ai_window_mode'] for r in mine}),
            first_block_event=blocks[0] if blocks else None))
    out = dict(test=f'C20 boundary {label} ({which}), minifw-monday-financial', started=since,
               clients_launched=launched, events_mark_line=mark, feeder_dns_events=feeder_events,
               state_file_after=STATE.read_text() if STATE.exists() else 'absent (no transition since start)',
               state_journal=[x for x in journal.splitlines() if '[STATE]' in x or '[AI_WINDOW]' in x][-8:], results=results)
    (out_dir / 'results.json').write_text(json.dumps(out, indent=2))
    for r in results:
        print(r['case'], r['ip'], 'isolated' if r['isolated'] else 'not-isolated', r['seconds_to_isolation'], r['max_n60'],
              r['max_probability'], r['segments'], r['modes'], r['nft_element'], flush=True)


def restore():
    run('systemctl', 'stop', 'minifw-ai')
    for ip in IPS:
        run('nft', 'delete', 'element', 'inet', 'minifw', 'minifw_block_v4', '{', ip, '}', check=False)
        run('conntrack', '-D', '-s', ip, check=False)
    for unit in ('bc20-feeder', 'bc20-dns', 'bc20-server'):
        run('systemctl', 'stop', unit, check=False)
    run('systemctl', 'reset-failed', 'bc20-*', check=False)
    run('ip', 'link', 'delete', 'mfcg', check=False)
    run('ip', 'link', 'delete', 'mfsg', check=False)
    run('ip', 'netns', 'delete', 'mf-client', check=False)
    run('ip', 'netns', 'delete', 'mf-server', check=False)
    modes = json.loads((ORIG / 'modes.json').read_text())
    for path in (POLICY, ENV, DNSLOG):
        with path.open('wb') as f:  # Same inode: owner and mode unchanged.
            f.write((ORIG / path.name).read_bytes())
        assert sha(path) == sha(ORIG / path.name), path
    if (ORIG / STATE.name).exists():
        STATE.write_bytes((ORIG / STATE.name).read_bytes())
        STATE.chmod(modes[STATE.name])
    else:
        STATE.unlink(missing_ok=True)
    run('systemctl', 'start', 'minifw-ai')
    time.sleep(8)
    facts('post-restore')
    pre = (OUT / 'pre-test.txt').read_text().splitlines()[1:8]
    post = (OUT / 'post-restore.txt').read_text().splitlines()[1:8]
    print('RESTORED_MATCHES_PRE', pre == post, [(a, b) for a, b in zip(pre, post) if a != b], flush=True)


{'setup': setup, 'run': lambda: test(*sys.argv[2:4]), 'restore': restore}[sys.argv[1]]()
