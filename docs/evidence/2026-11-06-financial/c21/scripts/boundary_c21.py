"""6 Nov C21 (2.2.12) lab checks on minifw-monday-financial. Copy of boundary-c20/scripts/boundary_c20.py (same
topology, backups and byte-exact restore) with C21 changes: setup no longer edits policy/env (`edit` does, for the
boundary run); the env already holds the commented #MINIFW_AI_ENFORCE_MODEL_SHA256= line from the C21 postinst;
rates 30/37/38/39/60 + benign a/e only; added `restartfb` (restart false block + dashboard checks) and `gap`.

Uses the installed service as shipped: real policy and /etc/minifw/minifw.env are edited in place (backups kept in
/var/tmp/boundary-c20/orig, root-only, never copied to evidence) and restored byte-for-byte by `restore`.
Topology, sandbox server and DNS feeder are the 5 Nov lab ones (lab_gateway_acceptance.py, DNS_LOOP from lab_c20_ai.py).
Usage: boundary_c21.py setup | edit | run LABEL main | restartfb | gap | restore  (each via systemd-run, logs in out/)
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
W = Path('/var/tmp/c21/lab')
OUT, ORIG = W / 'out', W / 'orig'
POLICY = Path('/opt/minifw_ai/config/modes/minifw_financial/policy.json')
ENV = Path('/etc/minifw/minifw.env')
STATE = Path('/opt/minifw_ai/logs/deployment_state.json')
DNSLOG = Path('/var/log/dnsmasq.log')
EVENTS = Path('/opt/minifw_ai/logs/events.jsonl')
HARNESS = '/var/tmp/c21/src-current/testing/lab_gateway_acceptance.py'
CLIENT = '10.10.0.20'  # mf-client primary address (dmz /24): restartfb scans from here
MODEL_SHA = 'd06ce40ea3276d2cedac9e354075c4aa74aa3987e08b35e40a95451d4e69d6ee'
APPROVAL = f'MINIFW_AI_ENFORCE_MODEL_SHA256={MODEL_SHA}\n'
FEEDER = '10.10.0.70'
DURATION = 150
# (case, ip, seconds between new connections, mode)
ATTACK = [(f'attack_{r}pm', f'10.10.0.{100 + r if r < 100 else r}', 60 / r, 'new') for r in (30, 37, 38, 39, 60)]
BENIGN = [('a_poller_1s', '10.10.0.201', 1.0, 'new'), ('e_exempt_poller_1s', '10.10.0.205', 1.0, 'new')]
# Replicates near the boundary: three addresses per rate, phase-offset against the 5 s polls.
REPLICAS = [(f'rep_{r}pm_{j}', f'10.10.0.{170 + 3 * i + j}', 60 / r, 'new') for i, r in enumerate((36, 37, 38)) for j in range(3)]
CASES = ATTACK + BENIGN  # 'main' (run R1)
# 'full': this morning's C20 R1 list, so 36/37/38 get 4 runs each with the replicas (coordinator, 6 Nov 10:2x).
ATTACK_FULL = [(f'attack_{r}pm', f'10.10.0.{100 + r}', 60 / r, 'new') for r in (30, 33, 35, 36, 37, 38, 39, 45, 60)]
BENIGN_FULL = [('a_poller_1s', '10.10.0.201', 1.0, 'new'), ('b_poller_2s', '10.10.0.202', 2.0, 'new'),
               ('c_monitor_10s', '10.10.0.203', 10.0, 'new'), ('d_keepalive_1s', '10.10.0.204', 1.0, 'keepalive'),
               ('e_exempt_poller_1s', '10.10.0.205', 1.0, 'new')]
FULL = ATTACK_FULL + BENIGN_FULL
IPS = [c[1] for c in FULL + REPLICAS]
# 'long': the 37/38 replicas (same addresses and phase offsets) for 300 s, because one 38/min replica needed 136.7 s of 150.
LONG = [c for c in REPLICAS if c[0].startswith(('rep_37', 'rep_38'))]
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
    time.sleep(2)
    for unit in ('bc20-server', 'bc20-dns', 'bc20-feeder'):
        assert run('systemctl', 'is-active', unit, check=False).strip() == 'active', unit
    facts('post-setup')


def approved():
    return any(x.startswith('MINIFW_AI_ENFORCE_MODEL_SHA256=') for x in ENV.read_text().splitlines())


def approve():
    assert not approved()
    with ENV.open('a') as f:  # Same inode: owner and mode unchanged.
        f.write(APPROVAL if ENV.read_text().endswith('\n') else '\n' + APPROVAL)


def edit():
    text = POLICY.read_text()
    for old, new in POLICY_EDITS:
        assert text.count(old) == 1, old
        text = text.replace(old, new)
    json.loads(text)
    with POLICY.open('w') as f:  # Same inode: owner and mode unchanged.
        f.write(text)
    approve()
    (OUT / 'policy.diff').write_text(subprocess.run(['diff', '-u', str(ORIG / POLICY.name), str(POLICY)],
                                                    capture_output=True, text=True).stdout)
    (OUT / 'env.diff').write_text(f'+{APPROVAL}(only line added to /etc/minifw/minifw.env; other values not recorded)\n')
    facts('post-edit')


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
    cases = {'main': CASES, 'full': FULL, 'replicas': REPLICAS, 'long': LONG}[which]
    duration = 300 if which == 'long' else DURATION
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
                               str(period), str(duration), str(out_dir / f'client-{case}.jsonl'), mode,
                               str(1.7 * int(case[-1])) if case.startswith('rep_') else '0'])
             for case, ip, period, mode in cases]
    first, snaps, last = {}, [], None
    while any(p.poll() is None for p in procs) or time.time() < launched + duration + 8:
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
            case=case, ip=ip, rate_per_min=round(60 / period, 2), mode=mode, duration_s=duration,
            attempts=len(client), connected_ok=sum(c['status'] is not None for c in client),
            failed=sum(c['error'] is not None for c in client), first_failure_s=next(
                (round(c['start'] - start, 1) for c in client if c['error']), None),
            isolated=hit is not None, seconds_to_isolation=round(hit['seen'] - start, 1) if hit else None,
            nft_element=hit['element'] if hit else None, events=len(mine),
            max_n60=max((r['ai_window_n60'] for r in scored), default=None),
            max_probability=max((r['ai_window_probability'] for r in probs), default=None),
            segments=sorted({r['segment'] for r in mine if r['segment']}), modes=sorted({r['ai_window_mode'] for r in mine}),
            first_block_event=blocks[0] if blocks else None))
    out = dict(test=f'C21 boundary {label} ({which}), minifw-monday-financial', started=since,
               clients_launched=launched, events_mark_line=mark, feeder_dns_events=feeder_events,
               state_file_after=STATE.read_text() if STATE.exists() else 'absent (no transition since start)',
               state_journal=[x for x in journal.splitlines() if '[STATE]' in x or '[AI_WINDOW]' in x][-8:], results=results)
    (out_dir / 'results.json').write_text(json.dumps(out, indent=2))
    for r in results:
        print(r['case'], r['ip'], 'isolated' if r['isolated'] else 'not-isolated', r['seconds_to_isolation'], r['max_n60'],
              r['max_probability'], r['segments'], r['modes'], r['nft_element'], flush=True)


def restore():
    run('systemctl', 'stop', 'minifw-ai')
    for ip in IPS + [CLIENT]:
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



def journal_since(since):
    text = run('journalctl', '-u', 'minifw-ai', '--since', since, '--no-pager', '-o', 'short-iso', check=False)
    return '\n'.join(x for x in text.splitlines() if 'SECRET' not in x and 'PASSWORD' not in x)


def snap(out_dir, tag):
    """Timestamped nft table snapshot, appended to nft-snapshots.txt."""
    text = f'## {tag} {stamp()} ({time.time():.1f})\n' + run('nft', 'list', 'table', 'inet', 'minifw', check=False)
    with (out_dir / 'nft-snapshots.txt').open('a') as f:
        f.write(text + '\n')


def conntrack_client(out_dir, tag):
    """Client's TCP conntrack entries: count, distinct destination ports, states (shows what the engine's first poll saw)."""
    text = subprocess.run(['conntrack', '-L', '-p', 'tcp', '-s', CLIENT], capture_output=True, text=True).stdout
    rows = [x for x in text.splitlines() if 'dport=' in x]
    ports = sorted({int(x.split('dport=')[1].split()[0]) for x in rows})
    with (out_dir / 'conntrack-client.txt').open('a') as f:
        f.write(f'## {tag} {stamp()} ({time.time():.1f})\n{text}\n')
    return dict(at=stamp(), entries=len(rows), distinct_dports=len(ports), states=sorted({x.split()[3] for x in rows if len(x.split()) > 3}))


def wait_member(ip, seconds):
    until = time.time() + seconds
    while time.time() < until:
        if ip in element_map():
            return time.time()
        time.sleep(.2)
    return None


def scan(out_dir, tag):
    return subprocess.Popen(['ip', 'netns', 'exec', 'mf-client', '/usr/bin/python3', HARNESS, 'client', 'scan', '198.18.0.2'],
                            stdout=(out_dir / f'scan-{tag}.log').open('w'), stderr=subprocess.STDOUT)


class Dashboard:
    """Authenticated dashboard session as in lab_c19_dashboard.py (password read from the env file, never printed)."""
    timeout = 20
    def __init__(self):
        import http.client, ssl, urllib.parse
        self.http, self.ssl, self.urlencode = http.client, ssl, urllib.parse.urlencode
        self.cookie = ''
        secret = dict(x.split('=', 1) for x in ENV.read_text().splitlines() if '=' in x and not x.startswith('#'))
        for _ in range(50):
            try:
                status, token, _ = self.call('POST', '/auth/login', {'username': 'admin', 'password': secret['MINIFW_ADMIN_PASSWORD']}, True)
                break
            except OSError:
                time.sleep(.2)
        assert status == 303 and 'access_token=' in token, status
        self.cookie = token.split(';', 1)[0]

    def call(self, method, path, data=None, form=False):
        c = self.http.HTTPSConnection('127.0.0.1', 8443, context=self.ssl._create_unverified_context(), timeout=self.timeout)
        headers = {'Origin': 'https://127.0.0.1:8443'}
        if self.cookie:
            headers['Cookie'] = self.cookie
        if data is not None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
            data = self.urlencode(data) if form else json.dumps(data)
        c.request(method, path, body=data, headers=headers)
        r = c.getresponse()
        out = r.status, r.getheader('Set-Cookie'), r.read()
        c.close()
        return out


def live_blocks(out_dir, dash, block_ip):
    """/api/live-blocks returns blocks from the last 5 s only: called right after the isolation; raw bodies kept."""
    raw, live = [], []
    for _ in range(6):
        status, _, body = dash.call('GET', '/admin/api/live-blocks')
        raw.append(dict(at=stamp(), status=status, body=body.decode('utf-8', 'replace')))
        if block_ip in raw[-1]['body']:
            data = json.loads(body)
            rows = data if isinstance(data, list) else next((v for v in data.values() if isinstance(v, list)), [])
            live = [r for r in rows if block_ip in json.dumps(r)]
            break
        time.sleep(.5)
    (out_dir / 'live-blocks-raw.json').write_text(json.dumps(raw, indent=2))
    return live


def dashboard_checks(out_dir, dash, block_ip):
    """Step 7, during an isolation of block_ip: pages free of invented labels, real mode rows, exports."""
    import csv, io, re
    pages = {}
    for path in ('/admin/', '/admin/events', '/admin/api/events'):
        status, _, body = dash.call('GET', path)
        text = body.decode('utf-8', 'replace')
        pages[path] = dict(status=status, bytes=len(body), forbidden_found=[w for w in ('Ransomware', 'FRAUD', 'Banking trojan', 'Math.random') if w in text])
        if path == '/admin/':
            rows = {}
            for label in ('Detection Mode', 'Connection-rate AI'):
                m = re.search(re.escape(label) + r'</span>\s*<span[^>]*>([^<]*)</span>', text)
                rows[label] = m.group(1).strip() if m else None
            pages[path]['rows'] = rows
            (out_dir / 'dashboard.html').write_text(text)
        elif path == '/admin/events':
            (out_dir / 'events.html').write_text(text)
    status, _, body = dash.call('GET', '/admin/api/events/download?fmt=csv&action_filter=all')
    (out_dir / 'events-export.csv').write_bytes(body)
    lines = body.decode('utf-8', 'replace').splitlines()
    table = list(csv.reader(io.StringIO('\n'.join(x for x in lines if not x.startswith('#')))))
    csv_info = dict(status=status, header=table[0] if table else None, rows=len(table) - 1,
                    widths=sorted({len(r) for r in table}), block_rows_for_ip=sum(1 for r in table[1:] if block_ip in r and 'block' in r))
    status, _, body = dash.call('GET', '/admin/api/events/download?fmt=pdf&action_filter=all')
    (out_dir / 'events-export.pdf').write_bytes(body)
    pdf_info = dict(status=status, bytes=len(body), magic=body[:5].decode('latin-1'), eof=body.rstrip().endswith(b'%%EOF'))
    return dict(pages=pages, csv=csv_info, pdf=pdf_info)


def fresh_engine(out_dir, tag):
    """Stop the engine, clear the client's element and conntrack entries, start it again (no memory of earlier scans)."""
    since = time.strftime('%Y-%m-%d %H:%M:%S')
    run('systemctl', 'stop', 'minifw-ai')
    run('nft', 'delete', 'element', 'inet', 'minifw', 'minifw_block_v4', '{', CLIENT, '}', check=False)
    run('conntrack', '-D', '-s', CLIENT, check=False)
    run('systemctl', 'start', 'minifw-ai')
    until = time.monotonic() + 60
    while 'Initial protection state' not in run('journalctl', '-u', 'minifw-ai', '--since', since, '--no-pager', '-o', 'cat', check=False):
        assert time.monotonic() < until, 'engine did not start'
        time.sleep(.5)
    time.sleep(8)  # past the new engine's first conntrack poll
    snap(out_dir, f'{tag}-fresh-engine')


def restartfb(label='restartfb', delay='0', checks='yes'):
    """Step 4 (+7): port-scan isolation, hand delete, dashboard Save -> Apply within 60 s, no re-block; fresh scan re-isolates.
    Run 1 used the defaults. Repeats (label != restartfb) start and end with a fresh engine, wait `delay` s between the
    hand delete and Save -> Apply, and skip the page/export checks (checks=no)."""
    out_dir = OUT / label
    out_dir.mkdir()
    repeat = label != 'restartfb'
    res = dict(test=f'C21 restart false block {label}, minifw-monday-financial', client=CLIENT, apply_delay_s=float(delay))
    if repeat:
        fresh_engine(out_dir, 'pre')
    run('nft', 'delete', 'element', 'inet', 'minifw', 'minifw_block_v4', '{', CLIENT, '}', check=False)
    run('conntrack', '-D', '-s', CLIENT, check=False)
    snap(out_dir, '0-before')
    since = time.strftime('%Y-%m-%d %H:%M:%S')
    mark = len(EVENTS.read_text().splitlines())
    res['scan1_start'] = stamp(); t0 = time.time()
    p1 = scan(out_dir, 'first')
    tb = wait_member(CLIENT, 30)
    assert tb, 'first scan not isolated'
    res['scan1_isolated_after_s'] = round(tb - t0, 1)
    snap(out_dir, '1-isolated-by-first-scan')
    res['conntrack_at_isolation'] = conntrack_client(out_dir, '1-isolated')
    dash = Dashboard()  # logged in first, so Save -> Apply follows the hand delete within seconds
    run('nft', 'delete', 'element', 'inet', 'minifw', 'minifw_block_v4', '{', CLIENT, '}')
    td = time.time(); res['hand_delete_at'] = stamp()
    snap(out_dir, '2-deleted-by-hand')
    res['readded_during_delay_at'] = None
    until = td + float(delay)
    while time.time() < until:  # the running engine still tracks the scan: does it re-add before the Apply?
        if res['readded_during_delay_at'] is None and CLIENT in element_map():
            res['readded_during_delay_at'] = stamp()
            res['readded_during_delay_after_s'] = round(time.time() - td, 1)
            snap(out_dir, '2a-readded-by-running-engine')
        time.sleep(.5)
    policy_before = sha(POLICY)
    enforcement = json.loads(POLICY.read_text())['enforcement']
    values = {k: enforcement[k] for k in ('ipset_name_v4', 'nft_table', 'nft_chain', 'ip_timeout_seconds')}  # saved unchanged
    pid_before = run('systemctl', 'show', '-p', 'MainPID', '--value', 'minifw-ai').strip()
    save = dash.call('POST', '/admin/policy/enforcement', values)
    apply = dash.call('POST', '/admin/policy/apply')
    ta = time.time()
    res.update(save_http=save[0], apply_http=apply[0], apply_response=json.loads(apply[2]) if apply[0] == 200 else apply[2].decode()[:300],
               apply_at=stamp(), seconds_delete_to_apply=round(ta - td, 1), policy_sha_before_save=policy_before, policy_sha_after_save=sha(POLICY),
               client_isolated_at_apply=CLIENT in element_map())
    until = time.time() + 60
    while time.time() < until:
        pid = run('systemctl', 'show', '-p', 'MainPID', '--value', 'minifw-ai').strip()
        if pid not in ('0', pid_before):
            break
        time.sleep(.2)
    tr = time.time()
    res['engine_restarted'] = pid not in ('0', pid_before)
    # The pre-restart engine still holds the scan's flows and may re-add the client before it stops: record that and
    # delete again, so the new engine's first conntrack poll (several seconds after its start) is what is tested.
    res['readded_by_old_engine_before_restart'] = CLIENT in element_map()
    if res['readded_by_old_engine_before_restart']:
        snap(out_dir, '3a-readded-by-pre-restart-engine')
        run('nft', 'delete', 'element', 'inet', 'minifw', 'minifw_block_v4', '{', CLIENT, '}')
        res['second_hand_delete_at'] = stamp()
    res.update(engine_pid_before=pid_before, engine_pid_after=pid, engine_restarted_at=stamp(), seconds_apply_to_restart=round(tr - ta, 1))
    res['conntrack_at_restart'] = conntrack_client(out_dir, '3-at-engine-restart')
    snap(out_dir, '3-engine-restarted')
    rebl = None
    while time.time() < max(ta, tr) + 30:
        if CLIENT in element_map() and rebl is None:
            rebl = time.time()
            snap(out_dir, '3x-REBLOCKED-after-restart')
        time.sleep(.5)
    res['conntrack_after_30s'] = conntrack_client(out_dir, '4-after-30s')
    snap(out_dir, '4-30s-after-apply-and-restart')
    res.update(reblocked_after_restart=rebl is not None, reblocked_after_s=round(rebl - tr, 1) if rebl else None,
               watched_until=stamp(), watched_s_after_restart=round(time.time() - tr, 1))
    journal = journal_since(since)
    (out_dir / 'journal-minifw-ai.txt').write_text(journal)
    res['hard_gate_lines'] = [x for x in journal.splitlines() if 'HARD_GATE' in x]
    p1.terminate(); p1.wait(timeout=5)
    rows = [json.loads(x) for x in EVENTS.read_text().splitlines()[mark:]]
    post = [{k: r.get(k) for k in KEEP} for r in rows if r.get('client_ip') == CLIENT
            and __import__('datetime').datetime.fromisoformat(r['ts']).timestamp() >= tr]
    res['post_restart_client_events'] = dict(count=len(post), actions=sorted({str(r['action']) for r in post}),
                                             reasons=sorted({x for r in post for x in (r['reasons'] or [])}))
    res['restart_test_valid'] = res['engine_restarted'] and res['conntrack_at_restart']['distinct_dports'] >= 15 and len(post) > 0
    res['first_poll_after_restart'] = [x for x in journal.splitlines() if '[FLOW]' in x or '[STATE]' in x][-6:]
    # Fresh scan from the same client: must be isolated again.
    res['scan2_start'] = stamp(); t2 = time.time()
    p2 = scan(out_dir, 'fresh')
    tf = wait_member(CLIENT, 30)
    res['live_blocks'] = live_blocks(out_dir, dash, CLIENT) if tf else None
    res['scan2_isolated'] = tf is not None
    res['scan2_isolated_after_s'] = round(tf - t2, 1) if tf else None
    snap(out_dir, '5-isolated-by-fresh-scan')
    res['conntrack_at_fresh_isolation'] = conntrack_client(out_dir, '5-fresh')
    if checks == 'yes':
        try:
            res['dashboard'] = dashboard_checks(out_dir, dash, CLIENT)
        except Exception as error:  # Step 7 must not stop the step 4 record.
            res['dashboard_error'] = repr(error)
    time.sleep(6)
    rows = [json.loads(x) for x in EVENTS.read_text().splitlines()[mark:]]
    mine = [{k: r.get(k) for k in KEEP} for r in rows if r.get('client_ip') == CLIENT]
    (out_dir / 'events-client.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in mine))
    res['block_events'] = [r for r in mine if r['action'] == 'block']
    p2.terminate(); p2.wait(timeout=5)
    run('nft', 'delete', 'element', 'inet', 'minifw', 'minifw_block_v4', '{', CLIENT, '}', check=False)
    run('conntrack', '-D', '-s', CLIENT, check=False)
    snap(out_dir, '6-cleanup')
    if repeat:  # finding 3 again: does the running engine re-add the hand-deleted client? then a clean engine.
        tc, res['readded_after_cleanup_delete_after_s'] = time.time(), None
        while time.time() < tc + 12:
            if CLIENT in element_map():
                res['readded_after_cleanup_delete_after_s'] = round(time.time() - tc, 1)
                snap(out_dir, '6a-readded-by-running-engine')
                break
            time.sleep(.5)
        fresh_engine(out_dir, '7-post')
        res['client_isolated_at_end'] = CLIENT in element_map()
    with POLICY.open('wb') as f:  # dashboard Save rewrote the policy: shipped bytes back (same inode)
        f.write((ORIG / POLICY.name).read_bytes())
    res['policy_restored'] = sha(POLICY) == sha(ORIG / POLICY.name)
    (out_dir / 'results.json').write_text(json.dumps(res, indent=2))
    print(json.dumps({k: v for k, v in res.items() if k not in ('block_events',)}, indent=1), flush=True)
    for b in res['block_events']:
        print('BLOCK', b['ts'], b['reasons'], b['decision_owner'], flush=True)


def gap():
    """Step 5: policy without ai_enforcement + approval line: WARNING at start, 60/min client stays shadow_only, not isolated."""
    out_dir = OUT / 'gap'
    out_dir.mkdir()
    ip = '10.10.0.160'
    text = (ORIG / POLICY.name).read_text().replace(*POLICY_EDITS[0])  # lab clients -> internal, as in the boundary run
    policy = json.loads(text)
    policy.pop('ai_enforcement')
    with POLICY.open('w') as f:  # Same inode
        f.write(json.dumps(policy, indent=2) + '\n')
    approve()
    (out_dir / 'policy.diff').write_text(subprocess.run(['diff', '-u', str(ORIG / POLICY.name), str(POLICY)], capture_output=True, text=True).stdout)
    run('nft', 'delete', 'element', 'inet', 'minifw', 'minifw_block_v4', '{', ip, '}', check=False)
    mark = len(EVENTS.read_text().splitlines())
    since = time.strftime('%Y-%m-%d %H:%M:%S')
    run('systemctl', 'stop', 'minifw-ai')
    run('conntrack', '-D', '-s', ip, check=False)
    STATE.unlink(missing_ok=True)  # start in AI_ENHANCED as in the boundary run, so the AI window actually scores
    run('systemctl', 'start', 'minifw-ai')
    until = time.monotonic() + 60
    while f'sha256={MODEL_SHA}' not in run('journalctl', '-u', 'minifw-ai', '--since', since, '--no-pager', '-o', 'cat', check=False):
        assert time.monotonic() < until, 'model not loaded'
        time.sleep(.5)
    time.sleep(11)
    snap(out_dir, 'before-client')
    health = json.loads(Path('/opt/minifw_ai/logs/runtime-health.json').read_text())
    launched = time.time()
    p = subprocess.Popen(['ip', 'netns', 'exec', 'mf-client', '/usr/bin/python3', str(W / 'rate_client.py'), ip, '1.0', '90',
                          str(out_dir / 'client-60pm.jsonl'), 'new'])
    hit = None
    while p.poll() is None:
        if ip in element_map() and hit is None:
            hit = time.time()
            snap(out_dir, 'ISOLATED')
        time.sleep(.5)
    time.sleep(6)
    snap(out_dir, 'after-client')
    journal = journal_since(since)
    (out_dir / 'journal-minifw-ai.txt').write_text(journal)
    rows = [json.loads(x) for x in EVENTS.read_text().splitlines()[mark:]]
    mine = [{k: r.get(k) for k in KEEP} for r in rows if r.get('client_ip') == ip]
    (out_dir / 'events-test-ip.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in mine))
    client = [json.loads(x) for x in (out_dir / 'client-60pm.jsonl').read_text().splitlines()]
    res = dict(test='C21 upgrade gap: policy without ai_enforcement, approval line set', ip=ip, rate_per_min=60, duration_s=90,
               attempts=len(client), connected_ok=sum(c['status'] is not None for c in client), isolated=hit is not None,
               warning_lines=[x for x in journal.splitlines() if 'WARNING' in x and 'AI_WINDOW' in x],
               state_lines=[x for x in journal.splitlines() if '[STATE]' in x][-4:],
               runtime_health_ai_window=health.get('ai_window'), runtime_health_protection_state=health.get('protection_state'),
               segments=sorted({r['segment'] for r in mine if r['segment']}), modes=sorted({str(r['ai_window_mode']) for r in mine}),
               max_n60=max((r['ai_window_n60'] for r in mine if r['ai_window_n60'] is not None), default=None),
               max_probability=max((r['ai_window_probability'] for r in mine if r['ai_window_probability'] is not None), default=None),
               block_events=[r for r in mine if r['action'] == 'block'], events=len(mine))
    run('nft', 'delete', 'element', 'inet', 'minifw', 'minifw_block_v4', '{', ip, '}', check=False)
    run('systemctl', 'stop', 'minifw-ai')
    for path in (POLICY, ENV):
        with path.open('wb') as f:  # Same inode: owner and mode unchanged.
            f.write((ORIG / path.name).read_bytes())
    res['policy_env_restored'] = sha(POLICY) == sha(ORIG / POLICY.name) and sha(ENV) == sha(ORIG / ENV.name)
    run('systemctl', 'start', 'minifw-ai')
    (out_dir / 'results.json').write_text(json.dumps(res, indent=2))
    print(json.dumps(res, indent=1), flush=True)



def backuprestore(label='backup-restore'):
    """Step 6: backup.sh then restore.sh on 2.2.12. The archive holds the env secret and the licence, so only member
    names/sizes and per-file match booleans are recorded (hashes only for non-secret files), and it is deleted after."""
    import tarfile
    out_dir = OUT / label
    out_dir.mkdir()
    secret = {'etc/minifw/minifw.env', 'var/lib/minifw-ai/minifw.db', 'var/lib/minifw-ai/license.json'}
    probe = Path('/opt/minifw_ai/config/feeds/allow_domains.txt')
    res = dict(test='C21 backup.sh -> restore.sh on 2.2.12', package=run('dpkg-query', '-W', 'minifw-ai').strip())
    def services():
        return {u: run('systemctl', 'is-active', u, check=False).strip() for u in ('minifw-ai', 'minifw-ai-web')}
    res['services_before'] = services()
    b = subprocess.run(['/opt/minifw_ai/scripts/backup.sh'], capture_output=True, text=True, timeout=300)
    archive = Path(b.stdout.split()[1]) if b.stdout.startswith('BACKUP') else None
    res.update(backup_rc=b.returncode, backup_stdout=b.stdout.strip(), backup_stderr=b.stderr.strip()[-300:], services_after_backup=services())
    st = archive.stat()
    res['archive_owner_mode'] = f'{st.st_uid}:{st.st_gid} {oct(st.st_mode & 0o777)}'
    with tarfile.open(archive) as tar:
        members = [(m.name, m.size) for m in tar.getmembers()]
        meta = json.load(tar.extractfile('minifw-backup.json'))
    entries = meta['entries']
    res['archive_members'] = len(members)
    res['archive_meta'] = {k: v for k, v in meta.items() if k != 'entries'}
    (out_dir / 'archive-members.txt').write_text(''.join(f'{n}\t{s}\n' for n, s in members))
    def matches():
        return {n: Path('/' + n).is_file() and sha('/' + n) == e['sha256'] for n, e in entries.items()}
    res['match_after_backup'] = all(matches().values())
    res['mismatch_after_backup'] = [n for n, ok in matches().items() if not ok]  # names only
    with probe.open('a') as f:  # deliberate change, so the restore is seen to restore something
        f.write('# c21-restore-probe\n')
    res['probe_changed_before_restore'] = not matches()['opt/minifw_ai/config/feeds/allow_domains.txt']
    r = subprocess.run(['/opt/minifw_ai/scripts/restore.sh', str(archive)], capture_output=True, text=True, timeout=300)
    res.update(restore_rc=r.returncode, restore_stdout=r.stdout.strip(), restore_stderr=r.stderr.strip()[-300:])
    time.sleep(8)
    res['services_after_restore'] = services()
    after = matches()
    res['all_entries_match_archive_after_restore'] = all(after.values())
    res['mismatches_after_restore'] = [n for n, ok in after.items() if not ok]
    res['secret_files_present_and_match'] = {n: after.get(n) for n in sorted(secret)}
    res['nonsecret_sha256_after_restore'] = {n: e['sha256'] for n, e in sorted(entries.items()) if n not in secret and n.startswith(('opt/minifw_ai/config/', 'etc/systemd'))}
    res['dpkg_verify'] = subprocess.run(['dpkg', '--verify', 'minifw-ai'], capture_output=True, text=True).stdout.strip() or 'clean'
    try:
        Dashboard()
        res['dashboard_login_after_restore'] = True
    except Exception as error:
        res['dashboard_login_after_restore'] = repr(error)
    archive.unlink()
    res['archive_deleted'] = not archive.exists()
    (out_dir / 'results.json').write_text(json.dumps(res, indent=2))
    print(json.dumps(res, indent=1), flush=True)


def exports():
    """Step 7 exports again with a long client timeout (the 20 s one in restartfb timed out on the PDF)."""
    out_dir = OUT / 'exports'
    out_dir.mkdir(exist_ok=True)
    dash = Dashboard()
    dash.timeout = 600
    res = {}
    for fmt in ('csv', 'pdf'):
        t0 = time.time()
        status, _, body = dash.call('GET', f'/admin/api/events/download?fmt={fmt}&action_filter=block')
        res[fmt] = dict(status=status, seconds=round(time.time() - t0, 1), bytes=len(body))
        (out_dir / f'events-block-export.{fmt}').write_bytes(body)
    (out_dir / 'results.json').write_text(json.dumps(res, indent=2))
    print(json.dumps(res), flush=True)



def rows(label):
    """Detection Mode / Connection-rate AI rows as rendered now, next to the engine's runtime-health state."""
    import re
    health = json.loads(Path('/opt/minifw_ai/logs/runtime-health.json').read_text())
    status, _, body = Dashboard().call('GET', '/admin/')
    text = body.decode('utf-8', 'replace')
    found = {}
    for name in ('Detection Mode', 'Connection-rate AI'):
        m = re.search(re.escape(name) + r'</span>\s*<span[^>]*>([^<]*)</span>', text)
        found[name] = m.group(1).strip() if m else None
    res = dict(at=stamp(), http=status, rows=found, protection_state=health.get('protection_state'), ai_window=health.get('ai_window'),
               forbidden_found=[w for w in ('Ransomware', 'FRAUD', 'Banking trojan', 'Math.random') if w in text])
    (OUT / f'rows-{label}.json').write_text(json.dumps(res, indent=2))
    print(json.dumps(res), flush=True)


def exportall():
    """Step 7 repeat: all-events CSV and PDF exports without a client timeout (durations), and whether the loopback
    transfer again gets 127.0.0.1 isolated (unexpected 1). Bodies are not kept (5+ MB); any 127.0.0.1 element is removed."""
    out_dir = OUT / 'exportall'
    out_dir.mkdir()
    loop = '127.0.0.1'
    since = time.strftime('%Y-%m-%d %H:%M:%S')
    snap(out_dir, '0-before')
    res = dict(at=stamp(), loopback_isolated_before=loop in element_map())
    dash = Dashboard()
    dash.timeout = 900
    for fmt in ('csv', 'pdf'):
        t0 = time.time()
        status, _, body = dash.call('GET', f'/admin/api/events/download?fmt={fmt}&action_filter=all')
        res[fmt] = dict(status=status, seconds=round(time.time() - t0, 1), bytes=len(body), start=body[:5].decode('latin-1'),
                        pdf_eof=body.rstrip().endswith(b'%%EOF') if fmt == 'pdf' else None,
                        csv_header=next((x for x in body.decode('utf-8', 'replace').splitlines() if not x.startswith('#')), None) if fmt == 'csv' else None,
                        csv_rows=body.count(b'\n') if fmt == 'csv' else None)
        res[fmt]['loopback_isolated_after'] = loop in element_map()
    adds, t1, clear_since = [], time.time(), None
    while time.time() < t1 + 180:  # watch for 127.0.0.1; delete each time; stop after 25 s clear
        if loop in element_map():
            adds.append(stamp())
            snap(out_dir, f'loopback-isolated-{len(adds)}')
            run('nft', 'delete', 'element', 'inet', 'minifw', 'minifw_block_v4', '{', loop, '}', check=False)
            clear_since = None
        elif clear_since is None:
            clear_since = time.time()
        elif time.time() - clear_since > 25:
            break
        time.sleep(.5)
    res['loopback_element_seen_and_deleted_at'] = adds
    journal = journal_since(since)
    res['hard_gate_lines'] = [x.split(' - WARNING - ')[-1] for x in journal.splitlines() if 'HARD_GATE' in x]
    res['loopback_isolated_at_end'] = loop in element_map()
    snap(out_dir, '9-end')
    (out_dir / 'journal-minifw-ai.txt').write_text(journal)
    (out_dir / 'results.json').write_text(json.dumps(res, indent=2))
    print(json.dumps({k: v for k, v in res.items() if k != 'hard_gate_lines'}), len(res['hard_gate_lines']), flush=True)



def bulk():
    """Follow-up to unexpected 1: does one routed bulk HTTP download from a lab client trip the pps_saturation hard gate
    (any flow with >200 packets/s, main.py evaluate_hard_threat)? Shipped policy, fresh engine per rate."""
    out_dir = OUT / 'bulk'
    out_dir.mkdir()
    blobs = W / 'bulk'
    blobs.mkdir()
    run('truncate', '-s', '300M', str(blobs / 'blob'))
    run('systemd-run', '--unit=bc20-bulk', 'ip', 'netns', 'exec', 'mf-server', '/usr/bin/python3', '-m', 'http.server', '18080',
        '--bind', '198.18.0.2', '--directory', str(blobs))
    time.sleep(2)
    results = []
    for rate in ('100K', '250K', '500K', 'unlimited'):
        fresh_engine(out_dir, f'pre-{rate}')
        mark = len(EVENTS.read_text().splitlines())
        cmd = ['ip', 'netns', 'exec', 'mf-client', 'curl', '-s', '-o', '/dev/null', '--max-time', '20',
               '-w', '%{size_download} %{speed_download}', 'http://198.18.0.2:18080/blob']
        if rate != 'unlimited':
            cmd[5:5] = ['--limit-rate', rate]
        t0 = time.time()
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
        hit = None
        while p.poll() is None or time.time() < t0 + 28:
            if hit is None and CLIENT in element_map():
                hit = time.time()
                snap(out_dir, f'isolated-{rate}')
            time.sleep(.5)
        size, speed = (p.stdout.read().split() + ['0', '0'])[:2]
        rows = [json.loads(x) for x in EVENTS.read_text().splitlines()[mark:]]
        blocks = [{k: r.get(k) for k in KEEP} for r in rows if r.get('client_ip') == CLIENT and r.get('action') == 'block']
        results.append(dict(limit=rate, bytes=int(float(size)), avg_bytes_per_s=int(float(speed)), isolated=hit is not None,
                            seconds_to_isolation=round(hit - t0, 1) if hit else None, block_events=blocks,
                            conntrack=conntrack_client(out_dir, f'after-{rate}')))
        print(json.dumps({k: v for k, v in results[-1].items() if k != 'block_events'}),
              [(b['reasons'], b['decision_owner']) for b in blocks], flush=True)
    run('systemctl', 'stop', 'bc20-bulk', check=False)
    run('systemctl', 'reset-failed', 'bc20-bulk', check=False)
    (blobs / 'blob').unlink()
    blobs.rmdir()
    fresh_engine(out_dir, 'post')
    (out_dir / 'results.json').write_text(json.dumps(dict(test='routed bulk download vs pps_saturation, shipped policy', client=CLIENT,
                                                          results=results, isolated_at_end=CLIENT in element_map()), indent=2))



# F1 bulk (coordinator, 10:4x): legitimate bulk traffic vs the pps_saturation hard gate (>200 packets/s in one flow).
F1_CLIENTS = {'A': ['10.10.0.150', '10.10.0.151', '10.10.0.152', '10.10.0.153'],
              'B': ['10.10.0.154', '10.10.0.155', '10.10.0.156', '10.10.0.157']}
F1_CASES = [('dl_20MB_unpaced', '/mb20', 0, 30), ('dl_20MB_paced_4MBps', '/mb20', 4e6, 30),
            ('stream_2.5Mbps_60s', '/big', 312500, 60), ('control_2MB_unpaced', '/mb2', 0, 30)]
F1_CLIENT = """import http.client,json,sys,time
ip,path,rate,limit=sys.argv[1],sys.argv[2],float(sys.argv[3]),float(sys.argv[4])
c=http.client.HTTPConnection('198.18.0.2',18080,timeout=10,source_address=(ip,0));t0=time.time();c.request('GET',path);r=c.getresponse();n=0
chunk=int(rate/10) if rate else 1<<20
while time.time()-t0<limit:
 b=r.read(chunk)
 if not b: break
 n+=len(b)
 if rate: time.sleep(max(0,t0+n/rate-time.time()))
c.close();print(json.dumps(dict(ip=ip,path=path,status=r.status,bytes=n,seconds=round(time.time()-t0,2),start=t0)))
"""


def ct_packets():
    """Per client IP: orig+reply packet counters of its TCP flows to the lab HTTP server (port 18080)."""
    text = subprocess.run(['conntrack', '-L', '-p', 'tcp', '--dport', '18080'], capture_output=True, text=True).stdout
    found = {}
    for line in text.splitlines():
        toks = line.split()
        srcs = [x[4:] for x in toks if x.startswith('src=')]
        packets = [int(x[8:]) for x in toks if x.startswith('packets=')]
        if srcs and packets:
            found[srcs[0]] = found.get(srcs[0], 0) + sum(packets)
    return found


def f1bulk(label, offload):
    """Pass `label` (A: veth offloads as the lab default, B: TSO/GSO/GRO off so segments are MTU-sized like a NIC without
    receive coalescing). Shipped policy with only segment_subnets.internal + 10.10.0.128/25, no approval, shipped state file."""
    out_dir = OUT / f'f1-bulk-{label}'
    out_dir.mkdir()
    ips = F1_CLIENTS[label]
    text = (ORIG / POLICY.name).read_text().replace(*POLICY_EDITS[0])
    json.loads(text)
    with POLICY.open('w') as f:
        f.write(text)
    with ENV.open('wb') as f:  # shipped env bytes: no approval line
        f.write((ORIG / ENV.name).read_bytes())
    assert not approved()
    (out_dir / 'policy.diff').write_text(subprocess.run(['diff', '-u', str(ORIG / POLICY.name), str(POLICY)], capture_output=True, text=True).stdout)
    blobs = W / 'f1blobs'
    blobs.mkdir(exist_ok=True)
    (blobs / 'mb20').write_bytes(os.urandom(20 * 1024 * 1024))
    (blobs / 'mb2').write_bytes(os.urandom(2 * 1024 * 1024))
    run('truncate', '-s', '300M', str(blobs / 'big'))
    run('systemd-run', '--unit=bc20-f1http', 'ip', 'netns', 'exec', 'mf-server', '/usr/bin/python3', '-m', 'http.server', '18080',
        '--bind', '198.18.0.2', '--directory', str(blobs))
    for ip in ips:
        run('ip', '-n', 'mf-client', 'addr', 'add', ip + '/24', 'dev', 'mfc0', check=False)
    devs = [([], 'mfcg'), ([], 'mfsg'), (['ip', 'netns', 'exec', 'mf-client'], 'mfc0'), (['ip', 'netns', 'exec', 'mf-server'], 'mfs0')]
    if offload == 'off':
        for prefix, dev in devs:
            run(*prefix, '/usr/sbin/ethtool', '-K', dev, 'tso', 'off', 'gso', 'off', 'gro', 'off')
    (out_dir / 'offloads.txt').write_text('\n'.join(dev + ': ' + ' | '.join(x.strip() for x in run(*prefix, '/usr/sbin/ethtool', '-k', dev).splitlines()
                                                                   if x.split(':')[0].strip() in ('tcp-segmentation-offload', 'generic-segmentation-offload', 'generic-receive-offload'))
                                                for prefix, dev in devs) + '\n')
    # shipped state file and a fresh engine
    since = time.strftime('%Y-%m-%d %H:%M:%S')
    run('systemctl', 'stop', 'minifw-ai')
    for ip in ips:
        run('nft', 'delete', 'element', 'inet', 'minifw', 'minifw_block_v4', '{', ip, '}', check=False)
        run('conntrack', '-D', '-s', ip, check=False)
    STATE.write_bytes((ORIG / STATE.name).read_bytes())
    STATE.chmod(json.loads((ORIG / 'modes.json').read_text())[STATE.name])
    run('systemctl', 'start', 'minifw-ai')
    until = time.monotonic() + 60
    while 'Initial protection state' not in run('journalctl', '-u', 'minifw-ai', '--since', since, '--no-pager', '-o', 'cat', check=False):
        assert time.monotonic() < until, 'engine did not start'
        time.sleep(.5)
    time.sleep(8)
    snap(out_dir, '0-before')
    mark = len(EVENTS.read_text().splitlines())
    procs = {ip: subprocess.Popen(['ip', 'netns', 'exec', 'mf-client', '/usr/bin/python3', '-c', F1_CLIENT, ip, path, str(rate), str(limit)],
                                  stdout=subprocess.PIPE, text=True) for ip, (case, path, rate, limit) in zip(ips, F1_CASES)}
    t0 = time.time()
    samples, first = [], {}
    while any(p.poll() is None for p in procs.values()) or time.time() < t0 + 75:
        now, counts, elems = time.time(), ct_packets(), element_map()
        samples.append((now, counts))
        for ip in ips:
            if ip in elems and ip not in first:
                first[ip] = dict(seen=now, element=elems[ip])
                snap(out_dir, f'isolated-{ip}')
        time.sleep(1)
    snap(out_dir, '9-end')
    journal = journal_since(since)
    (out_dir / 'journal-minifw-ai.txt').write_text(journal)
    rows = [json.loads(x) for x in EVENTS.read_text().splitlines()[mark:]]
    (out_dir / 'samples.json').write_text(json.dumps([[round(t, 2), c] for t, c in samples]))
    results = []
    for ip, (case, path, rate, limit) in zip(ips, F1_CASES):
        client = json.loads(procs[ip].stdout.read() or '{}')
        series = [(t, c[ip]) for t, c in samples if ip in c]
        pps5 = [round((b[1] - a[1]) / (b[0] - a[0]), 1) for i, a in enumerate(series) for b in series[i + 1:] if 4.5 <= b[0] - a[0] <= 5.5]
        mine = [r for r in rows if r.get('client_ip') == ip]
        blocks = [{k: r.get(k) for k in KEEP} for r in mine if r.get('action') == 'block']
        hit = first.get(ip)
        results.append(dict(case=case, ip=ip, client=client, isolated=hit is not None,
                            seconds_to_isolation=round(hit['seen'] - client.get('start', t0), 1) if hit else None,
                            nft_element=hit['element'] if hit else None, reasons=blocks[0]['reasons'] if blocks else None,
                            decision_owner=blocks[0]['decision_owner'] if blocks else None, block_events=len(blocks), events=len(mine),
                            segment=sorted({r.get('segment') for r in mine if r.get('segment')}),
                            conntrack_packets_total=series[-1][1] if series else None,
                            max_pps_5s_window_conntrack=max(pps5, default=None),
                            hard_gate_lines=[x.split(' - WARNING - ')[-1] for x in journal.splitlines() if 'HARD_GATE' in x and ip + ' ' in x][:3]))
    # cleanup: elements this test caused, conntrack, server, offloads, blobs
    removed = []
    for ip in ips:
        if ip in element_map():
            removed.append(ip)
        run('nft', 'delete', 'element', 'inet', 'minifw', 'minifw_block_v4', '{', ip, '}', check=False)
        run('conntrack', '-D', '-s', ip, check=False)
    run('systemctl', 'stop', 'bc20-f1http', check=False)
    run('systemctl', 'reset-failed', 'bc20-f1http', check=False)
    # Offloads are not switched back: the lab veths are deleted by `restore`.
    for name in ('mb20', 'mb2', 'big'):
        (blobs / name).unlink()
    snap(out_dir, '10-after-cleanup')
    out = dict(test=f'F1 bulk pass {label}: legitimate bulk traffic vs pps_saturation (>200 pkt/s in one flow)', offloads=offload,
               policy='shipped + segment_subnets.internal 10.10.0.128/25 only; no approval; shipped state file',
               elements_deleted_by_test=removed, results=results)
    (out_dir / 'results.json').write_text(json.dumps(out, indent=2))
    for r in results:
        print(json.dumps({k: v for k, v in r.items() if k not in ('hard_gate_lines',)}), flush=True)


{'setup': setup, 'f1bulk': lambda: f1bulk(*sys.argv[2:4]), 'bulk': bulk, 'rows': lambda: rows(sys.argv[2]), 'exportall': exportall, 'exports': exports, 'edit': edit, 'run': lambda: test(*sys.argv[2:4]), 'restartfb': lambda: restartfb(*sys.argv[2:5]), 'gap': gap, 'backuprestore': lambda: backuprestore(*sys.argv[2:3]),
 'restore': restore}[sys.argv[1]]()
