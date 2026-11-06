"""C20 (2.2.11) client-window AI acceptance in the Monday lab guests. Fictional sandbox; not institution traffic.

Shipped collector config (DNS file source + conntrack 5 s polls, no packet sensor), AI state enabled.
A DNS feeder (10.10.0.70, every 4 s) keeps DNS telemetry healthy so the engine stays in AI_ENHANCED_PROTECTION.
Actors come from heldout_client.py: tool = ~8 guesses/s (malicious), human = paced visits (benign).
Approval is set with a test-only systemd drop-in (95-c20-ai-test.conf), removed afterwards.
Corrupt/missing model use MINIFW_AI_WINDOW_MODEL pointing at lab files, so the packaged model file is never touched.
The lab harness pins 2.2.10; this driver loads it with that one assertion changed to 2.2.11 (nothing else).
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
import types

edition, package, source = sys.argv[1:4]
only = set(sys.argv[4].split(',')) if len(sys.argv) > 4 else None
assert edition in {'education', 'financial'} and socket.gethostname() == 'minifw-monday-' + edition and os.geteuid() == 0
assert subprocess.check_output(['systemd-detect-virt'], text=True).strip() in {'kvm', 'qemu'}
testing = Path(source) / 'testing'
sys.path.insert(0, str(testing))
harness = testing / 'lab_gateway_acceptance.py'
text = harness.read_text()
PIN = 'assert installed == "2.2.10-" + sector, "Only v2.2.10 may be tested"'
assert text.count(PIN) == 1
gateway = types.ModuleType('lab_gateway_acceptance')
gateway.__file__ = str(harness)
sys.modules['lab_gateway_acceptance'] = gateway
exec(compile(text.replace(PIN, PIN.replace('2.2.10', '2.2.11')), str(harness), 'exec'), gateway.__dict__)
import lab_extended_acceptance as extended

MODE = 'minifw_school' if edition == 'education' else 'minifw_financial'
STATE = Path('/opt/minifw_ai/logs/deployment_state.json')
SWITCH = Path('/etc/systemd/system/minifw-ai.service.d/95-c20-ai-test.conf')
MODEL = Path('/opt/minifw_ai/models/client_window_v1.json')
MODEL_SHA = 'd06ce40ea3276d2cedac9e354075c4aa74aa3987e08b35e40a95451d4e69d6ee'
OTHER_SHA = hashlib.sha256(Path('/opt/minifw_ai/models/mlp_packet14.pkl').read_bytes()).hexdigest()
CLIENT_SCRIPT = Path(__file__).with_name('heldout_client.py')
SEED = 5000 if edition == 'education' else 6000
FEEDER = '10.10.0.70'
START = dict(source='file', packet=False, ai=True)
KEEP = ('ts', 'client_ip', 'dst_ip', 'dst_port', 'segment', 'action', 'reasons', 'decision_owner', 'score',
        'ai_window_n60', 'ai_window_probability', 'ai_window_mode', 'ai_window_model_sha256')
DNS_LOOP = '''import socket,struct,sys,time
q=struct.pack("!HHHHHH",4321,0x100,1,0,0,0)+b"\\x06feeder\\x08approved\\x04test\\x00\\x00\\x01\\x00\\x01"
while True:
 try:
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(1); s.bind((sys.argv[1],0)); s.sendto(q,("10.10.0.1",53)); s.recvfrom(512); s.close()
 except OSError: pass
 time.sleep(4)
'''
HOLD = '''import socket,sys,time
c=[socket.create_connection(("198.18.0.2",int(sys.argv[3])),timeout=3,source_address=(sys.argv[1],0)) for _ in range(int(sys.argv[2]))]
print(len(c),flush=True); time.sleep(300)
'''
PROBE = '''import socket,sys
try:
 socket.create_connection(("198.18.0.2",8080),timeout=3,source_address=(sys.argv[1],0)).close(); print("allowed")
except OSError as e: print("failed:"+type(e).__name__)
'''


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def exercise(root, run, start, record, nft, ns, member, children):
    events = root / 'events.jsonl'
    policy_path = root / 'policy.json'
    base = json.loads(policy_path.read_text())
    active_has_ai = 'ai_enforcement' in base
    if not active_has_ai:  # Active policy kept from C19 (conffile): use the C20 shipped block, labelled.
        base['ai_enforcement'] = json.loads((Path(source) / 'config/modes' / MODE / 'policy.json').read_text())['ai_enforcement']
    record('c20_policy_basis', active_policy_has_ai_enforcement=active_has_ai,
           ai_enforcement={k: v for k, v in base['ai_enforcement'].items() if k != '_note'},
           harness_changes='ip_timeout_seconds=15 (baseline expiry), lab collector paths', model_sha256=sha(MODEL))
    assert sha(MODEL) == MODEL_SHA
    corrupt = root / 'corrupt-window-model.json'
    corrupt.write_bytes(MODEL.read_bytes()[:40])

    def rows(mark=0):
        if not events.exists():
            return []
        return [json.loads(x) for x in events.read_text().splitlines()[mark:]]

    def isolated(ip):
        return subprocess.run(['nft', 'get', 'element', 'inet', 'minifw', 'minifw_block_v4', '{', ip, '}'],
                              capture_output=True).returncode == 0

    def journal(since):
        return run('journalctl', '-u', 'minifw-ai', '--since', since, '--no-pager', '-o', 'cat', check=False).stdout

    def boot(approval='', model=None, segments=None, ips=()):
        run('systemctl', 'stop', 'minifw-ai')
        for ip in ips:
            run('conntrack', '-D', '-s', ip, check=False)
        policy = json.loads(json.dumps(base))
        if segments is not None:
            policy['ai_enforcement']['segments'] = segments
        policy_path.write_text(json.dumps(policy, indent=2))
        STATE.unlink(missing_ok=True)  # Controlled initial state AI_ENHANCED; restored by this driver afterwards.
        lines = [f'Environment=MINIFW_AI_ENFORCE_MODEL_SHA256={approval}\n']
        if model:
            lines.append(f'Environment=MINIFW_AI_WINDOW_MODEL={model}\n')
        SWITCH.write_text('[Service]\n' + ''.join(lines))
        mark, since = len(rows()), time.strftime('%Y-%m-%d %H:%M:%S')
        last['since'] = since
        start(**START)
        return mark, since, time.monotonic()

    def actors(plan, booted):
        time.sleep(max(0, booted + 12 - time.monotonic()))  # Engine ignores flows first seen in its first 10 s.
        procs = []
        for index, (kind, ip, count) in enumerate(plan):
            procs.append(subprocess.Popen(['ip', 'netns', 'exec', 'mf-client', '/usr/bin/python3', str(CLIENT_SCRIPT), kind, ip,
                                           str(SEED + index + int(ip.rsplit('.', 1)[1])), str(count), '0',
                                           str(root / f'actor-{ip}.jsonl'), str(testing)]))
        children.extend(procs)
        return procs

    def watch(procs, ips, seconds, stop_when=None):
        first = {}
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            for ip in ips:
                if ip not in first and isolated(ip):
                    first[ip] = time.time()
            if stop_when and stop_when(first):
                break
            time.sleep(.5)
        return first

    def stop(procs):
        for p in procs:
            if p.poll() is None:
                p.terminate()
                p.wait(timeout=5)

    def extract(name, mark, ips):
        picked = [{k: r.get(k) for k in KEEP} for r in rows(mark) if r.get('client_ip') in ips]
        (root / f'c20-events-{name}.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in picked))
        return picked

    def scored(picked, ip):
        return [r for r in picked if r['client_ip'] == ip and r['ai_window_n60'] is not None]

    def probe(ip):
        return run('ip', 'netns', 'exec', 'mf-client', '/usr/bin/python3', '-c', PROBE, ip, check=False).stdout.strip()

    def element(ip):
        return run('nft', 'get', 'element', 'inet', 'minifw', 'minifw_block_v4', '{', ip, '}', check=False).stdout.strip()

    last = {}
    plain_record = record

    def record(name, **kw):  # Every scenario records the AI protection state it actually ran in.
        if last:
            saved = json.loads(STATE.read_text()).get('current_protection_state') if STATE.exists() else None
            lines = [x for x in journal(last['since']).splitlines() if '[STATE]' in x]
            kw['ai_state'] = dict(state_file_after=saved or 'absent (no transition since boot)', journal=lines[-3:],
                                  stayed_ai_enhanced=saved in (None, 'AI_ENHANCED_PROTECTION') and not any('BASELINE' in x for x in lines))
        plain_record(name, **kw)

    all_ips = [f'10.10.0.{n}' for n in range(81, 100)]
    for ip in all_ips + [FEEDER]:
        run('ip', '-n', 'mf-client', 'addr', 'add', ip + '/24', 'dev', 'mfc0')
    feeder = subprocess.Popen(['ip', 'netns', 'exec', 'mf-client', '/usr/bin/python3', '-c', DNS_LOOP, FEEDER])
    children.append(feeder)

    def shadow_case(name, tool, humans, approval, expect_mode, segments=None):
        ips = [tool] + humans
        mark, since, booted = boot(approval=approval, segments=segments, ips=ips)
        procs = actors([('tool', tool, 300)] + [('human', h, 8) for h in humans], booted)
        hit = watch(procs, ips, 40, stop_when=lambda f: False)
        nft(f'c20-{name}')
        stop(procs)
        time.sleep(1)
        picked = extract(name, mark, ips)
        tool_rows = scored(picked, tool)
        top = max(tool_rows, key=lambda r: r['ai_window_n60'], default=None)
        assert top and top['ai_window_n60'] >= 39 and top['ai_window_probability'] >= .9, top
        assert all(r['ai_window_mode'] == expect_mode for r in tool_rows), {r['ai_window_mode'] for r in tool_rows}
        assert not hit and not any('ai_window_rate' in (r['reasons'] or []) for r in picked), hit
        record(f'c20_{name}', tool=tool, humans=humans, approval=approval or 'none', mode=expect_mode,
               segment=top['segment'], max_n60=top['ai_window_n60'], max_probability=top['ai_window_probability'],
               tool_scored_events=len(tool_rows), isolated_ips=sorted(hit), tool_routed_after=probe(tool),
               decided_by=f'tool n60>={top["ai_window_n60"]} p={top["ai_window_probability"]:.3f}, mode {expect_mode}, no nft element for any actor')

    def enforce_case(name, tool, humans, segments=None, note=None):
        ips = [tool] + humans
        mark, since, booted = boot(approval=MODEL_SHA, segments=segments, ips=ips)
        procs = actors([('tool', tool, 300)] + [('human', h, 8) for h in humans], booted)
        hit = watch(procs, ips, 40, stop_when=lambda f: tool in f)
        assert tool in hit, 'Approved model did not isolate the fast guesser'
        elem = element(tool)
        routed = probe(tool)
        human_routed = {h: probe(h) for h in humans}
        hit.update(watch(procs, humans, 15))  # Humans keep running alongside the isolated tool.
        nft(f'c20-{name}')
        stop(procs)
        time.sleep(1)
        picked = extract(name, mark, ips)
        blocks = [r for r in picked if r['client_ip'] == tool and r['action'] == 'block']
        assert blocks, 'No block event for the tool'
        b = blocks[0]
        assert 'ai_window_rate' in b['reasons'] and b['decision_owner'] == 'AI Engine (client window)', b
        assert b['ai_window_mode'] == 'enforcing' and b['ai_window_n60'] >= 39 and b['ai_window_probability'] >= .9, b
        assert 'timeout 15m' in elem, elem
        assert routed.startswith('failed'), routed
        assert not any(h in hit for h in humans) and all(v == 'allowed' for v in human_routed.values()), (hit, human_routed)
        record(f'c20_{name}', tool=tool, humans=humans, approval='exact model SHA', segment=b['segment'],
               ai_enforcement_segments=segments or base['ai_enforcement']['segments'], lab_policy_change=note,
               block_event=b, nft_element=elem, tool_routed_after=routed, humans_routed=human_routed,
               isolated_ips=sorted(hit),
               decided_by='block event reason ai_window_rate + owner AI Engine (client window); nft element timeout 15m; tool routed connect failed; humans not in set')

    def scope_case(name, tool, humans):
        ips = [tool] + humans
        mark, since, booted = boot(approval=MODEL_SHA, ips=ips)
        procs = actors([('tool', tool, 300)] + [('human', h, 8) for h in humans], booted)
        hit = watch(procs, ips, 40)
        nft(f'c20-{name}')
        stop(procs)
        time.sleep(1)
        picked = extract(name, mark, ips)
        tool_rows = scored(picked, tool)
        top = max(tool_rows, key=lambda r: r['ai_window_n60'], default=None)
        assert top and top['ai_window_n60'] >= 39 and top['ai_window_probability'] >= .9, top
        assert all(r['ai_window_mode'] == 'enforcing' and r['segment'] == 'dmz' for r in tool_rows)
        assert not hit and not any('ai_window_rate' in (r['reasons'] or []) for r in picked), hit
        record(f'c20_{name}', tool=tool, humans=humans, approval='exact model SHA', segment='dmz',
               ai_enforcement_segments=base['ai_enforcement']['segments'], max_n60=top['ai_window_n60'],
               max_probability=top['ai_window_probability'], isolated_ips=[], tool_routed_after=probe(tool),
               decided_by='mode enforcing, p>=0.9, but segment dmz not listed: no block event, no nft element')

    def model_fault_case(name, model, tool):
        mark, since, booted = boot(approval=MODEL_SHA, model=model, ips=[tool, gateway.CLIENT])
        procs = actors([('tool', tool, 300)], booted)
        hit = watch(procs, [tool], 25)
        stop(procs)
        active = run('systemctl', 'is-active', 'minifw-ai', check=False).stdout.strip()
        picked = extract(name, mark, [tool, gateway.CLIENT])
        tool_rows = [r for r in picked if r['client_ip'] == tool]
        assert active == 'active' and tool_rows, (active, len(tool_rows))
        assert all(r['ai_window_mode'] == 'not_run' and r['ai_window_probability'] is None for r in tool_rows)
        assert tool not in hit
        log = journal(since)
        scan_log = (root / f'c20-scan-{name}.log').open('w')
        scan = subprocess.Popen(['ip', 'netns', 'exec', 'mf-client', '/usr/bin/python3', gateway.__file__, 'client', 'scan',
                                 gateway.SERVER], stdout=scan_log, stderr=scan_log)
        children.append(scan)
        until = time.monotonic() + 25
        while not member() and time.monotonic() < until:
            time.sleep(.2)
        nft(f'c20-{name}')
        scan.send_signal(signal.SIGTERM)
        scan.wait(timeout=5)
        scan_log.close()
        assert member(), f'{name}: baseline scan control did not isolate'
        reasons = next(r for r in reversed(rows(mark)) if r.get('action') == 'block' and r.get('client_ip') == gateway.CLIENT)['reasons']
        assert 'port_scan' in reasons
        warn = [x for x in log.splitlines() if '[AI_WINDOW]' in x]
        record(f'c20_{name}', engine_active=True, model_env=str(model), tool=tool, tool_events=len(tool_rows),
               ai_window_mode='not_run', tool_isolated=False, journal_ai_window=warn[-2:], baseline_scan_isolation=True,
               scan_reasons=reasons, decided_by='engine active; all tool events ai_window_mode not_run; port_scan block of 10.10.0.20')

    def restart_case(name, holder, count=60):
        run('systemctl', 'stop', 'minifw-ai')
        run('conntrack', '-D', '-s', holder, check=False)
        hold = subprocess.Popen(['ip', 'netns', 'exec', 'mf-client', '/usr/bin/python3', '-c', HOLD, holder, str(count), '20001'],
                                stdout=subprocess.PIPE, text=True)
        children.append(hold)
        assert hold.stdout.readline().strip() == str(count)
        opened = run('conntrack', '-L', '-s', holder, '-p', 'tcp', '--dport', '20001', check=False).stdout.count('ESTABLISHED')
        mark, since, booted = boot(approval=MODEL_SHA)  # Same as Save->Apply: engine restarts with flows already open.
        hit = watch([], [holder], 40)
        nft(f'c20-{name}')
        hold.terminate()
        hold.wait(timeout=5)
        picked = extract(name, mark, [holder])
        n60 = [r['ai_window_n60'] for r in picked if r['ai_window_n60'] is not None]
        assert not hit and not any(r['action'] == 'block' for r in picked), hit
        record(f'c20_{name}', holder=holder, held_connections=count, conntrack_established_before_start=opened,
               events=len(picked), counted_n60=n60[:5], isolated=False, observed_seconds=40,
               decided_by='no nft element and no block event for the holder in 40 s after start; flows from the start snapshot not counted')

    plans = [
        ('a_no_approval_shadow', lambda: shadow_case('a_no_approval_shadow', '10.10.0.81', ['10.10.0.82', '10.10.0.83'], '', 'shadow_only')),
    ]
    if edition == 'financial':
        plans.append(('b_shipped_dmz_out_of_scope', lambda: scope_case('b_shipped_dmz_out_of_scope', '10.10.0.84', ['10.10.0.85', '10.10.0.86'])))
        plans.append(('b_approved_isolation', lambda: enforce_case(
            'b_approved_isolation', '10.10.0.87', ['10.10.0.88', '10.10.0.89'],
            segments=base['ai_enforcement']['segments'] + ['dmz'],
            note='LAB POLICY COPY: "dmz" added to ai_enforcement.segments (shipped Financial policy leaves dmz out of AI scope)')))
    else:
        plans.append(('b_approved_isolation', lambda: enforce_case('b_approved_isolation', '10.10.0.87', ['10.10.0.88', '10.10.0.89'])))
    plans += [
        ('c_other_sha_shadow', lambda: shadow_case('c_other_sha_shadow', '10.10.0.90', ['10.10.0.91'], OTHER_SHA, 'shadow_only',
                                                   segments=base['ai_enforcement']['segments'] + (['dmz'] if edition == 'financial' else []))),
        ('d_corrupt_model', lambda: model_fault_case('d_corrupt_model', corrupt, '10.10.0.92')),
        ('d_missing_model', lambda: model_fault_case('d_missing_model', root / 'absent-window-model.json', '10.10.0.93')),
        ('e_restart_snapshot', lambda: restart_case('e_restart_snapshot', '10.10.0.95')),
    ]
    failures = []
    try:
        for name, case in plans:
            if only and name not in only:
                continue
            try:
                case()
            except Exception as error:  # Record and continue: each scenario stands alone.
                failures.append(name)
                record(f'c20_{name}', result='FAIL', error=f'{type(error).__name__}: {str(error)[:600]}')
    finally:
        SWITCH.unlink(missing_ok=True)
        run('systemctl', 'daemon-reload')
    record('c20_summary', failed=failures, scenarios=[n for n, _ in plans if not only or n in only])


extended.exercise = exercise
state_before = STATE.read_bytes() if STATE.exists() else None
state_mode = STATE.stat().st_mode & 0o777 if state_before is not None else None
units = ['dnsmasq', 'minifw-ai', 'minifw-ai-web']
active_before = [u for u in units if subprocess.run(['systemctl', 'is-active', '--quiet', u]).returncode == 0]
assert not SWITCH.exists(), 'Existing AI test override must be reviewed first'
try:
    gateway.acceptance(edition, package, extended=True)
finally:
    SWITCH.unlink(missing_ok=True)
    if state_before is None:
        STATE.unlink(missing_ok=True)
    else:
        STATE.write_bytes(state_before)
        STATE.chmod(state_mode)
    subprocess.run(['systemctl', 'daemon-reload'])
    for unit in active_before:
        subprocess.run(['systemctl', 'start', unit])
    print('DEPLOYMENT_STATE_RESTORED', 'absent' if state_before is None else hashlib.sha256(state_before).hexdigest(),
          'RESTARTED', active_before, flush=True)
