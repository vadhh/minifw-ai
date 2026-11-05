"""AI enforcement switch mechanism check with a TEST-ONLY always-threat model.

Proves model output -> policy decision -> kernel isolation only when root config approves the exact model hash,
and that missing/corrupt/unapproved models leave baseline protection running. Says nothing about detection quality.
The lab policy copy lowers block thresholds to 30 so the AI's maximum contribution alone crosses them;
shipped thresholds keep AI as an escalation-only contributor.
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

edition, package, source, patched = sys.argv[1:]
assert edition in {'education', 'financial'} and socket.gethostname() == 'minifw-monday-' + edition and os.geteuid() == 0
assert subprocess.check_output(['systemd-detect-virt'], text=True).strip() in {'kvm', 'qemu'}
sys.path.insert(0, str(Path(source) / 'testing'))
import lab_gateway_acceptance as gateway
import lab_extended_acceptance as extended

SECTOR = 'education' if edition == 'education' else 'finance'
MODE = 'minifw_school' if edition == 'education' else 'minifw_financial'
DROPIN = Path('/etc/systemd/system/minifw-ai.service.d/90-monday-lab.conf')
SWITCH = Path('/etc/systemd/system/minifw-ai.service.d/95-ai-switch-test.conf')
STATE = Path('/opt/minifw_ai/logs/deployment_state.json')
VENV = '/opt/minifw_ai/venv/bin/python'
MAKE_MODEL = '''import pickle,sys
import numpy as np,pandas as pd,sklearn
from sklearn.dummy import DummyClassifier
from sklearn.preprocessing import StandardScaler
sys.path.insert(0,'/opt/minifw_ai/app')
from minifw_ai.utils.mlp_engine import FEATURE_NAMES
names=FEATURE_NAMES[:14]
X=pd.DataFrame(np.random.default_rng(0).random((20,14)),columns=names)
scaler=StandardScaler().fit(X)
model=DummyClassifier(strategy='constant',constant=1).fit(scaler.transform(X),np.array([0,1]*10))
meta=dict(feature_schema='packet14-v1',sklearn_version=sklearn.__version__,feature_names=names,
          training_data='TEST-ONLY always-threat mechanism model; not a detector')
with open(sys.argv[1],'wb') as f: pickle.dump(dict(model=model,scaler=scaler,metadata=meta),f)
'''
TLS_LOOP = '''import http.client,json,ssl,sys,time
ok=0
for i in range(int(sys.argv[1])):
 try:
  c=http.client.HTTPSConnection('198.18.0.2',443,context=ssl._create_unverified_context(),timeout=2)
  c.request('GET','/'); r=c.getresponse(); r.read(); c.close(); ok+=1
 except OSError: pass
 time.sleep(.5)
print(json.dumps(dict(requests=int(sys.argv[1]),succeeded=ok)))
'''


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def exercise(root, run, start, record, nft, ns, member, children):
    events = root / 'events.jsonl'

    def rows():
        return [json.loads(x) for x in events.read_text().splitlines()] if events.exists() else []

    def boot(model, approval):
        run('systemctl', 'stop', 'minifw-ai')
        run('nft', 'flush', 'set', 'inet', 'minifw', 'minifw_block_v4', check=False)
        run('conntrack', '-D', '-s', gateway.CLIENT, check=False)
        STATE.unlink(missing_ok=True)  # Controlled initial AI state; harness restores the original.
        DROPIN.parent.mkdir(exist_ok=True)
        DROPIN.write_text('[Service]\n' + ''.join(f'Environment={k}={v}\n' for k, v in dict(
            MINIFW_POLICY=root / 'policy.json', MINIFW_LOG=events, MINIFW_AUDIT_LOG=root / 'audit.jsonl',
            MINIFW_FLOW_RECORDS=root / 'flows.jsonl', MINIFW_DNS_SOURCE='none', MINIFW_CONNTRACK_PATH='/proc/net/nf_conntrack',
            AI_ENABLED=1, DEGRADED_MODE=0, MINIFW_PACKET_INTERFACE='mfcg', MINIFW_DISABLE_FLOWS=0,
            MINIFW_SECTOR=SECTOR, PRODUCT_MODE=MODE).items()))
        SWITCH.write_text(f'[Service]\nEnvironment=PYTHONPATH={patched}/app\nEnvironment=MINIFW_MLP_MODEL={model}\n'
                          f'Environment=MINIFW_AI_ENFORCE_MODEL_SHA256={approval}\n')
        audit = root / 'audit.jsonl'
        before = audit.read_text().count('"daemon_start"') if audit.exists() else 0
        mark = len(rows())
        since = time.strftime('%Y-%m-%d %H:%M:%S')
        run('systemctl', 'daemon-reload')
        run('systemctl', 'start', 'minifw-ai')
        until = time.monotonic() + 20
        while not (audit.exists() and audit.read_text().count('"daemon_start"') > before):
            assert time.monotonic() < until, 'Engine did not start'
            time.sleep(.2)
        return mark, since

    def traffic(count):
        return json.loads(run('ip', 'netns', 'exec', 'mf-client', '/usr/bin/python3', '-c', TLS_LOOP, str(count),
                              timeout=count + 30).stdout.splitlines()[-1])

    def packet_rows(mark):
        return [r for r in rows()[mark:] if r.get('telemetry_source') == 'packet' and r.get('mlp_status') == 'inferred']

    def journal(since):
        return run('journalctl', '-u', 'minifw-ai', '--since', since, '--no-pager', '-o', 'cat', check=False).stdout

    def engine_active():
        return run('systemctl', 'is-active', 'minifw-ai', check=False).stdout.strip() == 'active'

    test_model = root / 'test-always-threat.pkl'
    run(VENV, '-c', MAKE_MODEL, str(test_model))
    approved = sha(test_model)
    shipped = '/opt/minifw_ai/models/mlp_packet14.pkl'
    corrupt = root / 'corrupt-model.pkl'
    corrupt.write_bytes(b'not a pickle')
    policy = json.loads((root / 'policy.json').read_text())
    for segment in policy['segments'].values():
        segment.update(block_threshold=30, monitor_threshold=15)
    (root / 'policy.json').write_text(json.dumps(policy, indent=2))
    try:
        # 1. Switch off (no approval): the test model infers but stays shadow-only.
        mark, _ = boot(test_model, '')
        outcome = traffic(16)
        seen = packet_rows(mark)
        assert seen and all(r['mlp_mode'] == 'shadow_only' and r['score'] == 0 for r in seen), seen[-1:]
        assert not member() and outcome['succeeded'] == outcome['requests']
        record('ai_switch_off_shadow', inferred_events=len(seen), mlp_mode='shadow_only', score=0, isolation=False, **outcome)

        # 2. Approved exact model: same traffic, AI score reaches the kernel block set and routed access stops.
        mark, _ = boot(test_model, approved)
        traffic(16)
        blocked = [r for r in rows()[mark:] if r.get('action') == 'block']
        assert blocked, 'Approved model did not cause a block'
        event = blocked[0]
        assert event['mlp_mode'] == 'scoring' and any(x.startswith('mlp_threat_score_') for x in event['reasons']), event
        assert member(), 'Client not in kernel block set'
        nft('ai-switch-approved')
        ns('http', gateway.SERVER, '8080', '/', allowed=False)
        record('ai_caused_kernel_isolation', model='TEST-ONLY always-threat', model_sha256=approved, score=event['score'],
               reasons=event['reasons'], kernel_set_member=True, routed_HTTP='blocked',
               lab_thresholds='block 30 in lab policy copy only', detection_quality='not evaluated')

        # 3. Approval names a different model (rollback/replacement): back to shadow, no isolation.
        mark, _ = boot(test_model, sha(shipped))
        outcome = traffic(16)
        seen = packet_rows(mark)
        assert seen and all(r['mlp_mode'] == 'shadow_only' and r['score'] == 0 for r in seen)
        assert not member() and outcome['succeeded'] == outcome['requests']
        record('ai_switch_mismatched_approval', approved_sha256='shipped packet14 model', loaded='test model',
               mlp_mode='shadow_only', isolation=False, **outcome)

        # 4/5. Corrupt or missing model, even with an approval: engine runs on baseline, scan control still isolates.
        for name, model, approval in [('corrupt', corrupt, sha(corrupt)), ('missing', root / 'absent.pkl', approved)]:
            mark, since = boot(model, approval)
            outcome = traffic(10)
            assert engine_active() and not packet_rows(mark) and not member()
            assert outcome['succeeded'] == outcome['requests']
            log = journal(since)
            scan_log = (root / f'scan-{name}.log').open('w')
            scan = subprocess.Popen(['ip', 'netns', 'exec', 'mf-client', '/usr/bin/python3', gateway.__file__, 'client', 'scan',
                                     gateway.SERVER], stdout=scan_log, stderr=scan_log)
            children.append(scan)
            until = time.monotonic() + 20
            while not member() and time.monotonic() < until:
                time.sleep(.2)
            scan.send_signal(signal.SIGTERM)
            scan.wait(timeout=5)
            scan_log.close()
            assert member(), f'{name} model: baseline scan control did not isolate'
            reason = next(r for r in reversed(rows()) if r.get('action') == 'block')['reasons']
            assert 'port_scan' in reason
            record(f'ai_model_{name}_baseline_continues', engine_active=True, mlp_inferences=0,
                   journal_model_warning=('Failed to load model' in log) if name == 'corrupt' else ('No model configured' in log or 'Failed' not in log),
                   ordinary_requests=outcome, baseline_scan_isolation=True, reasons=reason)
    finally:
        SWITCH.unlink(missing_ok=True)
        run('systemctl', 'daemon-reload')


extended.exercise = exercise
gateway.acceptance(edition, package, extended=True)
