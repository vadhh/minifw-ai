"""Bounded check: an invalid policy file applied through the dashboard's apply path, then corrected.

Disposable fresh C19 guest only. Simulates a damaged/hand-edited policy file (truncated JSON); the dashboard itself
writes JSON with json.dump, so this is not a claim that the dashboard can produce this state.
"""
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

edition = sys.argv[1]
assert socket.gethostname() == 'minifw-c19fresh-' + edition
mode = 'minifw_school' if edition == 'education' else 'minifw_financial'
POLICY = Path(f'/opt/minifw_ai/config/modes/{mode}/policy.json')
HEALTH = Path('/opt/minifw_ai/logs/runtime-health.json')
MARKER = '192.0.2.55'  # TEST-NET address standing in for an existing block.
results = {}


def sh(*args):
    return subprocess.run(args, capture_output=True, text=True)


def prop(name):
    return sh('systemctl', 'show', '-p', name, '--value', 'minifw-ai').stdout.strip()


def blocked():
    return sh('nft', 'get', 'element', 'inet', 'minifw', 'minifw_block_v4', '{', MARKER, '}').returncode == 0


def health():
    try:
        return json.loads(HEALTH.read_text())
    except (OSError, ValueError):
        return {}


def wait(predicate, seconds):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if predicate():
            return True
        time.sleep(.25)
    return False


def apply_as_dashboard():
    code = ('from app.services.policy.apply_policy_service import apply_saved_policy\n'
            'try:\n print("OK", apply_saved_policy()["message"])\n'
            'except Exception as e:\n print("FAILED", type(e).__name__, e)\n')
    return sh('runuser', '-u', 'minifw-web', '--', 'env', 'PYTHONPATH=/opt/minifw_ai:/opt/minifw_ai/app',
              '/opt/minifw_ai/venv/bin/python', '-c', code).stdout.strip()


original = POLICY.read_bytes()
sh('systemctl', 'start', 'minifw-ai')
assert wait(lambda: prop('ActiveState') == 'active' and str(health().get('pid')) == prop('MainPID'), 30), 'engine not healthy'
assert sh('nft', 'add', 'element', 'inet', 'minifw', 'minifw_block_v4', '{', MARKER, 'timeout', '1h', '}').returncode == 0
before_pid = prop('MainPID')
results['before'] = dict(engine='active', pid=before_pid, existing_block=blocked(), restarts=prop('NRestarts'))
try:
    POLICY.write_bytes(original[:len(original) // 2])  # Truncated JSON.
    started = time.monotonic()
    results['apply_response'] = apply_as_dashboard()
    samples = []
    for _ in range(12):
        samples.append(dict(t=round(time.monotonic() - started, 1), state=prop('ActiveState'), sub=prop('SubState'),
                            restarts=prop('NRestarts'), existing_block=blocked(), health_pid=health().get('pid')))
        time.sleep(2.5)
    log = sh('journalctl', '-u', 'minifw-ai', '--since', '-60s', '--no-pager', '-o', 'cat').stdout
    results['during_invalid_policy'] = dict(samples=samples, journal_json_error=('JSONDecodeError' in log or 'Expecting' in log),
                                            existing_block_kept=all(s['existing_block'] for s in samples))
finally:
    POLICY.write_bytes(original)
    restored = time.monotonic()
recovered = wait(lambda: prop('ActiveState') == 'active' and prop('MainPID') not in {'0', before_pid}
                 and str(health().get('pid')) == prop('MainPID'), 30)
results['after_correction'] = dict(recovered_without_admin_command=recovered, seconds=round(time.monotonic() - restored, 1),
                                   pid=prop('MainPID'), restarts=prop('NRestarts'), existing_block=blocked(),
                                   policy_restored_identical=POLICY.read_bytes() == original)
sh('nft', 'delete', 'element', 'inet', 'minifw', 'minifw_block_v4', '{', MARKER, '}')
sh('systemctl', 'stop', 'minifw-ai')
print(json.dumps(results, indent=2))
