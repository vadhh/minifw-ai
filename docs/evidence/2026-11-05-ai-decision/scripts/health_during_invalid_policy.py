"""Observe the dashboard /health/ response (which drives the C19 warning banner) during an invalid-policy outage.

Disposable fresh C19 guest only. The banner shows unless /health/ returns 200 with status "ready"
(app/web/templates/admin/base.html); C19 browser-verified that rendering on 5 November.
"""
import json
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

edition = sys.argv[1]
assert socket.gethostname() == 'minifw-c19fresh-' + edition
mode = 'minifw_school' if edition == 'education' else 'minifw_financial'
POLICY = Path(f'/opt/minifw_ai/config/modes/{mode}/policy.json')
context = ssl._create_unverified_context()  # Local self-signed dashboard certificate.


def health():
    try:
        with urllib.request.urlopen('https://127.0.0.1:8443/health/', context=context, timeout=3) as response:
            return response.status, json.loads(response.read()).get('status')
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b'{}').get('status')
    except (OSError, ValueError) as error:
        return None, type(error).__name__


def banner(sample):
    return 'hidden' if sample == (200, 'ready') else 'shown'


def until(expected, seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        sample = health()
        if banner(sample) == expected:
            return sample
        time.sleep(.5)
    return health()


original = POLICY.read_bytes()
subprocess.run(['systemctl', 'start', 'minifw-ai', 'minifw-ai-web'], check=True)
result = {'before': until('hidden', 60)}
try:
    POLICY.write_bytes(original[:len(original) // 2])
    subprocess.run(['systemctl', 'restart', 'minifw-ai'])  # What the packaged apply unit runs.
    started = time.monotonic()
    shown = until('shown', 30)
    result['during_invalid_policy'] = dict(response=shown, banner=banner(shown), seconds=round(time.monotonic() - started, 1))
    time.sleep(10)
    result['during_invalid_policy_after_10s'] = dict(response=health(), banner=banner(health()))
finally:
    POLICY.write_bytes(original)
fixed = time.monotonic()
after = until('hidden', 30)
result['after_correction'] = dict(response=after, banner=banner(after), seconds=round(time.monotonic() - fixed, 1),
                                  policy_restored_identical=POLICY.read_bytes() == original)
subprocess.run(['systemctl', 'stop', 'minifw-ai-web', 'minifw-ai'])
print(json.dumps(result, indent=2))
