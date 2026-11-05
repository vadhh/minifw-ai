"""Observe the operator warning on a configured lab gateway during an invalid-policy outage (C19, unchanged).

Healthy gateway with live DNS/flow sources -> warning hidden -> truncated policy + engine restart (what the
apply unit runs) -> /health/ 503 and Chromium-observed warning, existing block retained, new traffic behaviour
recorded -> policy restored -> recovery and warning cleared. Monday lab VMs only.
"""
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time

edition, package, source = sys.argv[1:]
assert edition in {'education', 'financial'} and socket.gethostname() == 'minifw-monday-' + edition and os.geteuid() == 0
sys.path.insert(0, str(Path(source) / 'testing'))
import lab_gateway_acceptance as gateway
import lab_extended_acceptance as extended

MARKER = '192.0.2.55'  # TEST-NET stand-in for an existing block; never the lab client.


def exercise(root, run, start, record, nft, ns, member, children):
    override = Path('/etc/systemd/system/minifw-ai.service.d/97-invalid-policy-health.conf')
    assert not override.exists()
    override.write_text('[Service]\nEnvironment=MINIFW_HEALTH_FILE=/opt/minifw_ai/logs/runtime-health.json\n')
    run('systemctl', 'daemon-reload')
    output = root / 'operator-browser'
    output.mkdir()
    run('chown', 'lab:lab', str(output))
    policy = root / 'policy.json'
    original = policy.read_bytes()

    def health():
        try:
            c = http.client.HTTPSConnection('127.0.0.1', 8443, context=ssl._create_unverified_context(), timeout=5)
            c.request('GET', '/health/')
            r = c.getresponse()
            status, body = r.status, json.loads(r.read())
            c.close()
            return status, body
        except (OSError, ValueError) as error:
            return None, {'error': type(error).__name__}

    def browser(expected):
        secret = dict(line.split('=', 1) for line in Path('/etc/minifw/minifw.env').read_text().splitlines() if '=' in line)
        credentials = json.dumps(dict(username='admin', password=secret['MINIFW_ADMIN_PASSWORD']))
        result = subprocess.run(['runuser', '-u', 'lab', '--', '/opt/minifw_ai/venv/bin/python', '/var/tmp/browser_health_check.py',
                                 str(output), expected], input=credentials, text=True, capture_output=True)
        assert result.returncode == 0, result.stderr[-2000:]
        return json.loads(result.stdout.splitlines()[-1])

    def feed_until(wanted, seconds=40):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            ns('dns', '10.10.0.1', 'approved.lab.test')
            ns('http', gateway.SERVER, '8080', '/')
            # Lab stand-in for a provisioned Zeek sensor (Financial policy uses Zeek SNI): one benign ssl.log TSV row.
            with (root / 'ssl.log').open('a') as zeek:
                zeek.write('\t'.join([f'{time.time():.6f}', 'Clab', gateway.CLIENT, '50000', gateway.SERVER, '443', 'TLSv13',
                                      'TLS_AES_128_GCM_SHA256', 'x25519', 'lab.test', 'F', '-', 'http/1.1', 'T', 'Fa,Fb']) + '\n')
            status, body = health()
            if status == wanted:
                return status, body
            time.sleep(1)
        return health()

    def marker_blocked():
        return subprocess.run(['nft', 'get', 'element', 'inet', 'minifw', 'minifw_block_v4', '{', MARKER, '}'],
                              capture_output=True).returncode == 0

    try:
        start(source='file')
        run('systemctl', 'start', 'minifw-ai-web')
        status, body = feed_until(200, 60)
        assert status == 200, (status, body)
        run('nft', 'add', 'element', 'inet', 'minifw', 'minifw_block_v4', '{', MARKER, 'timeout', '1h', '}')
        record('healthy_configured_gateway', http_status=status, health=body, existing_block=marker_blocked(), browser=browser('recovered'))

        policy.write_bytes(original[:len(original) // 2])  # Truncated JSON: damaged or hand-edited file.
        run('systemctl', 'restart', 'minifw-ai', check=False)  # The packaged apply unit runs exactly this.
        broken = time.monotonic()
        until = time.monotonic() + 30
        while time.monotonic() < until and health()[0] == 200:
            time.sleep(.5)
        status, body = health()
        assert status == 503, (status, body)
        seen = round(time.monotonic() - broken, 1)
        observed = browser('warning')
        new_traffic = ns('http', gateway.SERVER, '8080', '/', allowed=True).returncode == 0
        engine = run('systemctl', 'show', 'minifw-ai', '-p', 'ActiveState', '-p', 'SubState', '-p', 'NRestarts').stdout.split()
        record('invalid_policy_outage_visible', http_status=status, health=body, seconds_to_503=seen, browser=observed,
               existing_block_retained=marker_blocked(), new_routed_traffic='forwarded without new detection' if new_traffic else 'blocked',
               engine=engine)

        policy.write_bytes(original)
        fixed = time.monotonic()
        status, body = feed_until(200, 60)
        assert status == 200, (status, body)
        record('policy_corrected_recovered', http_status=status, seconds_to_200=round(time.monotonic() - fixed, 1),
               existing_block_retained=marker_blocked(), browser=browser('recovered'),
               restored_identical=policy.read_bytes() == original)
    finally:
        policy.write_bytes(original)
        subprocess.run(['nft', 'delete', 'element', 'inet', 'minifw', 'minifw_block_v4', '{', MARKER, '}'], capture_output=True)
        run('systemctl', 'stop', 'minifw-ai-web', check=False)
        override.unlink(missing_ok=True)
        run('systemctl', 'daemon-reload', check=False)


extended.exercise = exercise
gateway.acceptance(edition, package, extended=True)
