"""Extend the unchanged C18 load/full-log probe with C19 warning/recovery checks."""
import http.client
import json
import os
from pathlib import Path
import runpy
import socket
import ssl
import subprocess
import sys
import time

edition,package,source=sys.argv[1:]
assert edition in {'education','financial'} and socket.gethostname()=='minifw-monday-'+edition
assert os.geteuid()==0
sys.path.insert(0,str(Path(source)/'testing'))
import lab_gateway_acceptance as gateway
import lab_extended_acceptance as extended
acceptance=gateway.acceptance
gateway.acceptance=lambda *a,**k: None
try:
    previous=runpy.run_path('/var/tmp/lab_c18_fault_original.py')['exercise']
finally:
    gateway.acceptance=acceptance


def exercise(root,run,start,record,nft,ns,member,children):
    override=Path('/etc/systemd/system/minifw-ai.service.d/97-thursday-health.conf')
    assert not override.exists()
    override.write_text('[Service]\nEnvironment=MINIFW_HEALTH_FILE=/opt/minifw_ai/logs/runtime-health.json\n')
    run('systemctl','daemon-reload')
    def health():
        c=http.client.HTTPSConnection('127.0.0.1',8443,context=ssl._create_unverified_context(),timeout=5)
        c.request('GET','/health/')
        r=c.getresponse();status,body=r.status,json.loads(r.read());c.close()
        return status,body
    output=root/'operator-browser'
    output.mkdir()
    run('chown','lab:lab',str(output))
    def browser(expected):
        secret=dict(line.split('=',1) for line in Path('/etc/minifw/minifw.env').read_text().splitlines() if '=' in line)
        credentials=json.dumps(dict(username='admin',password=secret['MINIFW_ADMIN_PASSWORD']))
        result=subprocess.run(['runuser','-u','lab','--','/opt/minifw_ai/venv/bin/python',
                               '/var/tmp/browser_health_check.py',str(output),expected],input=credentials,text=True,capture_output=True)
        if result.returncode:
            record('browser_check_failure',expected=expected,stderr=result.stderr)
            raise AssertionError(result.stderr)
        return json.loads(result.stdout.splitlines()[-1])
    def checked_record(name,**actual):
        record(name,**actual)
        if name=='isolated_disk_full':
            status,data=health()
            assert status==503
            record('operator_logging_fault_visible',http_status=status,health=data,browser=browser('warning'))
        if name=='disk_full_recovery':
            events=root/'events.jsonl';flows=root/'flows.jsonl'
            before=events.stat().st_size
            for _ in range(3):
                ns('dns','10.10.0.1','approved.lab.test')
                ns('http','198.18.0.2','8080','/')
                time.sleep(1)
            until=time.monotonic()+15
            while time.monotonic()<until:
                status,data=health()
                if status==200: break
                time.sleep(.3)
            assert status==200,(status,data)
            assert events.stat().st_size>before and flows.stat().st_size>0
            latest=json.loads(events.read_text().splitlines()[-1])
            record('recording_resumed_and_warning_cleared',http_status=status,event_bytes_before=before,
                   event_bytes_after=events.stat().st_size,flow_bytes=flows.stat().st_size,
                   last_event_timestamp=latest.get('ts'),browser=browser('recovered'),
                   limitation='No recovery of audit records lost during storage failure')
    try:
        previous(root,run,start,checked_record,nft,ns,member,children)
    finally:
        override.unlink(missing_ok=True)
        run('systemctl','daemon-reload',check=False)


extended.exercise=exercise
gateway.acceptance(edition,package,extended=True)
