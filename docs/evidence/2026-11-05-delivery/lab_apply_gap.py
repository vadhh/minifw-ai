"""Measure explicit dashboard apply and a recoverable dispatch failure on C18."""
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse

edition, package, source = sys.argv[1:]
assert edition in {'education', 'financial'}
assert socket.gethostname() == 'minifw-monday-'+edition and os.geteuid() == 0
assert subprocess.check_output(['systemd-detect-virt'], text=True).strip() in {'kvm', 'qemu'}
sys.path.insert(0, str(Path(source)/'testing'))
import lab_gateway_acceptance as gateway
import lab_extended_acceptance as extended


def exercise(root, run, start, record, nft, ns, member, children):
    start(source='none', packet=True)
    health_path=Path('/opt/minifw_ai/logs/runtime-health.json')
    override=Path('/etc/systemd/system/minifw-ai.service.d/96-thursday-health.conf')
    assert not override.exists()
    override.write_text(f'[Service]\nEnvironment=MINIFW_HEALTH_FILE={health_path}\n')
    run('systemctl','daemon-reload')
    run('systemctl','restart','minifw-ai')
    run('systemctl','start','minifw-ai-web','minifw-ai-apply.path')
    cookie=''

    def call(method,path,data=None,form=False):
        connection=http.client.HTTPSConnection('127.0.0.1',8443,context=ssl._create_unverified_context(),timeout=22)
        headers={'Origin':'https://127.0.0.1:8443'}
        if cookie: headers['Cookie']=cookie
        if data is not None:
            headers['Content-Type']='application/x-www-form-urlencoded' if form else 'application/json'
            data=urllib.parse.urlencode(data) if form else json.dumps(data)
        connection.request(method,path,body=data,headers=headers)
        response=connection.getresponse()
        value=response.status,response.getheader('Set-Cookie'),response.read()
        connection.close()
        return value

    samples=[]
    stop=threading.Event()
    def monitor():
        while not stop.is_set():
            probe=subprocess.run(['ip','netns','exec','mf-client','/usr/bin/python3',
                                  str(Path(source)/'testing/lab_gateway_acceptance.py'),
                                  'client','http','198.18.0.2','8080','/'],capture_output=True,text=True,timeout=4)
            try: health=json.loads(health_path.read_text())
            except (OSError,ValueError): health={}
            events=root/'events.jsonl'
            samples.append(dict(monotonic=time.monotonic(),http_exit=probe.returncode,
                                engine_pid=health.get('pid'),sources=health.get('sources'),
                                event_bytes=events.stat().st_size if events.exists() else 0))
            stop.wait(.1)
    worker=threading.Thread(target=monitor,daemon=True)
    try:
        secret=dict(line.split('=',1) for line in Path('/etc/minifw/minifw.env').read_text().splitlines() if '=' in line)
        for _ in range(50):
            try:
                status,token,_=call('POST','/auth/login',{'username':'admin','password':secret['MINIFW_ADMIN_PASSWORD']},True)
                break
            except OSError: time.sleep(.2)
        assert status==303 and 'access_token=' in token
        cookie=token.split(';',1)[0]
        worker.start()
        time.sleep(3)
        oldpid=int(run('systemctl','show','minifw-ai','-p','MainPID','--value').stdout.strip())
        run('nft','add','element','inet','minifw','minifw_block_v4','{','10.10.0.99','timeout','90s','}')
        before=time.monotonic()
        status,_,body=call('POST','/admin/policy/apply')
        returned=time.monotonic()
        assert status==200,(status,body)
        newpid=int(json.loads(body)['engine_pid'])
        assert newpid!=oldpid
        time.sleep(3)
        kept=run('nft','get','element','inet','minifw','minifw_block_v4','{','10.10.0.99','}',check=False).returncode==0
        assert kept
        old=[s for s in samples if s['engine_pid']==oldpid and s['monotonic']<=before]
        new=[s for s in samples if s['engine_pid']==newpid and s.get('sources',{}).get('packet',0)]
        assert old and new
        # This is a sampled observation interval including the probe and health publication cadence.
        gap=new[0]['monotonic']-old[-1]['monotonic']
        record('dashboard_restart_gap',request_seconds=returned-before,
               sampled_detection_observation_gap_seconds=gap,old_pid=oldpid,new_pid=newpid,
               existing_kernel_block_retained=kept,http_failed_samples=sum(s['http_exit']!=0 for s in samples),
               scope='C18 baseline; includes probe/health publication cadence, not exact lossless detection timing')

        # Explicit dispatch failure: request cannot be consumed while the path is stopped.
        run('systemctl','stop','minifw-ai-apply.path')
        status,_,body=call('POST','/admin/policy/apply')
        assert status>=400,(status,body)
        unchanged=int(run('systemctl','show','minifw-ai','-p','MainPID','--value').stdout.strip())==newpid
        assert unchanged
        ns('http','198.18.0.2','8080','/')
        Path('/var/lib/minifw-ai/apply-policy').unlink(missing_ok=True)
        run('systemctl','start','minifw-ai-apply.path')
        status2,_,body2=call('POST','/admin/policy/apply')
        assert status2==200,(status2,body2)
        record('dashboard_failed_dispatch_recovery',failed_http=status,engine_unchanged=unchanged,
               retry_http=status2,scenario='Lab stopped apply watcher, then removed pending request and restored watcher',
               limitation='Does not test invalid-policy restart failure; watcher repair required administrator action')
    finally:
        stop.set()
        if worker.is_alive(): worker.join(timeout=5)
        (root/'apply-samples.json').write_text(json.dumps(samples,indent=2)+'\n')
        Path('/var/lib/minifw-ai/apply-policy').unlink(missing_ok=True)
        override.unlink(missing_ok=True)
        run('systemctl','stop','minifw-ai-web',check=False)
        run('systemctl','daemon-reload',check=False)
        run('systemctl','start','minifw-ai-apply.path',check=False)


extended.exercise=exercise
gateway.acceptance(edition,package,extended=True)
