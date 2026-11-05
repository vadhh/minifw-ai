"""C18 baseline checks and newly generated, labelled lab traffic; never client traffic."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import time

edition, package, source = sys.argv[1:]
assert edition in {'education', 'financial'}
assert socket.gethostname() == 'minifw-monday-' + edition and os.geteuid() == 0
assert subprocess.check_output(['systemd-detect-virt'], text=True).strip() in {'kvm', 'qemu'}
expected = {'education': 'b180e835a9769ca9ca6de2f0932dd72f190a8a1fd2c13fe392d929353ad18843',
            'financial': '6e4f812567e87ffb6c8b26e7bbd4d5bc797055e7dfcbf5ab759e4fcc8289e08f'}
assert hashlib.sha256(Path(package).read_bytes()).hexdigest() == expected[edition]
sys.path.insert(0, str(Path(source) / 'testing'))
import lab_gateway_acceptance as gateway
import lab_extended_acceptance as extended


def exercise(root, run, start, record, nft, ns, member, children):
    start(source='file', packet=True, ai=True)
    corpus = []
    # Capture separate sessions, not random rows of one capture in different splits.
    for session in range(4):
        for label in ['benign', 'malicious']:
            capture = root / f'{edition}-{session}-{label}.pcap'
            log = (root / (capture.stem + '-capture.log')).open('w')
            process = subprocess.Popen(['tcpdump', '--immediate-mode', '-B', '4096', '-U', '-n', '-i', 'mfcg', '-w', str(capture),
                                        'host', '10.10.0.20', 'and', 'host', '198.18.0.2'],
                                       stdout=log, stderr=log)
            children.append(process)
            time.sleep(.4)
            assert process.poll() is None
            # This fictionally labelled activity is not real institution acceptance.
            # Includes benign failed login and hostile password guessing on the same TLS endpoint.
            code = '''import http.client,json,ssl,time
context=ssl._create_unverified_context()
rows=[]
for i in range(30):
 c=http.client.HTTPSConnection('198.18.0.2',443,context=context,timeout=3)
 if LABEL=='malicious':
  method,path,body='POST','/login',json.dumps({'username':'alice','password':'guess-'+str(i)})
  expected=401
 else:
  method,path,body,expected=[('GET','/',None,200),('GET','/lessons/intro',None,200),('GET','/search?q=fractions',None,200),('GET','/media/lesson.webm',None,200),('POST','/login',json.dumps({'username':'alice','password':'typo'}),401)][i%5]
 started=time.time()
 c.request(method,path,body,{'Content-Type':'application/json'} if body else {})
 r=c.getresponse(); data=r.read(); status=r.status; c.close()
 rows.append({'index':i,'method':method,'path':path,'status':status,'expected':expected,'bytes':len(data),'start':started,'end':time.time()})
 assert status==expected
 time.sleep(DELAY)
print(json.dumps(rows))
'''.replace('LABEL', repr(label)).replace('DELAY', str(.02 * (session+1)))
            try:
                result = run('ip', 'netns', 'exec', 'mf-client', '/usr/bin/python3', '-c', code, timeout=60)
                outcomes = json.loads(result.stdout.splitlines()[-1])
            finally:
                # Let tcpdump drain the kernel capture buffer before ending the session.
                time.sleep(1.5)
                process.send_signal(signal.SIGINT)
                process.wait(timeout=10)
                log.close()
            assert not member(), 'Shadow model must not cause unintended isolation'
            item = dict(capture=capture.name, sha256=hashlib.sha256(capture.read_bytes()).hexdigest(),
                        edition=edition, session=session, label=label, label_source='controlled isolated fixture',
                        activity='TLS password guessing' if label == 'malicious' else 'TLS web/lesson/search/media/failed-login',
                        split='train' if session < 2 else 'validation' if session == 2 else 'test',
                        representative=False, outcomes=outcomes)
            corpus.append(item)
            (root / 'corpus-manifest.json').write_text(json.dumps(corpus, indent=2)+'\n')
    record('new_labelled_lab_corpus', captures=len(corpus), requests=sum(len(x['outcomes']) for x in corpus),
           representative=False, AI='C18 shadow only', quality_gate='not evaluated yet')

    # Removing count-only isolation must retain the distinct-port scan control.
    start(source='none', packet=False)
    attack_log = (root / 'scan.log').open('w')
    attack = subprocess.Popen(['ip', 'netns', 'exec', 'mf-client', '/usr/bin/python3',
                               str(Path(source)/'testing/lab_gateway_acceptance.py'), 'client', 'scan', '198.18.0.2'],
                              stdout=attack_log, stderr=attack_log)
    children.append(attack)
    until = time.monotonic()+15
    while not member() and time.monotonic() < until:
        time.sleep(.2)
    assert member(), 'Port scan no longer reaches kernel block'
    nft('thursday-port-scan')
    ns('http', '198.18.0.2', '8080', '/', allowed=False)
    events = [json.loads(x) for x in (root/'events.jsonl').read_text().splitlines()]
    actual = next(x for x in reversed(events) if x.get('action') == 'block')
    assert 'port_scan' in actual['reasons']
    record('F1_remaining_scan_control', reasons=actual['reasons'], routed_HTTP='blocked',
           limitation='Does not establish same-port flood or encrypted password-guessing detection')
    attack.terminate()
    attack.wait(timeout=5)
    attack_log.close()


extended.exercise = exercise
gateway.acceptance(edition, package, extended=True)
