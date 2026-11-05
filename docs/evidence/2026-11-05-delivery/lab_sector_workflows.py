"""New controlled normal-workflow corpus for both standalone editions; no real client data."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

edition,package,source=sys.argv[1:]
assert edition in {'education','financial'} and socket.gethostname()=='minifw-monday-'+edition
assert os.geteuid()==0
sys.path.insert(0,str(Path(source)/'testing'))
import lab_gateway_acceptance as gateway
import lab_extended_acceptance as extended


def exercise(root,run,start,record,nft,ns,member,children):
    start(source='none',packet=True,ai=True)
    capture=root/(edition+'-sector-normal.pcap')
    log=(root/'sector-capture.log').open('w')
    process=subprocess.Popen(['tcpdump','--immediate-mode','-U','-n','-i','mfcg','-w',str(capture),
                              'host','10.10.0.20','and','host','198.18.0.2'],stdout=log,stderr=log)
    children.append(process)
    time.sleep(.5)
    try:
        result=ns('workflows','198.18.0.2','10.10.0.20')
        outcomes=json.loads(result.stdout.splitlines()[-1])
        assert not member()
        record('normal_sector_lab_workflows',**outcomes,AI='shadow only; not enforced',
               additional_boundary='Staff and client share the lab source IP; no production segmentation claim')
    finally:
        time.sleep(1.5)
        process.send_signal(signal.SIGINT)
        process.wait(timeout=10)
        log.close()
    import hashlib
    (root/'sector-corpus-manifest.json').write_text(json.dumps(dict(capture=capture.name,
        sha256=hashlib.sha256(capture.read_bytes()).hexdigest(),label='benign',edition=edition,
        split='additional_normal_holdout',representative=False,
        label_source='Scripted fictional payment/transfer/statement/role/lesson/search/media workflows; permitted typo and rejection cases'),indent=2)+'\n')


extended.exercise=exercise
gateway.acceptance(edition,package,extended=True)
