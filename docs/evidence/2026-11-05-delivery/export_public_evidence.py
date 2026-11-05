"""Export only selected fictional lab captures, results and nonsecret diagnostic logs."""
import json
import os
from pathlib import Path
import socket
import tarfile

assert os.geteuid()==0
edition=socket.gethostname().removeprefix('minifw-monday-')
assert edition in {'education','financial'}
files=[]
names={'results.json','bounded-load.json','resource-samples.json','corpus-manifest.json',
       'sector-corpus-manifest.json','apply-samples.json','events.jsonl','flows.jsonl','engine-journal.log',
       'browser-warning.json','browser-recovered.json'}
for folder in Path('/var/tmp').glob('minifw-monday-'+edition+'-20261105*'):
    for file in folder.rglob('*'):
        if file.is_file() and not file.is_symlink() and (file.name in names or file.suffix in {'.pcap','.nft','.png'} or file.name.endswith('-capture.log')):
            files.append((file,Path('runs')/folder.name/file.relative_to(folder)))
patterns=['thursday-*.log','c19-*.log','c19-tests.xml']
for pattern in patterns:
    for file in Path('/var/tmp').glob(pattern):
        if file.is_file(): files.append((file,Path('logs')/file.name))
for base in ['thursday-education-corpus','thursday-education-complete']:
    folder=Path('/var/tmp')/base/'model-comparison'
    for name in ['results.json','prefixes.json']:
        file=folder/name
        if file.is_file(): files.append((file,Path('experiments')/base/name))
for name in ['download-manifest.json','pilot-result.json','pilot-decoder.log']:
    file=Path('/var/tmp/minifw-thursday-data')/name
    if file.is_file(): files.append((file,Path('public-data')/name))
for name in ['hikari-pilot.log','hikari-pilot-ipv6-fixture-failed.log']:
    file=Path('/var/tmp')/name
    if file.is_file(): files.append((file,Path('public-data')/name))
for file,relative in files:
    if file.suffix in {'.json','.jsonl','.log','.xml'}:
        content=file.read_text(errors='replace')
        for marker in ['-----BEGIN PRIVATE KEY-----','-----BEGIN OPENSSH PRIVATE KEY-----','access_token=eyJ','MINIFW_ADMIN_PASSWORD=','MINIFW_SECRET_KEY=']:
            assert marker not in content,(file,marker)
archive=Path('/var/tmp')/('minifw-thursday-public-'+edition+'.tar.gz')
with tarfile.open(archive,'w:gz') as target:
    for file,relative in sorted(files,key=lambda x:str(x[1])):
        target.add(file,arcname=str(relative),recursive=False)
print(json.dumps(dict(edition=edition,archive=str(archive),files=len(files),bytes=archive.stat().st_size)))
