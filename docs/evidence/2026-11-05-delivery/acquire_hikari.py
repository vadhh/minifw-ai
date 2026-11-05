"""Acquire pinned publisher data for offline analysis; never replay traffic."""
import hashlib
import json
from pathlib import Path
import time
import urllib.request

ROOT = Path('/var/tmp/minifw-thursday-data')
FILES = [
    ('BRUTEFORCE_XML/pcap/Monday_2021-04-12_0611.pcap', 271079071,
     'ec97d152f8e8582dd093873d40e8c9b4'),
    ('ground-truth.zip', 97345155, 'a940cca16c3f1051e0de30f22bb843de'),
    ('ALLFLOWMETER_HIKARI2021.csv.zip', 68403081, 'd7d9e277fe4a66cb00764d7f91a810dd'),
]


def main():
    ROOT.mkdir(exist_ok=True)
    manifest = []
    for key, size, expected in FILES:
        target = ROOT / Path(key).name
        url = 'https://zenodo.org/api/records/6463389/files/' + key + '/content'
        started = time.time()
        if not target.exists():
            partial = target.with_suffix(target.suffix + '.partial')
            with urllib.request.urlopen(url, timeout=90) as response, partial.open('wb') as output:
                while chunk := response.read(1024 * 1024):
                    output.write(chunk)
            partial.rename(target)
        md5, sha = hashlib.md5(), hashlib.sha256()
        with target.open('rb') as source:
            while chunk := source.read(1024 * 1024):
                md5.update(chunk)
                sha.update(chunk)
        if target.stat().st_size != size or md5.hexdigest() != expected:
            raise ValueError('Publisher size/checksum mismatch: ' + str(target))
        item = dict(record=6463389, version='1.4.0', licence='CC-BY-4.0',
                    key=key, url=url, bytes=size, publisher_md5=expected,
                    sha256=sha.hexdigest(), elapsed_seconds=time.time()-started)
        manifest.append(item)
        print(json.dumps(item), flush=True)
        (ROOT / 'download-manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')


if __name__ == '__main__':
    main()
