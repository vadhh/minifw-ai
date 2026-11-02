import hashlib,json,os,signal,struct,subprocess
from pathlib import Path
root=Path("/var/tmp/minifw-public-validation")
source=root/"mirai.part"
limit=16*1024*1024
assert source.stat().st_size>=limit
for line in subprocess.check_output(["ps","-eo","pid,args"],text=True).splitlines():
 fields=line.strip().split(None,1)
 if len(fields)==2 and fields[1]=="python3 /var/tmp/download_minifw_validation.py":os.kill(int(fields[0]),signal.SIGTERM)
raw=source.read_bytes()[:limit]
endian="<" if raw[:4] in (bytes.fromhex("d4c3b2a1"),bytes.fromhex("4d3cb2a1")) else ">"
assert raw[:4] in [bytes.fromhex(value) for value in ["d4c3b2a1","a1b2c3d4","4d3cb2a1","a1b23c4d"]]
pos,count=24,0
while pos+16<=len(raw):
 header=struct.unpack(endian+"IIII",raw[pos:pos+16]);length=header[2]
 assert length<=262144
 if pos+16+length>len(raw):break
 pos+=16+length;count+=1
sample=raw[:pos];(root/"mirai.pcap").write_bytes(sample)
entry={"file":"mirai.pcap","source_url":"https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-34-1/pcap/2018-12-21-15-50-14-192.168.1.195.pcap",
       "selection":"First 16 MiB prefix, trimmed to complete PCAP records; NOT the full capture",
       "source_prefix_bytes":len(raw),"source_prefix_sha256":hashlib.sha256(raw).hexdigest(),
       "bytes":len(sample),"packets":count,"sha256":hashlib.sha256(sample).hexdigest(),
       "purpose":"Bounded offline external robustness control, not representative sector validation"}
(root/"mirai-prefix-manifest.json").write_text(json.dumps(entry,indent=2));print(json.dumps(entry))
