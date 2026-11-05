import urllib.request,hashlib,json,socket
from pathlib import Path
assert socket.gethostname()=="minifw-monday-education"
root=Path("/var/tmp/minifw-public-validation")
base="https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/"
items=[("benign","CTU-Honeypot-Capture-4-1/2018-10-25-14-06-32-192.168.1.132-zeek-conn.log.labeled"),
       ("mirai","CTU-IoT-Malware-Capture-34-1/2018-12-21-15-50-14-192.168.1.195-zeek-conn-log.labeled")]
records=[]
for label,relative in items:
 url=base+relative
 with urllib.request.urlopen(url,timeout=40) as response:data=response.read(10*1024*1024+1)
 assert len(data)<=10*1024*1024
 name=label+"-expert.labels";(root/name).write_bytes(data)
 records.append({"file":name,"url":url,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()})
 print(name)
 for line in data.decode().splitlines():
  if line.startswith("#fields") or not line.startswith("#"):
   print(line[:1200])
   if not line.startswith("#"):break
(root/"expert-label-manifest.json").write_text(json.dumps(records,indent=2))
