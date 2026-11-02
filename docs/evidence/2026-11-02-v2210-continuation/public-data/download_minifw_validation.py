import hashlib,json,socket,urllib.request
from pathlib import Path
assert socket.gethostname()=="minifw-monday-education"
root=Path("/var/tmp/minifw-public-validation");root.mkdir(mode=0o700,exist_ok=True)
base="https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/"
items=[("benign","CTU-Honeypot-Capture-4-1","2018-10-25-14-06-32-192.168.1.132.pcap"),
       ("mirai","CTU-IoT-Malware-Capture-34-1","2018-12-21-15-50-14-192.168.1.195.pcap")]
records=[]
for label,folder,pcap in items:
 for relative,name in [("pcap/"+pcap,label+".pcap"),("zeek-labeled/conn.log",label+".labels"),("README.md",label+"-README.md")]:
  url=base+folder+"/"+relative;target=root/name;temporary=target.with_suffix(".part")
  with urllib.request.urlopen(url,timeout=45) as response,temporary.open("wb") as output:
   size=0
   while True:
    data=response.read(1024*1024)
    if not data:break
    size+=len(data)
    if size>150*1024*1024:raise ValueError("Sample exceeds 150 MiB bound")
    output.write(data)
  temporary.replace(target)
  entry={"file":name,"url":url,"bytes":size,"sha256":hashlib.sha256(target.read_bytes()).hexdigest()}
  records.append(entry);(root/"download-manifest.json").write_text(json.dumps(records,indent=2));print(json.dumps(entry),flush=True)
print("DOWNLOADS_COMPLETE; data only, no malware execution or traffic replay")
