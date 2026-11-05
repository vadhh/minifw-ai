"""Audit HIKARI tuple candidates; missing time/protocol prevents accepted labels."""
from collections import Counter, defaultdict
import csv
import hashlib
import io
import ipaddress
import json
from pathlib import Path
import subprocess
import zipfile

from minifw_ai.collector_flow import FlowTracker, build_packet_features_14
from minifw_ai.collector_packets import FIELDS, observe_packet, parse_packet_fields

root=Path('/var/tmp/minifw-thursday-data')
index=defaultdict(list)
classes=Counter()
with zipfile.ZipFile(root/'ALLFLOWMETER_HIKARI2021.csv.zip') as archive:
    assert archive.namelist()==['ALLFLOWMETER_HIKARI2021.csv']
    with archive.open(archive.namelist()[0]) as raw:
        reader=csv.DictReader(io.TextIOWrapper(raw))
        columns=reader.fieldnames
        for row in reader:
            key=(row['originh'],int(row['originp']),row['responh'],int(row['responp']))
            index[key].append((row['uid'],row['Label'],row['traffic_category']))
            classes[row['traffic_category']+' / '+row['Label']]+=1
pcap=root/'Monday_2021-04-12_0611.pcap'
command=['tshark','-n','-r',str(pcap),'-T','fields','-E','occurrence=f']
for field in FIELDS+['tcp.stream','udp.stream']:
    command.extend(['-e',field])
counts=Counter()
seen=set()
trackers={}
candidate_labels=Counter()
examples=[]
with (root/'pilot-decoder.log').open('w') as errors:
    process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=errors,text=True)
    try:
        for line in process.stdout:
            counts['decoded_packets']+=1
            fields=line.rstrip('\r\n').split('\t')
            assert len(fields)==len(FIELDS)+2
            packet=parse_packet_fields('\t'.join(fields[:-2]))
            if packet is None:
                counts['unsupported_packets']+=1
                continue
            stream=(packet.proto,fields[-2] if packet.proto=='tcp' else fields[-1])
            if not stream[1] or stream in seen:
                continue
            if stream not in trackers:
                key=(packet.src_ip,packet.src_port,packet.dst_ip,packet.dst_port)
                reverse=(key[2],key[3],key[0],key[1])
                candidates=index.get(key,[])+index.get(reverse,[])
                counts['observed_streams']+=1
                counts['no_quadruple_candidate' if not candidates else
                       'unique_quadruple_candidate' if len(candidates)==1 else 'ambiguous_quadruple_candidate']+=1
                if len(candidates)==1:
                    candidate_labels[candidates[0][2]+' / '+candidates[0][1]]+=1
                # Prefix extraction can be checked without accepting the inferred class.
                client=packet.src_ip
                address=ipaddress.ip_address(client)
                trackers[stream]=(FlowTracker(),[ipaddress.ip_network(f'{client}/{address.max_prefixlen}')])
            tracker,networks=trackers[stream]
            flow,_=observe_packet(tracker,packet,networks)
            if flow is not None and flow.pkt_count>=5 and flow.last_seen>flow.first_seen:
                features=build_packet_features_14(flow)
                assert len(features)==14 and features[1]==5
                counts['eligible_five_packet_prefixes']+=1
                if len(examples)<5:
                    examples.append(dict(stream=stream,features=features,labels_accepted=False))
                seen.add(stream)
                del trackers[stream]
    finally:
        process.stdout.close()
        process.wait(timeout=60)
assert process.returncode==0
counts['ineligible_streams']=counts['observed_streams']-counts['eligible_five_packet_prefixes']
result=dict(capture=pcap.name,pcap_sha256=hashlib.sha256(pcap.read_bytes()).hexdigest(),
            publisher_label_rows=sum(classes.values()),class_counts=dict(classes),columns=columns,
            ground_truth_archive_contents=zipfile.ZipFile(root/'ground-truth.zip').namelist(),
            counts=dict(counts),tentative_unique_quadruple_labels=dict(candidate_labels),examples=examples,
            accepted_labelled_flows=0,accepted_training_flows=0,
            status='BLOCKED: published CSV lacks absolute start timestamps and transport protocol',
            limitation='Tuple candidates cannot establish capture/session/time-specific identity or attack onset; no labels accepted and no HIKARI model trained')
(root/'pilot-result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k not in {'examples','columns','ground_truth_archive_contents'}},indent=2),flush=True)
