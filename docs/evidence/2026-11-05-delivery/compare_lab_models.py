"""Offline measured-prefix experiment. Results qualify fixtures, not institutions."""
from collections import Counter
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import resource
import subprocess
import sys
import time
import warnings

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from minifw_ai.collector_flow import FlowTracker, build_packet_features_14
from minifw_ai.collector_packets import FIELDS, observe_packet, parse_packet_fields
from minifw_ai.utils.mlp_engine import MLPThreatDetector


def extract(folder):
    rows, diagnostics = [], []
    for entry in json.loads((folder/'corpus-manifest.json').read_text()):
        path = folder/entry['capture']
        assert hashlib.sha256(path.read_bytes()).hexdigest() == entry['sha256']
        command = ['tshark', '-n', '-r', str(path), '-T', 'fields', '-E', 'occurrence=f']
        for field in FIELDS:
            command.extend(['-e', field])
        tracker, scored, counts, observed = FlowTracker(), set(), Counter(), {}
        with (folder/(path.stem+'-decode.log')).open('w') as errors:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors, text=True)
            try:
                for line in process.stdout:
                    counts['decoded_packets'] += 1
                    packet = parse_packet_fields(line)
                    if packet is None:
                        counts['unsupported_packets'] += 1
                        continue
                    flow, _ = observe_packet(tracker, packet, [ipaddress.ip_network('10.10.0.20/32')])
                    if flow is None:
                        continue
                    key = (flow.client_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.proto)
                    if key not in scored:
                        observed.setdefault(key, []).append(packet)
                    if key in scored or flow.pkt_count < 5 or flow.last_seen <= flow.first_seen:
                        continue
                    features = build_packet_features_14(flow)
                    assert len(features) == 14 and all(math.isfinite(x) for x in features)
                    assert flow.pkt_count == 5, 'First eligible prefix unexpectedly delayed'
                    packets=observed.pop(key)
                    assert len(packets)==5
                    sizes=np.array([p.size for p in packets],dtype=float)
                    stamps=np.array([p.observed_at for p in packets])
                    iats=np.diff(stamps)*1000
                    outgoing=sum(p.size for p in packets if p.src_ip==flow.client_ip and p.src_port==flow.src_port)
                    incoming=sum(sizes)-outgoing
                    windows=[];begin=packets[0].observed_at;count=total=0
                    for p in packets:
                        if p.observed_at-begin>=1:
                            windows.append((count,total));begin=p.observed_at;count=total=0
                        count+=1;total+=p.size
                    windows.append((count,total))
                    duration=stamps[-1]-stamps[0]
                    reference=[duration,5,float(sum(sizes)),sum(sizes)/duration,5/duration,
                               float(np.mean(sizes)),float(np.std(sizes)),incoming/(outgoing+1),
                               max(w[0] for w in windows),max(w[1] for w in windows),
                               float(np.mean(iats)),float(np.std(iats)),sorted(iats)[int(len(iats)*.95)],
                               float(np.mean(sizes<120))]
                    assert np.allclose(features,reference,rtol=1e-10,atol=1e-8),'Independent prefix-statistics mismatch'
                    scored.add(key)
                    rows.append(dict(capture=entry['capture'], edition=entry['edition'], session=entry['session'],
                                     split=entry['split'], label=int(entry['label']=='malicious'),
                                     flow=list(key), features=features, packets=flow.pkt_count))
            finally:
                process.stdout.close()
                if process.poll() is None:
                    process.wait(timeout=30)
            assert process.returncode == 0, 'Decoder failed'
        diagnostics.append(dict(capture=entry['capture'], labelled_requests=len(entry['outcomes']),
                                eligible_flows=len(scored), packet_counts=dict(counts),
                                independent_feature_parity='all 14 values match independent NumPy calculations',
                                label_source=entry['label_source'], sha256=entry['sha256']))
        assert len(scored)==len(entry['outcomes']), 'Capture did not retain every labelled request prefix'
    return rows, diagnostics


def metrics(y, p):
    tn, fp, fn, tp = confusion_matrix(y, p >= .5, labels=[0, 1]).ravel()
    return dict(tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp),
                benign_flows=int(tn+fp), malicious_flows=int(fn+tp),
                benign_false_positive_rate=float(fp/(tn+fp)) if tn+fp else None,
                malicious_recall=float(tp/(tp+fn)) if tp+fn else None,
                threshold=.5)


def main():
    folders = [Path(x) for x in sys.argv[1:]]
    rows, diagnostics = [], []
    for folder in folders:
        extracted, counts = extract(folder)
        rows.extend(extracted)
        diagnostics.extend(counts)
    assert rows
    output = folders[0]/'model-comparison'
    output.mkdir(exist_ok=True)
    (output/'prefixes.json').write_text(json.dumps(rows, indent=2)+'\n')
    shipped = MLPThreatDetector('/opt/minifw_ai/models/mlp_packet14.pkl', enable_caching=False)
    assert shipped.model_loaded and shipped.feature_schema == 'packet14-v1'
    X = pd.DataFrame([r['features'] for r in rows], columns=shipped.feature_names)
    y = np.array([r['label'] for r in rows])
    masks = {s: np.array([r['split']==s for r in rows]) for s in ['train', 'validation', 'test']}
    captures = {s: {r['capture'] for r in rows if r['split']==s} for s in masks}
    assert all(not captures[a] & captures[b] for a,b in [('train','validation'),('train','test'),('validation','test')])
    assert all(set(y[m]) == {0,1} for m in masks.values()), 'Each split requires both classes'
    scaler = StandardScaler().fit(X[masks['train']])
    transformed = scaler.transform(X)
    models = {'trained_MLP': MLPClassifier(hidden_layer_sizes=(32,16), max_iter=300, random_state=20261105),
              'small_RF': RandomForestClassifier(n_estimators=64, max_depth=6, min_samples_leaf=5,
                                                class_weight='balanced', random_state=20261105, n_jobs=1)}
    result = dict(schema='packet14-v1', feature_names=shipped.feature_names,
                  sklearn_version=sklearn.__version__, seed=20261105,
                  recall_target=.9, false_isolation_limit='not yet agreed',
                  method='One first eligible five-packet prefix per flow; entire generated capture sessions held out',
                  representative_sector_validation=False, independent_environment=False,
                  attack_onset_checked=False, session_labels_are_prefix_threat_ground_truth=False,
                  limitations=['All sessions use the same fictional service/network; public corpus pilot evaluated separately',
                               'First five TLS packets generally precede the guessed password; session labels do not establish attack onset at the scored prefix',
                               'Flow false positives do not equal client isolation rate',
                               'Capture and session signatures may confound results; no production qualification'],
                  diagnostics=diagnostics, splits={s: dict(flows=int(m.sum()), captures=sorted(captures[s])) for s,m in masks.items()},
                  models={}, decision='HOLD; experimental fixture comparison only')
    for name, model in [('shipped_MLP', shipped.model), *models.items()]:
        preprocessor = shipped.scaler if name=='shipped_MLP' else scaler
        values = preprocessor.transform(X)
        started = time.perf_counter()
        cpu_started=time.process_time()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            if name != 'shipped_MLP':
                model.fit(transformed[masks['train']], y[masks['train']])
        training_seconds = time.perf_counter()-started
        training_cpu_seconds=time.process_time()-cpu_started
        probabilities = model.predict_proba(values)[:,1]
        latency=[]
        for index in np.flatnonzero(masks['test']):
            started=time.perf_counter()
            model.predict_proba(preprocessor.transform(X.iloc[[index]]))
            latency.append((time.perf_counter()-started)*1000)
        scores={}
        for split in ['validation','test']:
            scores[split]={}
            for edition in ['education','financial','all']:
                mask=masks[split] & np.array([edition=='all' or r['edition']==edition for r in rows])
                scores[split][edition]=metrics(y[mask], probabilities[mask])
        bundle=dict(model=model, scaler=preprocessor, feature_schema='packet14-v1',
                    feature_names=shipped.feature_names, sklearn_version=sklearn.__version__)
        path=output/(name+'.joblib')
        joblib.dump(bundle,path)
        result['models'][name]=dict(training_seconds=training_seconds, scores=scores,
                                    training_CPU_seconds=training_cpu_seconds,
                                    single_flow_latency_ms=dict(mean=float(np.mean(latency)),p95=float(np.percentile(latency,95))),
                                    artifact_bytes=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                                    warnings=[str(x.message) for x in caught],parameters=model.get_params(),
                                    max_process_RSS_KiB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        print(name,json.dumps(scores['test']),flush=True)
    (output/'results.json').write_text(json.dumps(result,indent=2,default=str)+'\n')
    print('RESULT',output/'results.json',flush=True)


if __name__ == '__main__':
    main()
