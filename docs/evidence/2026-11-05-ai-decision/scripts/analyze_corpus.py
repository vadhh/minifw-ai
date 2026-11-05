"""Feasibility analysis of the realistic lab corpus. Diagnostic only: fictional sandbox, one lab network.

Usage: python3 analyze_corpus.py <run-dir> [<run-dir> ...]   (each holds actor-*.jsonl, flows.jsonl, events.jsonl)
"""
import glob
import json
import sys
from collections import defaultdict
from pathlib import Path

WINDOW = 60.0
SERVER = '198.18.0.2'


def load(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def analyse(run):
    actors = [r for f in glob.glob(f'{run}/actor-*.jsonl') for r in load(f) if r['port']]
    # Gateway flow records are exported repeatedly; keep the most complete export per connection.
    flows = {}
    for r in load(f'{run}/flows.jsonl'):
        if r.get('dst_ip') == SERVER and r.get('dst_port') == 443:
            key = (r['client_ip'], r['src_port'], round(r['timestamp']))
            if key not in flows or (r.get('packets') or 0) >= (flows[key].get('packets') or 0):
                flows[key] = r
    by_port = defaultdict(list)
    for (ip, port, _), r in flows.items():
        by_port[(ip, port)].append(r)
    probability = {}
    for e in load(f'{run}/events.jsonl'):
        if e.get('mlp_probability') is not None and e.get('src_port'):
            probability[(e.get('client_ip'), e['src_port'])] = e['mlp_probability']
    rows = []
    for a in actors:
        match = [r for r in by_port[(a['ip'], a['port'])] if abs(r['timestamp'] - a['start']) < 5]
        if match:
            f = min(match, key=lambda r: abs(r['timestamp'] - a['start']))
            rows.append(dict(a, t=f['timestamp'], gw_bytes=f.get('bytes'), gw_packets=f.get('packets'),
                             p=probability.get((a['ip'], a['port']))))
    rows.sort(key=lambda r: r['t'])
    # Per-client window features at each connection, using only gateway-observed data before it.
    history = defaultdict(list)
    for r in rows:
        past = [x for x in history[r['ip']] if r['t'] - x['t'] <= WINDOW]
        r['n60'] = len(past) + 1
        size = r['gw_bytes'] or 0
        r['same60'] = 1 + sum(1 for x in past if size and abs((x['gw_bytes'] or 0) - size) <= .03 * size)
        history[r['ip']].append(r)
    return actors, rows


def summary(actors, rows):
    out = {}
    out['actor_connections'] = len(actors)
    out['joined_to_gateway_flow'] = len(rows)
    kinds = sorted({r['kind'] for r in rows})
    with_p = [r for r in rows if r['p'] is not None]
    out['per_connection_shipped_model_flag_rate'] = {k: f"{sum(r['p'] >= .5 for r in with_p if r['kind'] == k)}/{sum(1 for r in with_p if r['kind'] == k)}" for k in kinds}
    out['max_n60'] = {k: max(r['n60'] for r in rows if r['kind'] == k) for k in kinds}
    out['max_same60'] = {k: max(r['same60'] for r in rows if r['kind'] == k) for k in kinds}
    rules = {'rate: >=20 connections to one server in 60 s': lambda r: r['n60'] >= 20,
             'repetition: >=6 near-identical connections in 60 s': lambda r: r['same60'] >= 6}
    out['rules'] = {}
    for name, rule in rules.items():
        clients = defaultdict(list)
        for r in rows:
            clients[(r['kind'], r['ip'])].append(r)
        detail = {}
        for (kind, ip), items in sorted(clients.items()):
            hits = [r for r in items if rule(r)]
            detail[ip] = dict(kind=kind, connections=len(items), flagged_connections=len(hits),
                              client_flagged=bool(hits),
                              seconds_to_first_flag=round(hits[0]['t'] - items[0]['t'], 1) if hits else None)
        out['rules'][name] = detail
    return out


all_actors, all_rows, report = [], [], {}
for run in sys.argv[1:]:
    actors, rows = analyse(run)
    report[Path(run).name] = summary(actors, rows)
    all_actors += actors
    all_rows += rows
print(json.dumps(report, indent=2))
