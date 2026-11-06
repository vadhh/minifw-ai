"""Per-client evaluation of the frozen client-window-v1 model on lab corpus runs. Stdlib only.

Usage: python3 -I evaluate_window_model.py <run-dir> [<run-dir> ...]
Each run dir holds actor-*.jsonl[.gz] (per-connection labels: kind, ip, port, start) and flows.jsonl[.gz]
(gateway flow exports). Features come from minifw_ai.client_window.ClientWindow, the code the engine runs.
Exit code: 0 PASS, 1 FAIL, 2 model file differs from the one frozen in manifest.json.
"""
import gzip
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
sys.path.insert(0, str(REPO / "app"))
from minifw_ai.client_window import ClientWindow, WindowModel  # noqa: E402

MODEL_PATH = REPO / "models" / "client_window_v1.json"
MANIFEST_PATH = HERE / "manifest.json"
JOIN_SECONDS = 5.0  # actor start vs gateway first_seen, as in analyze_corpus.py
FAST_KINDS = ("tool", "tool1")
ACCEPTANCE_RULE = (
    "Held-out pass requires: 0 human clients isolated, and at least 90% of fast-guesser clients (kind tool and "
    "tool1) isolated within 60 s of their first connection. The benign automated poller is expected to be flagged; "
    "it is reported separately and shows why servers/pollers must be exempt or out of AI segments. Slow guessers "
    "are out of scope (D3) and reported. If held-out fails, C20 ships with AI shadow-only and the report says so. "
    "No retraining or threshold change on held-out results."
)


def read_jsonl(path):
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def run_files(run, pattern):
    """Plain file wins over its .gz twin (gunzip -k leaves both)."""
    files = {}
    for p in sorted(Path(run).glob(pattern + "*")):
        name = p.name.removesuffix(".gz")
        if Path(name).match(pattern):
            files.setdefault(name, p)
    return list(files.values())


def replay(run):
    """Deduped gateway flows of one run in first-seen order, each with the n60 that ClientWindow.add() returned.

    Every flow (all destinations) feeds one fresh window. Exports repeat a connection with growing counters but
    the same timestamp (FlowStats.first_seen), so the key is the 5-tuple plus first_seen: one record per
    flow-tracker entry, which is what the runtime counts. A reused source port with a new first_seen is a new flow.
    """
    raw = [r for p in run_files(run, "flows.jsonl") for r in read_jsonl(p)]
    unique = {}
    for r in raw:
        unique.setdefault((r["client_ip"], r["dst_ip"], r["dst_port"], r["src_port"], r["proto"], r["timestamp"]), r)
    window = ClientWindow(ignore_before=0)
    flows = []
    for r in sorted(unique.values(), key=lambda r: r["timestamp"]):
        features = window.add(r["client_ip"], r["dst_ip"], r["dst_port"], r["timestamp"])
        if features:
            flows.append(dict(client_ip=r["client_ip"], dst=f"{r['dst_ip']}:{r['dst_port']}",
                              src_port=r["src_port"], t=r["timestamp"], **features))
    stats = dict(export_records=len(raw), flows=len(flows), five_tuples=len({k[:5] for k in unique}))
    return flows, stats


def join(run, flows):
    """Actor connections matched to the nearest gateway flow with the same client_ip and source port (any server)."""
    actors = [a for p in run_files(run, "actor-*.jsonl") for a in read_jsonl(p)]
    by_port = defaultdict(list)
    for f in flows:
        by_port[(f["client_ip"], f["src_port"])].append(f)
    joined = []
    for a in actors:
        if not a.get("port"):
            continue
        near = [f for f in by_port[(a["ip"], a["port"])] if abs(f["t"] - a["start"]) < JOIN_SECONDS]
        if near:
            joined.append((a, min(near, key=lambda f: abs(f["t"] - a["start"]))))
    return actors, joined


def evaluate(run, model):
    flows, stats = replay(run)
    actors, joined = join(run, flows)
    offsets = [f["t"] - a["start"] for a, f in joined]
    stats.update(actor_records=len(actors), actor_connections=sum(1 for a in actors if a.get("port")),
                 joined=len(joined), joined_distinct_flows=len({id(f) for _, f in joined}),
                 join_offset_seconds=dict(min=round(min(offsets), 3), median=round(statistics.median(offsets), 3),
                                          max=round(max(offsets), 3)) if offsets else None)
    kinds, labelled, servers = defaultdict(set), defaultdict(int), defaultdict(set)
    for a in actors:
        kinds[a["ip"]].add(a["kind"])
        labelled[a["ip"]] += bool(a.get("port"))
    joined_count = defaultdict(int)
    for a, f in joined:
        joined_count[a["ip"]] += 1
        servers[a["ip"]].add(f["dst"])
    by_client = defaultdict(list)
    for f in flows:
        f["p"] = model.probability(f)
        by_client[f["client_ip"]].append(f)
    clients = {}
    for ip in sorted(set(kinds) | set(by_client)):
        mine = by_client[ip]
        flagged = [f for f in mine if f["p"] >= model.block_probability]
        clients[ip] = dict(kind="+".join(sorted(kinds[ip])) or "unlabelled", actor_connections=labelled[ip],
                           joined=joined_count[ip], connections=len(mine), servers=sorted(servers[ip]),
                           max_n60=max((f["n60"] for f in mine), default=0), max_p=round(max((f["p"] for f in mine), default=0), 4),
                           flagged=len(flagged), isolated=bool(flagged),
                           seconds_to_first_flag=round(flagged[0]["t"] - mine[0]["t"], 1) if flagged else None)
    return dict(stats=stats, clients=clients)


def summarise(results):
    """Acceptance check over all runs pooled. Every kind is counted by name; only human/tool/tool1 decide."""
    clients = [c for r in results.values() for c in r["clients"].values()]
    by_kind = defaultdict(list)
    for c in clients:
        by_kind[c["kind"]].append(c)
    kinds = {k: dict(clients=len(v), isolated=sum(c["isolated"] for c in v),
                     isolated_within_60s=sum(c["isolated"] and c["seconds_to_first_flag"] <= 60 for c in v),
                     worst_seconds_to_first_flag=max((c["seconds_to_first_flag"] for c in v if c["isolated"]), default=None))
             for k, v in sorted(by_kind.items())}
    humans_isolated = kinds.get("human", {}).get("isolated", 0)
    fast = sum(kinds.get(k, {}).get("clients", 0) for k in FAST_KINDS)
    fast_ok = sum(kinds.get(k, {}).get("isolated_within_60s", 0) for k in FAST_KINDS)
    passed = humans_isolated == 0 and fast > 0 and fast_ok >= 0.9 * fast
    return dict(kinds=kinds, human_clients_isolated=humans_isolated, fast_guessers=fast,
                fast_guessers_isolated_within_60s=fast_ok, verdict="PASS" if passed else "FAIL")


def table(name, result):
    lines = [f"== {name}  {json.dumps(result['stats'])}",
             f"{'client':<16}{'kind':<12}{'conns':>6}{'joined':>7}{'max_n60':>8}{'flagged':>8}  isolated  first_flag_s"]
    for ip, c in result["clients"].items():
        lines.append(f"{ip:<16}{c['kind']:<12}{c['connections']:>6}{c['joined']:>7}{c['max_n60']:>8}{c['flagged']:>8}  "
                     f"{'yes' if c['isolated'] else 'no':<8}  {c['seconds_to_first_flag']}")
    return "\n".join(lines)


def main(runs):
    raw = MODEL_PATH.read_bytes()
    model = WindowModel(raw)
    frozen = json.loads(MANIFEST_PATH.read_text())["model_sha256"] if MANIFEST_PATH.exists() else None
    print(f"model {MODEL_PATH} sha256={model.sha256} frozen={frozen} block_probability={model.block_probability}")
    if frozen != model.sha256:
        print("ERROR: model file is not the one frozen in manifest.json; refusing to evaluate.")
        return 2
    results = {run: evaluate(run, model) for run in runs}
    for run, result in results.items():
        print(table(run, result))
    summary = summarise(results)
    print("\nAcceptance rule (pre-committed): " + ACCEPTANCE_RULE)
    for kind, k in summary["kinds"].items():
        print(f"  {kind:<12} clients={k['clients']} isolated={k['isolated']} within_60s={k['isolated_within_60s']} "
              f"worst_s={k['worst_seconds_to_first_flag']}")
    print(f"  human clients isolated: {summary['human_clients_isolated']} (must be 0)")
    print(f"  fast guessers (tool+tool1) isolated within 60 s: {summary['fast_guessers_isolated_within_60s']}"
          f"/{summary['fast_guessers']} (need >= 90%)")
    print(f"VERDICT: {summary['verdict']}")
    print("JSON " + json.dumps(dict(model_sha256=model.sha256, runs=results, summary=summary)))
    return 0 if summary["verdict"] == "PASS" else 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1:]))
