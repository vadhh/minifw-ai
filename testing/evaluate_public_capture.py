"""Offline first-eligible-prefix quality check; never replay downloaded traffic."""
import argparse
from collections import Counter, defaultdict
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import socket
import subprocess

from minifw_ai.collector_flow import FlowTracker
from minifw_ai.collector_packets import FIELDS, observe_packet, parse_packet_fields
from minifw_ai.utils.mlp_engine import MLPThreatDetector


def read_labels(path, client):
    rows, rejected, fields = [], Counter(), None
    for line in Path(path).read_text().splitlines():
        if line.startswith("#fields"):
            fields = line.split()[1:]
        elif line and not line.startswith("#"):
            if fields is None or "label" not in fields:
                raise ValueError("Expert labels required; plain Zeek conn.log is not ground truth")
            values = line.split()
            if len(values) != len(fields):
                rejected["column_mismatch"] += 1
                continue
            row = dict(zip(fields, values))
            if row["id.orig_h"] != client or row["proto"] not in {"tcp", "udp"}:
                rejected["outside_original_client_TCP_UDP"] += 1
                continue
            label = row["label"].lower()
            if label not in {"benign", "malicious"}:
                rejected["unknown_label"] += 1
                continue
            start = float(row["ts"])
            duration = float(row["duration"]) if row["duration"] != "-" else 0.0
            if not math.isfinite(start) or not math.isfinite(duration) or duration < 0:
                rejected["invalid_interval"] += 1
                continue
            rows.append({"uid": row["uid"], "start": start, "end": start + duration,
                         "key": (row["id.orig_h"], int(row["id.orig_p"]), row["id.resp_h"],
                                 int(row["id.resp_p"]), row["proto"]),
                         "label": label, "detail": row.get("detailed-label", "-")})
    if not rows:
        raise ValueError("No eligible expert-labelled flows")
    return rows, rejected


def match_label(packet, index):
    forward = (packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port, packet.proto)
    reverse = (packet.dst_ip, packet.dst_port, packet.src_ip, packet.src_port, packet.proto)
    hits = [row for key in {forward, reverse} for row in index.get(key, [])
            if row["start"] - .001 <= packet.observed_at <= row["end"] + .001]
    return hits[0] if len(hits) == 1 else None


def evaluate(root, scenario, client, detector):
    pcap = root / (scenario + ".pcap")
    labels = root / (scenario + "-expert.labels")
    rows, rejected = read_labels(labels, client)
    index = defaultdict(list)
    for row in rows:
        index[row["key"]].append(row)
    command = ["tshark", "-n", "-r", str(pcap), "-T", "fields", "-E", "occurrence=f"]
    for field in FIELDS:
        command.extend(["-e", field])
    trackers, predictions, counts = {}, {}, Counter()
    first_stamp, last_stamp = float("inf"), float("-inf")
    networks = [ipaddress.ip_network(client + "/32")]
    stderr = root / (scenario + "-decoder.log")
    with stderr.open("w") as errors:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors, text=True,
                                   env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C.UTF-8"})
        try:
            for line in process.stdout:
                counts["decoded_rows"] += 1
                packet = parse_packet_fields(line)
                if packet is None:
                    counts["unsupported_packet"] += 1
                    continue
                first_stamp = min(first_stamp, packet.observed_at)
                last_stamp = max(last_stamp, packet.observed_at)
                row = match_label(packet, index)
                if row is None:
                    counts["unmatched_or_ambiguous_packet"] += 1
                    continue
                uid = row["uid"]
                if uid in predictions:
                    continue
                if uid not in trackers and len(trackers) >= 20000:
                    counts["unscored_state_limit_packet"] += 1
                    continue
                if uid not in trackers:
                    trackers[uid] = FlowTracker()
                tracker = trackers[uid]
                flow, _ = observe_packet(tracker, packet, networks)
                if flow is None or flow.pkt_count < 5 or not detector.can_infer(flow):
                    continue
                before = detector.total_inferences
                is_threat, probability = detector.is_suspicious(flow, return_probability=True)
                if detector.total_inferences == before:
                    counts["inference_failed_packet"] += 1
                    continue
                if len(detector.last_features) != 14 or not all(math.isfinite(value) for value in detector.last_features):
                    raise ValueError("Invalid measured feature vector")
                predictions[uid] = {"uid": uid, "label": row["label"], "detail": row["detail"],
                                    "prediction": "malicious" if is_threat else "benign", "probability": probability,
                                    "features": list(detector.last_features), "schema": detector.feature_schema,
                                    "packets_at_inference": flow.pkt_count, "enforcement_score": 0}
                del trackers[uid]
        except BaseException:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            raise
        finally:
            process.stdout.close()
        code = process.wait(timeout=10)
        if code != 0:
            raise RuntimeError("Offline decoder failed; no quality-pass claim")
    matrix = Counter(row["label"] + "_as_" + row["prediction"] for row in predictions.values())
    totals = Counter(row["label"] for row in rows if row["start"] <= last_stamp and row["end"] >= first_stamp)
    scored = Counter(row["label"] for row in predictions.values())
    result = {"scenario": scenario, "pcap_sha256": hashlib.sha256(pcap.read_bytes()).hexdigest(),
              "expert_labels_sha256": hashlib.sha256(labels.read_bytes()).hexdigest(),
              "labelled_flows": dict(totals), "scored_flows": dict(scored),
              "label_file_total_flows": dict(Counter(row["label"] for row in rows)),
              "capture_interval": [first_stamp, last_stamp],
              "unscored_flows": {label: count - scored[label] for label, count in totals.items()},
              "confusion_counts": dict(matrix), "packet_counts": dict(counts), "label_rejections": dict(rejected),
              "representative_sector_validation": False, "training_changed": False, "mode": "shadow_only",
              "method": "One first eligible prefix (at least five packets) per unambiguously time/tuple-joined original-client TCP/UDP flow; no replay"}
    (root / (scenario + "-predictions.json")).write_text(json.dumps(list(predictions.values()), indent=2))
    (root / (scenario + "-evaluation.json")).write_text(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--benign-only", action="store_true")
    args = parser.parse_args()
    assert socket.gethostname() == "minifw-monday-education" and os.geteuid() != 0
    detector = MLPThreatDetector("/opt/minifw_ai/models/mlp_packet14.pkl", enable_caching=False)
    assert detector.model_loaded and detector.feature_schema == "packet14-v1"
    scenarios = [("benign", "192.168.1.132")] + ([] if args.benign_only else [("mirai", "192.168.1.195")])
    for scenario, client in scenarios:
        print(json.dumps(evaluate(args.root, scenario, client, detector)), flush=True)
