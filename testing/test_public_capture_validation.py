from pathlib import Path
from types import SimpleNamespace

import pytest

from evaluate_public_capture import match_label, read_labels


def test_unlabelled_zeek_is_rejected(tmp_path):
    p = tmp_path / "labels"
    p.write_text("#fields ts uid\n1 uid\n")
    with pytest.raises(ValueError, match="Expert labels"):
        read_labels(p, "10.0.0.1")


def test_reply_joins_same_flow_and_ambiguous_is_skipped():
    packet = SimpleNamespace(src_ip="198.18.0.2", src_port=443, dst_ip="10.0.0.1", dst_port=50000,
                             proto="tcp", observed_at=10.5)
    key = ("10.0.0.1", 50000, "198.18.0.2", 443, "tcp")
    row = {"start": 10, "end": 11}
    assert match_label(packet, {key: [row]}) is row
    assert match_label(packet, {key: [row, row.copy()]}) is None
    packet.observed_at = 12
    assert match_label(packet, {key: [row]}) is None


def test_labels_preserve_ground_truth_and_original_client(tmp_path):
    p = tmp_path / "labels"
    p.write_text("#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto duration label detailed-label\n"
                 "10 uid 10.0.0.1 50000 198.18.0.2 443 tcp 1 Benign -\n"
                 "20 incoming 198.18.0.2 443 10.0.0.1 50000 tcp 1 Malicious C&C\n")
    rows, rejected = read_labels(p, "10.0.0.1")
    assert rows[0]["label"] == "benign" and rows[0]["end"] == 11
    assert len(rows) == 1 and rejected["outside_original_client_TCP_UDP"] == 1
