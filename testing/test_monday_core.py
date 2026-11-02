"""Corrections use real identities/counters; no telemetry threshold tuning."""

import json
import threading
import time
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from minifw_ai.collector_flow import ConntrackFlow, FlowTracker, build_feature_vector_24, parse_conntrack_line
from minifw_ai.collector_runtime import stream_collector_events
from minifw_ai.feeds import FeedMatcher
from minifw_ai.main import score_and_decide, segment_for_ip
from minifw_ai.policy import SegmentThreshold


@pytest.mark.parametrize("prefix", ["", "ipv4 2 "])
@pytest.mark.parametrize("proto,number,port", [("tcp", 6, 443), ("udp", 17, 53)])
def test_conntrack_original_tuple_and_directional_counters(prefix, proto, number, port):
    line = (f"{prefix}{proto} {number} 117 src=10.10.0.20 dst=198.18.0.2 sport=51000 dport={port} "
            f"packets=10 bytes=1000 src=198.18.0.2 dst=192.0.2.9 sport={port} dport=61000 "
            "packets=8 bytes=2000 mark=0 use=2")
    assert parse_conntrack_line(line) == ConntrackFlow("10.10.0.20", "198.18.0.2", port, proto,
                                                      51000, 10, 1000, 8, 2000)


@pytest.mark.parametrize("field", ["sport=0", "sport=65536", "sport=no", "bytes=-1", "src=bad"])
def test_conntrack_rejects_malformed_observations(field):
    fields = {"sport": "sport=51000", "bytes": "bytes=100", "src": "src=10.10.0.20"}
    line = "tcp 6 117 src=10.10.0.20 dst=198.18.0.2 sport=51000 dport=443 packets=1 bytes=100"
    assert parse_conntrack_line(line.replace(fields[field.split("=")[0]], field)) is None


def test_repeated_snapshots_are_not_packets_and_resets_start_a_new_baseline():
    tracker = FlowTracker()
    sample = ConntrackFlow("10.10.0.20", "198.18.0.2", 443, "tcp", 51000, 10, 1000, 8, 2000)
    flow, new = tracker.observe_conntrack(sample)
    assert new
    for _ in range(20):
        flow, new = tracker.observe_conntrack(sample)
        assert not new
    assert (flow.pkt_count, flow.bytes_sent, flow.bytes_recv) == (0, 0, 0)
    flow, new = tracker.observe_conntrack(replace(sample, packets_out=13, bytes_out=1300,
                                                 packets_in=10, bytes_in=2400))
    assert (flow.pkt_count, flow.bytes_sent, flow.bytes_recv) == (5, 300, 400)
    assert not flow.packet_timing_available
    assert not flow.interarrival_times and not flow.pkt_sizes
    with pytest.raises(ValueError, match="unavailable from conntrack"):
        build_feature_vector_24(flow)
    flow, new = tracker.observe_conntrack(replace(sample, packets_out=1, bytes_out=100,
                                                 packets_in=0, bytes_in=0))
    assert new and flow.pkt_count == 0 and flow.get_total_bytes() == 0


def test_absent_and_partial_counters_do_not_invent_measurements():
    tracker = FlowTracker()
    sample = ConntrackFlow("10.10.0.20", "198.18.0.2", 443, "tcp", 51000)
    for _ in range(5):
        flow, _ = tracker.observe_conntrack(sample)
    assert flow.pkt_count == flow.get_total_bytes() == 0
    tracker.observe_conntrack(replace(sample, packets_out=10, bytes_out=1000))
    flow, _ = tracker.observe_conntrack(replace(sample, packets_out=12, bytes_out=1200))
    assert (flow.pkt_count, flow.bytes_sent, flow.bytes_recv) == (2, 200, 0)


def test_counter_rate_uses_elapsed_monotonic_time_not_wall_clock(monkeypatch):
    from minifw_ai import collector_flow
    monotonic = iter([10.0, 15.0])
    monkeypatch.setattr(collector_flow.time, "monotonic", lambda: next(monotonic))
    monkeypatch.setattr(collector_flow.time, "time", lambda: 100.0)
    tracker = FlowTracker()
    sample = ConntrackFlow("10.10.0.20", "198.18.0.2", 443, "tcp", 51000, 10, 1000, 8, 2000)
    tracker.observe_conntrack(sample)
    monkeypatch.setattr(collector_flow.time, "time", lambda: 50.0)
    flow, _ = tracker.observe_conntrack(replace(sample, packets_out=20, bytes_out=2000))
    assert flow.get_duration() == 5.0
    assert flow.get_pkts_per_sec() == 2.0


def test_counter_rate_uses_collection_time_even_if_decisions_are_delayed(monkeypatch):
    from minifw_ai import collector_flow
    monkeypatch.setattr(collector_flow.time, "monotonic", lambda: 1000.0)
    tracker = FlowTracker()
    first = ConntrackFlow("10.10.0.20", "198.18.0.2", 443, "tcp", 51000,
                          10, 1000, 8, 2000, observed_at=10.0)
    tracker.observe_conntrack(first)
    flow, _ = tracker.observe_conntrack(replace(first, packets_out=20, bytes_out=2000, observed_at=15.0))
    assert flow.get_duration() == 5.0 and flow.get_pkts_per_sec() == 2.0


def test_cli_snapshot_timestamp_is_stable_while_consumer_is_delayed(monkeypatch):
    from minifw_ai import collector_flow
    first = "tcp 6 117 src=10.10.0.20 dst=198.18.0.2 sport=51000 dport=443"
    second = first.replace("51000", "51001")
    monkeypatch.setattr(collector_flow.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(stdout=first + "\n" + second))
    clock = [100.0]
    monkeypatch.setattr(collector_flow.time, "monotonic", lambda: clock[0])
    stream = collector_flow._stream_conntrack_via_cli()
    a = next(stream)
    clock[0] = 1000.0
    b = next(stream)
    stream.close()
    assert a.observed_at == b.observed_at == 100.0


def test_sni_matches_connection_and_source_port_dns_queries_do_not_label_flows():
    tracker = FlowTracker()
    first = tracker.update_flow("10.10.0.20", "198.18.0.2", 443, "tcp", src_port=51000)
    second = tracker.update_flow("10.10.0.20", "198.18.0.2", 443, "tcp", src_port=51001)
    other = tracker.update_flow("10.10.0.20", "198.18.0.3", 22, "tcp", src_port=51000)
    tracker.enrich_with_sni("10.10.0.20", "bank.example", dst_ip="198.18.0.2", dst_port=443, src_port=51000)
    assert first.sni == "bank.example"
    assert second.sni == other.sni == ""
    tracker.enrich_with_dns("10.10.0.20", "unrelated.example")
    assert first.domain == second.domain == other.domain == ""


def test_ipv6_connection_identities_cannot_collide_at_colon_boundaries():
    tracker = FlowTracker()
    first = tracker.update_flow("2001:db8::1", "2001:db8::2", 443, "tcp", src_port=10)
    second = tracker.update_flow("2001:db8::1:10", "db8::2", 443, "tcp", src_port=2001)
    assert first is not second and len(tracker.flows) == 2


@pytest.mark.parametrize("silent", ["dns", "zeek", "flow"])
@pytest.mark.parametrize("mode", ["quiet", "missing", "stopped"])
def test_collectors_continue_when_another_source_is_quiet_missing_or_stopped(silent, mode):
    release = threading.Event()

    def unavailable():
        if mode == "quiet":
            release.wait(2)
        if mode == "missing":
            raise FileNotFoundError("controlled missing collector")
        return iter(())

    sources = {name: (lambda name=name: iter([name])) for name in ("dns", "zeek", "flow")}
    sources[silent] = unavailable
    events = stream_collector_events(sources)
    seen, started = set(), time.monotonic()
    try:
        while len(seen) < 2 and time.monotonic() - started < 1:
            name, event = next(events)
            if name != "tick":
                seen.add(name)
        assert seen == set(sources) - {silent}
    finally:
        release.set()
        events.close()


def test_longest_subnet_selects_dmz_and_education_segments():
    from pathlib import Path
    from minifw_ai.policy import Policy
    root = Path(__file__).resolve().parents[1]
    finance = Policy(str(root / "config/modes/minifw_financial/policy.json"))
    assert segment_for_ip("10.10.0.20", finance.segment_subnets()) == "dmz"
    school = Policy(str(root / "config/modes/minifw_school/policy.json"))
    for ip, segment in [("10.10.0.20", "student"), ("192.168.1.20", "staff"),
                        ("192.168.100.20", "guest"), ("10.0.0.20", "admin")]:
        assert segment_for_ip(ip, school.segment_subnets()) == segment


def test_deny_patterns_cover_apex_subdomain_and_case_without_suffix_confusion(tmp_path):
    (tmp_path / "deny_domains.txt").write_text("*.example.test\nvpn.test\n")
    feeds = FeedMatcher(str(tmp_path))
    for domain in ["example.test", "www.example.test", "WWW.EXAMPLE.TEST.", "vpn.test", "www.vpn.test"]:
        assert feeds.domain_denied(domain)
    for domain in ["notexample.test", "example.test.attacker.test", "notvpn.test"]:
        assert not feeds.domain_denied(domain)


@pytest.mark.parametrize("dns,sni", [(True, False), (False, True)])
def test_approved_deny_match_isolates_client_without_threshold_changes(dns, sni):
    score, reasons, action = score_and_decide("blocked.test", dns, sni, False, 0, {},
        SegmentThreshold(90, 60), deny_domain_immediate=True)
    assert (score, action) == (100, "block")
    assert "deny_domain_client_ipv4_isolation" in reasons


def test_numeric_model_reason_retains_model_attribution():
    from minifw_ai.main import _resolve_decision_owner
    assert _resolve_decision_owner(["mlp_threat_score_90"]) == "AI Engine (MLP)"


@pytest.mark.parametrize("sector,mode,scenario", [
    ("education", "minifw_school", "port_scan"),
    ("finance", "minifw_financial", "port_scan"),
    ("finance", "minifw_financial", "destination_asn"),
    ("finance", "minifw_financial", "destination_ip"),
    ("finance", "minifw_financial", "packet_source_precedence"),
])
def test_engine_enforces_flow_threat_without_dns(tmp_path, monkeypatch, sector, mode, scenario):
    from pathlib import Path
    from minifw_ai import main
    from minifw_ai.state_manager import StateManager
    root = Path(__file__).resolve().parents[1]
    if scenario == "destination_ip":
        (tmp_path / "feeds").mkdir()
        (tmp_path / "feeds/deny_ips.txt").write_text("198.18.0.2\n")
    if scenario == "destination_asn":
        (tmp_path / "feeds").mkdir()
        (tmp_path / "feeds/deny_asn.txt").write_text("AS64500\n")
        resolver = Mock(loaded=True)
        resolver.lookup.side_effect = lambda ip: "AS64500" if ip == "198.18.0.2" else "AS0"
        monkeypatch.setattr(main, "ASNResolver", lambda: resolver)
    for key, value in {
        "MINIFW_POLICY": str(root / f"config/modes/{mode}/policy.json"),
        "MINIFW_FEEDS": str(tmp_path / "feeds"), "MINIFW_LOG": str(tmp_path / "events.jsonl"),
        "MINIFW_FLOW_RECORDS": str(tmp_path / "flows.jsonl"), "MINIFW_AUDIT_LOG": str(tmp_path / "audit.jsonl"),
        "MINIFW_DNS_SOURCE": "none", "DEGRADED_MODE": "1", "AI_ENABLED": "0", "DEMO_MODE": "1",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(main, "StateManager", lambda initial_state: StateManager(initial_state,
        state_file_path=str(tmp_path / "state.json")))
    monkeypatch.setattr(main, "METRICS_AVAILABLE", False)
    monkeypatch.setattr(main, "SECTOR_LOCK_AVAILABLE", True)
    lock = SimpleNamespace(get_sector=lambda: sector, get_sector_config=lambda: {}, is_hospital=lambda: False)
    monkeypatch.setattr(main, "get_sector_lock", lambda: lock)
    for name in ["audit_config_loaded", "audit_firewall_init", "audit_daemon_start", "audit_ip_block"]:
        monkeypatch.setattr(main, name, Mock())
    samples = [ConntrackFlow("10.10.0.20", "198.18.0.2", 10000 + i, "tcp", 51000 + i)
               for i in range(15 if scenario == "port_scan" else 1)]
    monkeypatch.setattr(main, "stream_collector_events", lambda sources: iter(("flow", s) for s in samples))
    if scenario == "packet_source_precedence":
        monkeypatch.setenv("MINIFW_PACKET_INTERFACE", "mfcg")

        def inspect_sources(sources):
            assert set(sources) == {"packet"}, "Packet mode must not merge counter/Zeek flow state"
            return iter(())

        monkeypatch.setattr(main, "stream_collector_events", inspect_sources)
    enforce = Mock(return_value=True)
    monkeypatch.setattr(main, "ipset_add", enforce)
    main.run()
    if scenario == "packet_source_precedence":
        enforce.assert_not_called()
        return
    events = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text().splitlines()]
    if scenario == "destination_ip":
        enforce.assert_not_called()
        assert "ip_denied_tor_anonymizer" in events[-1]["reasons"]
        assert events[-1]["client_ip"] == "10.10.0.20"
        return
    enforce.assert_called_once_with("minifw_block_v4", "10.10.0.20", 86400, family="inet", table_name="minifw")
    assert events[-1]["action"] == "block"
    assert events[-1]["dst_ip"] == "198.18.0.2"
    assert events[-1]["telemetry_source"] == "flow"
    assert events[-1]["mlp_status"] == "disabled_unsupported_packet_features"
    if scenario == "destination_asn":
        resolver.lookup.assert_called_once_with("198.18.0.2")
        assert "sector_rule:blocked_asn" in events[-1]["reasons"]
    else:
        assert events[-1]["decision_owner"] == "Hard Gate"
