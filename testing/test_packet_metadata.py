"""Real capture metadata has a separate feature schema and strict protocol correlation."""
import ipaddress
from dataclasses import replace
import socket

import pytest

from minifw_ai.collector_flow import FlowTracker, build_packet_features_14, build_feature_vector_24
from minifw_ai.collector_packets import PacketObservation, parse_packet_fields, observe_packet, protocol_policy, FIELDS
from minifw_ai.safesearch import render_safesearch

NETS = [ipaddress.ip_network("10.10.0.0/16")]


def packet(**changes):
    return replace(PacketObservation(100.0, 100, "10.10.0.20", "198.18.0.2", 51000, 443, "tcp"), **changes)


def test_measured_packet_direction_time_and_schema():
    tracker = FlowTracker()
    first, new = observe_packet(tracker, packet(), NETS)
    assert new
    reverse = packet(observed_at=100.25, src_ip="198.18.0.2", dst_ip="10.10.0.20",
                     src_port=443, dst_port=51000, size=300)
    second, new = observe_packet(tracker, reverse, NETS)
    assert second is first and not new
    vector = build_packet_features_14(second)
    assert len(vector) == 14 and vector[:6] == [0.25, 2, 400, 1600, 8, 200]
    assert vector[7] == 300 / 101 and vector[10:13] == [250, 0, 250]
    assert second.bytes_sent == 100 and second.bytes_recv == 300
    with pytest.raises(ValueError):
        build_feature_vector_24(second)
    observe_packet(tracker, packet(observed_at=99.0), NETS)
    assert second.pkt_count == 2


def test_ambiguous_initial_intrasite_direction_is_not_guessed():
    tracker = FlowTracker()
    flow, new = observe_packet(tracker, packet(dst_ip="10.10.0.30"), NETS)
    assert flow is None and not new and not tracker.flows


def test_server_hello_selects_tls13_without_legacy_version_false_positive():
    fields = [""] * len(FIELDS)
    fields[:4] = ["100.0", "100", "198.18.0.2", "10.10.0.20"]
    fields[6:8] = ["443", "51000"]
    fields[10:13] = ["2", "0x0303", "0x0304"]
    observed = parse_packet_fields("\t".join(fields))
    assert observed.tls_version == "TLSv1.3"
    fields[10] = "1"
    assert parse_packet_fields("\t".join(fields)).tls_version == ""
    fields[0] = "nan"
    assert parse_packet_fields("\t".join(fields)) is None


def test_packet_rate_gates_require_a_complete_second_without_threshold_changes():
    from minifw_ai.main import evaluate_hard_threat
    tracker = FlowTracker()
    for index in range(5):
        flow, _ = observe_packet(tracker, packet(observed_at=100 + index * .001), NETS)
    assert flow.pkts_per_sec > 200
    assert evaluate_hard_threat([flow], 1, 200) == (False, None)
    assert evaluate_hard_threat([flow], 1, 200, port_scan_detected=True) == (True, "port_scan")


@pytest.mark.parametrize("field,value", [(1,"0"), (2,"invalid"), (6,"65536"), (11,"bad")])
def test_malformed_packet_metadata_is_rejected(field, value):
    fields = [""] * len(FIELDS)
    fields[:4] = ["100", "100", "198.18.0.2", "10.10.0.20"]
    fields[6:8] = ["443", "51000"]
    fields[10:12] = ["2", "0x0301"]
    fields[field] = value
    assert parse_packet_fields("\t".join(fields)) is None


def test_wireguard_requires_matching_handshake_and_transport_not_a_udp_port():
    tracker = FlowTracker()
    outgoing = packet(proto="udp", dst_port=51820)
    flow, _ = observe_packet(tracker, outgoing, NETS)
    assert flow.vpn_protocol == ""
    observe_packet(tracker, replace(outgoing, observed_at=101, wg_type=1, wg_sender=10), NETS)
    incoming = replace(outgoing, observed_at=102, src_ip=outgoing.dst_ip, dst_ip=outgoing.src_ip,
                       src_port=outgoing.dst_port, dst_port=outgoing.src_port, wg_type=2, wg_sender=20, wg_receiver=99)
    observe_packet(tracker, incoming, NETS)
    observe_packet(tracker, replace(outgoing, observed_at=103, wg_type=4, wg_receiver=20), NETS)
    assert flow.vpn_protocol == ""
    observe_packet(tracker, replace(incoming, observed_at=104, wg_receiver=10), NETS)
    observe_packet(tracker, replace(outgoing, observed_at=105, wg_type=4, wg_receiver=20), NETS)
    assert flow.vpn_protocol == "wireguard"
    assert protocol_policy(flow, {}) == ("monitor", ["vpn_tunnel:wireguard"])
    assert protocol_policy(flow, {"block_vpn_tunnels": True})[0] == "block"


def test_tls_minimum_and_unknown_config():
    flow, _ = observe_packet(FlowTracker(), packet(), NETS)
    controls = {"minimum_tls_version": "TLSv1.2"}
    flow.tls_version = "TLSv1.0"
    assert protocol_policy(flow, controls)[0] == "block"
    flow.tls_version = "TLSv1.3"
    assert protocol_policy(flow, controls) == ("", [])
    with pytest.raises(ValueError):
        protocol_policy(flow, {"minimum_tls_version": "typo"})


def test_safesearch_exact_hosts_preserve_unrelated_services(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: [(None, None, None, None, ("216.239.38.120", 0))])
    text = render_safesearch()
    assert "cname=www.google.com,forcesafesearch.google.com" in text
    assert "cname=www.bing.com,strict.bing.com" in text
    assert "cname=www.youtube.com,restrict.youtube.com" in text
    assert "cname=youtube.com," not in text and "accounts.google.com" not in text
    # The only address override is Firefox's DoH canary, answered NXDOMAIN.
    assert [line for line in text.splitlines() if line.startswith("address=")] == ["address=/use-application-dns.net/"]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: [(None, None, None, None, ("127.0.0.1", 0))])
    with pytest.raises(ValueError):
        render_safesearch()


@pytest.mark.parametrize("flag", ["0", "false", "FALSE ", "off", "invalid"])
def test_explicit_ai_disable_overrides_persisted_state_and_packet_health(tmp_path, monkeypatch, flag):
    from minifw_ai.state_manager import StateManager, ProtectionState
    import json
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"current_protection_state": "AI_ENHANCED_PROTECTION"}))
    monkeypatch.setenv("AI_ENABLED", flag)
    state = StateManager(ProtectionState.AI_ENHANCED_PROTECTION, str(path))
    state.record_packet_event()
    state._health.consecutive_healthy = 10
    assert not state.is_ai_enabled() and not state.check_and_transition()[0]


def test_real_packet_health_supports_ai_without_dns(tmp_path, monkeypatch):
    from minifw_ai.state_manager import StateManager, ProtectionState
    monkeypatch.setenv("AI_ENABLED", "1")
    state = StateManager(ProtectionState.BASELINE_PROTECTION, str(tmp_path / "state.json"))
    state._health.check_interval = 0
    for _ in range(3):
        state.record_packet_event()
        state.check_and_transition()
    assert state.is_ai_enabled()


def test_bundled_packet_model_infers_only_its_measured_schema():
    import sklearn
    from pathlib import Path
    from minifw_ai.utils.mlp_engine import MLPThreatDetector
    if sklearn.__version__ != "1.5.2":
        pytest.skip("Packet model uses pinned Debian sklearn 1.5.2; cross-version inference is rejected")
    detector = MLPThreatDetector(str(Path(__file__).resolve().parents[1] / "models/mlp_packet14.pkl"))
    assert detector.model_loaded and detector.feature_schema == "packet14-v1"
    tracker = FlowTracker()
    for i in range(5):
        flow, _ = observe_packet(tracker, packet(observed_at=100 + i * .25), NETS)
    suspicious, probability = detector.is_suspicious(flow, return_probability=True)
    assert detector.total_inferences == 1 and len(detector.last_features) == 14
    assert detector.last_features[:3] == [1, 5, 500] and 0 <= probability <= 1
    assert isinstance(suspicious, bool)
    flow.packet_timing_available = False
    assert not detector.can_infer(flow)
    detector.is_suspicious(flow)
    assert detector.total_inferences == 1


def test_capture_stream_uses_memory_pipe_and_stops_both_children(monkeypatch):
    import io
    from unittest.mock import MagicMock
    from minifw_ai import collector_packets
    fields = [""] * len(FIELDS)
    fields[:4] = ["100", "100", "10.10.0.20", "198.18.0.2"]
    fields[6:8] = ["51000", "443"]
    capture, decoder = MagicMock(), MagicMock()
    capture.stdout = io.BytesIO()
    decoder.stdout = iter(["\t".join(fields)])
    capture.poll.return_value = decoder.poll.return_value = None
    launch = MagicMock(side_effect=[capture, decoder])
    monkeypatch.setattr(collector_packets.subprocess, "Popen", launch)
    events = collector_packets.stream_packet_events("mfcg")
    assert next(events).size == 100
    events.close()
    assert launch.call_args_list[0].args[0][-2:] == ["-w", "-"]
    assert "-r" in launch.call_args_list[1].args[0]
    assert launch.call_args_list[1].kwargs["user"] != 0
    assert "SSLKEYLOGFILE" not in launch.call_args_list[1].kwargs["env"]
    assert "JWT_SECRET" not in launch.call_args_list[1].kwargs["env"]
    capture.terminate.assert_called_once()
    decoder.terminate.assert_called_once()
