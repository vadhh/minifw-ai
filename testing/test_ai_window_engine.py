"""Client-window AI wired into the engine loop: owner, event fields, one count per connection, policy Save."""

import hashlib
import ipaddress
import json
import shutil
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from minifw_ai import client_window as cw
from minifw_ai.collector_flow import ConntrackFlow, FlowTracker
from minifw_ai.collector_packets import PacketObservation, observe_packet
from minifw_ai.collector_zeek import ZeekSSLEvent
from minifw_ai.events import Event, EventWriter
from minifw_ai.main import _resolve_decision_owner

ROOT = Path(__file__).resolve().parents[1]
CLIENT, SERVER = "10.10.0.20", "198.18.0.2"
# n60=35 -> p=0.924 (isolate); n60=34 -> p=0.881 (below block_probability 0.9)
MODEL = json.dumps(dict(schema=cw.SCHEMA, features=list(cw.FEATURES), coef=[0.5], intercept=-15.0,
                        block_probability=0.9)).encode()


def test_ai_window_rate_is_credited_to_the_ai_even_with_monitor_level_reasons():
    assert _resolve_decision_owner(["ai_window_rate"]) == "AI Engine (client window)"
    assert _resolve_decision_owner(["vpn_tunnel:wireguard", "mlp_threat_score_40", "yara_X", "ai_window_rate"]) \
        == "AI Engine (client window)"
    assert _resolve_decision_owner(["vpn_tunnel:wireguard"]) == "Protocol Policy"
    assert _resolve_decision_owner(["sector_rule:blocked_asn"]) == "Policy Engine"


def test_event_ai_window_fields_default_and_serialise(tmp_path):
    ev = Event(ts="t", segment="default", client_ip=CLIENT, domain="", action="allow", score=0, reasons=[])
    assert (ev.ai_window_n60, ev.ai_window_probability, ev.ai_window_mode, ev.ai_window_model_sha256) \
        == (None, None, "not_run", "")
    ev.ai_window_n60, ev.ai_window_probability, ev.ai_window_mode = 35, 0.92, "shadow_only"
    EventWriter(str(tmp_path / "events.jsonl")).write(ev)
    row = json.loads((tmp_path / "events.jsonl").read_text())
    assert row == json.loads(json.dumps(asdict(ev)))
    assert row["ai_window_mode"] == "shadow_only" and row["ai_window_n60"] == 35


def test_one_connection_is_new_once_across_conntrack_zeek_and_packets():
    sample = ConntrackFlow(CLIENT, SERVER, 22, "tcp", 51000)
    tracker = FlowTracker()
    assert tracker.observe_conntrack(sample)[1]
    assert tracker.get_flow(CLIENT, SERVER, 22, "tcp", 51000) is not None  # zeek's `existing`: not new
    assert not tracker.observe_conntrack(sample)[1]

    tracker = FlowTracker()
    tracker.update_flow(CLIENT, SERVER, 22, "tcp", src_port=51000)  # zeek first
    assert not tracker.observe_conntrack(sample)[1]

    tracker, subnets = FlowTracker(), [ipaddress.ip_network("10.10.0.0/16")]
    request = PacketObservation(1000.0, 60, CLIENT, SERVER, 51000, 22, "tcp")
    reply = PacketObservation(1000.1, 60, SERVER, CLIENT, 22, 51000, "tcp")
    assert observe_packet(tracker, request, subnets)[1]
    assert not observe_packet(tracker, reply, subnets)[1]
    assert not observe_packet(tracker, request, subnets)[1]


def _run_engine(tmp_path, monkeypatch, observations, *, approve, sector="education", mode="minifw_school"):
    from minifw_ai import main
    from minifw_ai.state_manager import ProtectionState, StateManager

    model_path = tmp_path / "client_window_v1.json"
    model_path.write_bytes(MODEL)
    env = {
        "MINIFW_POLICY": str(ROOT / f"config/modes/{mode}/policy.json"),
        "MINIFW_FEEDS": str(tmp_path / "feeds"), "MINIFW_LOG": str(tmp_path / "events.jsonl"),
        "MINIFW_FLOW_RECORDS": str(tmp_path / "flows.jsonl"), "MINIFW_AUDIT_LOG": str(tmp_path / "audit.jsonl"),
        "MINIFW_DNS_SOURCE": "none", "AI_ENABLED": "1", "DEGRADED_MODE": "0", "DEMO_MODE": "1",
        "MINIFW_AI_WINDOW_MODEL": str(model_path),
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    for key in ["MINIFW_MLP_MODEL", "MINIFW_YARA_RULES", "MINIFW_PACKET_INTERFACE"]:
        monkeypatch.delenv(key, raising=False)
    if approve:
        monkeypatch.setenv("MINIFW_AI_ENFORCE_MODEL_SHA256", hashlib.sha256(MODEL).hexdigest())
    else:
        monkeypatch.delenv("MINIFW_AI_ENFORCE_MODEL_SHA256", raising=False)

    def pinned_state(initial_state):
        sm = StateManager(ProtectionState.AI_ENHANCED_PROTECTION, state_file_path=str(tmp_path / "state.json"))
        sm.check_and_transition = lambda: (False, sm.get_current_state(), "")
        return sm

    monkeypatch.setattr(main, "StateManager", pinned_state)
    monkeypatch.setattr(main, "ClientWindow", lambda ignore_before: cw.ClientWindow())  # synthetic flows are "now"
    monkeypatch.setattr(main, "METRICS_AVAILABLE", False)
    monkeypatch.setattr(main, "SECTOR_LOCK_AVAILABLE", True)
    lock = SimpleNamespace(get_sector=lambda: sector, get_sector_config=lambda: {}, is_hospital=lambda: False)
    monkeypatch.setattr(main, "get_sector_lock", lambda: lock)
    for name in ["audit_config_loaded", "audit_firewall_init", "audit_daemon_start", "audit_ip_block"]:
        monkeypatch.setattr(main, name, Mock())
    monkeypatch.setattr(main, "stream_collector_events", lambda sources: iter(observations))
    enforce = Mock(return_value=True)
    monkeypatch.setattr(main, "ipset_add", enforce)
    main.run()
    events = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text().splitlines()]
    return enforce, events


def guesses(client=CLIENT, n=35, port=22):
    return [("flow", ConntrackFlow(client, SERVER, port, "tcp", 40000 + i)) for i in range(n)]


def test_engine_counts_one_connection_once_across_sources(tmp_path, monkeypatch):
    zeek = ZeekSSLEvent(CLIENT, "", 0.0, 0.0, 0.0, dst_ip=SERVER, dst_port=22, src_port=40000)
    observations = guesses(n=1) + [("zeek", zeek)] + guesses(n=1) + [("flow", ConntrackFlow(CLIENT, SERVER, 22, "tcp", 40001))]
    observations.append(("flow", ConntrackFlow(CLIENT, SERVER, 53, "udp", 40002)))  # UDP is not counted
    _, events = _run_engine(tmp_path, monkeypatch, observations, approve=False)
    assert [e["ai_window_n60"] for e in events] == [1, None, None, 2, None]


@pytest.mark.parametrize("scenario", ["enforcing", "shadow", "segment_not_listed", "rule_block_first"])
def test_engine_ai_only_isolation(tmp_path, monkeypatch, scenario):
    client = "10.0.0.5" if scenario == "segment_not_listed" else CLIENT  # school admin segment is not listed
    observations = guesses(client)
    if scenario == "rule_block_first":  # 14 other ports + port 22 = port-scan hard gate before the AI threshold
        observations = [("flow", ConntrackFlow(client, SERVER, 1000 + i, "tcp", 30000 + i)) for i in range(14)
                        ] + observations
    enforce, events = _run_engine(tmp_path, monkeypatch, observations, approve=scenario != "shadow")
    last, before = events[-1], events[-2]
    sha = hashlib.sha256(MODEL).hexdigest()
    assert last["ai_window_n60"] == 35 and last["ai_window_probability"] > 0.9
    assert last["ai_window_model_sha256"] == sha
    assert before["ai_window_n60"] == 34

    if scenario == "enforcing":
        enforce.assert_called_once_with("minifw_block_v4", client, 900, family="inet", table_name="minifw",
                                        refresh=False)
        assert before["action"] == "allow"
        assert last["action"] == "block" and last["score"] == 92
        assert last["reasons"] == ["ai_window_rate"]
        assert last["decision_owner"] == "AI Engine (client window)"
        assert {e["ai_window_mode"] for e in events} == {"enforcing"}
    elif scenario == "rule_block_first":
        assert enforce.call_count > 0
        assert all(call.args[2] == 86400 for call in enforce.call_args_list)  # rule blocks keep their timeout
        assert not any("ai_window_rate" in e["reasons"] for e in events)
        assert last["decision_owner"] == "Hard Gate" and last["ai_window_mode"] == "enforcing"
    else:
        enforce.assert_not_called()
        assert not any("ai_window_rate" in e["reasons"] for e in events)
        assert last["action"] == "allow" and last["score"] == 0
        assert {e["ai_window_mode"] for e in events} == {"shadow_only" if scenario == "shadow" else "enforcing"}


@pytest.mark.parametrize("mode,excluded", [("minifw_financial", {"dmz", "trading"}), ("minifw_school", {"admin"})])
def test_policy_save_keeps_ai_enforcement(tmp_path, monkeypatch, mode, excluded):
    from app.services.policy import update_policy_service as svc

    policy = tmp_path / "policy.json"
    shutil.copy(ROOT / f"config/modes/{mode}/policy.json", policy)
    monkeypatch.setenv("MINIFW_POLICY", str(policy))
    monkeypatch.setenv("MINIFW_LOG", str(tmp_path / "logs/events.jsonl"))
    original = json.loads(policy.read_text())
    block = original["ai_enforcement"]
    assert set(block["segments"]) <= set(original["segments"]) and not set(block["segments"]) & excluded
    assert block["exempt"] == [] and block["block_timeout_seconds"] == 900

    for save in [
        lambda: svc.update_segment("lab", 70, 40),
        lambda: svc.update_segment_subnets("lab", ["10.99.0.0/24"]),
        lambda: svc.delete_segment("lab"),
        lambda: svc.update_features(40, 35, 15, 10),
        lambda: svc.update_enforcement("minifw_block_v4", 86400, "inet", "forward"),
        lambda: svc.update_collectors("/opt/minifw_ai/logs/dnsmasq.log", "/opt/minifw_ai/logs/ssl.log", False),
        lambda: svc.update_burst(30, 50),
    ]:
        save()
        assert json.loads(policy.read_text())["ai_enforcement"] == block
