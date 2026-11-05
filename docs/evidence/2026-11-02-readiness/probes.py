"""Offline requirement probes; known defects should FAIL. No real nft calls."""

import itertools
import json
import os
import pickle
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT / "app"), str(ROOT)]
if "--save" in sys.argv:
    sys.stdout = (Path(__file__).parent / "probes.log").open("w")
    sys.stderr = sys.stdout

from minifw_ai import main
from minifw_ai.collector_flow import FlowStats, FlowTracker, parse_conntrack_line
from minifw_ai.feeds import FeedMatcher
from minifw_ai.policy import Policy, SegmentThreshold
from minifw_ai.state_manager import ProtectionState


class RequirementProbes(unittest.TestCase):
    def parse_case(self, prefix, proto, port):
        line = (f"{prefix}{proto} {'6 117 ESTABLISHED' if proto == 'tcp' else '17 30'} "
                f"src=10.10.0.20 dst=192.0.2.80 sport=52000 dport={port} packets=10 bytes=800 "
                f"src=192.0.2.80 dst=10.10.0.20 sport={port} dport=52000 packets=8 bytes=1600 mark=0 use=2")
        actual = parse_conntrack_line(line)
        print("PARSER", repr(line), "ACTUAL", actual)
        self.assertEqual(actual, ("10.10.0.20", "192.0.2.80", port, proto))

    def test_procfs_tcp_original_tuple(self):
        self.parse_case("ipv4 2 ", "tcp", 443)

    def test_procfs_udp_original_tuple(self):
        self.parse_case("ipv4 2 ", "udp", 53)

    def test_cli_tcp_original_tuple(self):
        self.parse_case("", "tcp", 443)

    def test_cli_udp_original_tuple(self):
        self.parse_case("", "udp", 53)

    def test_sni_does_not_label_unrelated_connection(self):
        t = FlowTracker()
        t.update_flow("10.10.0.20", "192.0.2.80", 443, "tcp")
        other = t.update_flow("10.10.0.20", "192.0.2.81", 22, "tcp")
        t.enrich_with_sni("10.10.0.20", "bank.example")
        print("SNI_UNRELATED_PORT_22", other.sni)
        self.assertEqual(other.sni, "")

    def test_dns_requires_connection_correlation(self):
        t = FlowTracker()
        t.update_flow("10.10.0.20", "192.0.2.80", 443, "tcp")
        other = t.update_flow("10.10.0.20", "192.0.2.81", 443, "tcp")
        t.enrich_with_dns("10.10.0.20", "bank.example")
        print("DNS_UNRELATED_DESTINATION", other.domain)
        self.assertEqual(other.domain, "")

    def test_financial_dmz_precedence(self):
        p = Policy(str(ROOT / "config/modes/minifw_financial/policy.json"))
        actual = main.segment_for_ip("10.10.0.20", p.segment_subnets())
        print("FINANCIAL_DMZ", actual)
        self.assertEqual(actual, "dmz")

    def test_education_bare_domain_matches_school_feed(self):
        feeds = FeedMatcher(str(ROOT / "config/feeds"))
        feeds.load_sector_feeds(["school_blacklist.txt"])
        actual = [feeds.domain_denied(d) for d in ["4chan.org", "www.4chan.org"]]
        print("EDUCATION_BARE_SUBDOMAIN", actual)
        self.assertEqual(actual, [True, True])

    def test_education_template_segment_selection_control(self):
        p = Policy(str(ROOT / "config/modes/minifw_school/policy.json"))
        for ip, expected in [("10.10.0.20", "student"), ("192.168.1.20", "staff"),
                             ("192.168.100.20", "guest"), ("10.0.0.20", "admin")]:
            actual = main.segment_for_ip(ip, p.segment_subnets())
            print("EDUCATION_TEMPLATE_SEGMENT", ip, actual)
            self.assertEqual(actual, expected)

    def test_deny_domain_is_currently_score_only_control(self):
        for mode, segment, adjustment in [("minifw_school", "student", -10),
                                           ("minifw_financial", "internal", -5)]:
            p = Policy(str(ROOT / f"config/modes/{mode}/policy.json"))
            thr = p.thresholds(segment)
            thr = SegmentThreshold(thr.block_threshold + adjustment, thr.monitor_threshold + adjustment)
            actual = main.score_and_decide("blocked.example", True, False, False, 0, p.features(), thr)
            print("DENY_DOMAIN_SCORE_ONLY", mode, actual)
            self.assertEqual((actual[0], actual[2]), (40, "monitor"))

    def test_degraded_flow_actually_reaches_evaluation_and_enforcement(self):
        class EndProbe(BaseException):
            pass

        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {
                "MINIFW_POLICY": str(ROOT / "config/modes/minifw_school/policy.json"),
                "MINIFW_FEEDS": str(ROOT / "config/feeds"),
                "MINIFW_LOG": str(Path(tmp) / "events.jsonl"),
                "MINIFW_FLOW_RECORDS": str(Path(tmp) / "flows.jsonl"),
                "MINIFW_AUDIT_LOG": str(Path(tmp) / "audit.jsonl"),
                "MINIFW_DNS_SOURCE": "none", "DEGRADED_MODE": "1", "AI_ENABLED": "0",
                "MINIFW_DISABLE_FLOWS": "0", "MINIFW_FLOW_FREQ_THRESHOLD": "1", "DEMO_MODE": "1",
            }))
            for name in ["METRICS_AVAILABLE", "SECTOR_LOCK_AVAILABLE"]:
                stack.enter_context(patch.object(main, name, False))
            stack.enter_context(patch.object(main.signal, "signal"))
            state = stack.enter_context(patch.object(main, "StateManager")).return_value
            state.is_ai_enabled.return_value = False
            state.get_current_state.return_value = ProtectionState.BASELINE_PROTECTION
            state.check_and_transition.side_effect = [
                (False, ProtectionState.BASELINE_PROTECTION, "probe"), EndProbe()
            ]
            stack.enter_context(patch.object(main, "stream_conntrack_flows", return_value=itertools.repeat(
                ("10.10.0.20", "192.0.2.80", 443, "tcp"))))
            evaluate = stack.enter_context(patch.object(main, "evaluate_hard_threat", wraps=main.evaluate_hard_threat))
            enforce = stack.enter_context(patch.object(main, "ipset_add"))
            with self.assertRaises(EndProbe):
                main.run()
            print("DEGRADED_NO_DNS", "evaluation_calls", evaluate.call_count, "enforcement_calls", enforce.call_count)
            self.assertGreater(evaluate.call_count, 0, "flow threshold=1 was supplied but evaluator was never called")
            self.assertGreater(enforce.call_count, 0)

    def test_bundled_model_loading_and_fixture_inference_control(self):
        from minifw_ai.utils.mlp_engine import MLPThreatDetector
        with (ROOT / "models/mlp_model.pkl").open("rb") as model:
            metadata = pickle.load(model).get("metadata", {})
        print("BUNDLED_MODEL_METADATA", json.dumps(metadata, sort_keys=True, default=str))
        d = MLPThreatDetector(str(ROOT / "models/mlp_model.pkl"))
        self.assertTrue(d.model_loaded)
        flow = FlowStats(client_ip="10.10.0.20", dst_ip="192.0.2.80", dst_port=443, proto="tcp")
        flow.first_seen = 100.0
        flow.last_seen = 110.0
        flow.pkt_count = 10
        flow.bytes_sent = 800
        flow.bytes_recv = 1600
        actual = d.is_suspicious(flow, return_probability=True)
        print("MODEL_FIXTURE_ONLY_NOT_MEASURED", actual, "INFERENCES", d.total_inferences)
        self.assertEqual(d.total_inferences, 1)
        self.assertTrue(0 <= actual[1] <= 1)


if __name__ == "__main__":
    suite = unittest.TestSuite([
        unittest.defaultTestLoader.loadTestsFromTestCase(RequirementProbes),
        unittest.defaultTestLoader.loadTestsFromName("testing.test_baseline_hard_gates"),
    ])
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
    print("AUDIT_TOTAL", result.testsRun, "FAILURES", len(result.failures),
          "ERRORS", len(result.errors), "SKIPPED", len(result.skipped))
    raise SystemExit(not result.wasSuccessful())
