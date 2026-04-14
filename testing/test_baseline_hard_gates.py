import time
import unittest
from unittest import mock
from collections import deque

from minifw_ai.collector_flow import FlowTracker, FlowStats
from minifw_ai.main import evaluate_hard_threat, init_mlp_detector, init_yara_scanner


class TestBaselineHardGates(unittest.TestCase):
    def test_hard_gate_survives_ai_failure(self):
        tracker = FlowTracker()
        flow = tracker.update_flow("192.168.1.10", "8.8.8.8", 443, "tcp", pkt_size=1500)

        flow.first_seen = time.time() - 4.0
        flow.last_seen = time.time()
        flow.pkt_count = 1000

        flows_for_client = tracker.get_flows_for_client("192.168.1.10")

        with mock.patch("minifw_ai.main.MLP_AVAILABLE", True), \
            mock.patch("minifw_ai.main.YARA_AVAILABLE", True), \
            mock.patch("minifw_ai.main.get_mlp_detector", side_effect=RuntimeError("mlp init failed")), \
            mock.patch("minifw_ai.main.get_yara_scanner", side_effect=RuntimeError("yara init failed")):
            mlp_detector, mlp_enabled = init_mlp_detector(True)
            yara_scanner, yara_enabled = init_yara_scanner(True)

        self.assertIsNone(mlp_detector)
        self.assertFalse(mlp_enabled)
        self.assertIsNone(yara_scanner)
        self.assertFalse(yara_enabled)

        hard_threat, reason = evaluate_hard_threat(flows_for_client, flow_freq=0, flow_freq_threshold=200)
        self.assertTrue(hard_threat)
        self.assertEqual(reason, "pps_saturation")

    # -------------------------------------------------------------------
    # Gate: burst_flood — max_burst_pkts_1s > 300
    # -------------------------------------------------------------------

    def test_burst_flood_gate(self):
        """Burst window with > 300 packets triggers burst_flood gate."""
        flow = FlowStats(client_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=80, proto="tcp")
        flow.pkt_count = 10
        flow.first_seen = time.time() - 5.0
        flow.last_seen = time.time()
        # Inject a burst window exceeding threshold
        flow.burst_windows = deque([{"pkts": 301, "bytes": 30100}])

        hit, reason = evaluate_hard_threat([flow], flow_freq=0, flow_freq_threshold=200)
        self.assertTrue(hit)
        self.assertEqual(reason, "burst_flood")

    def test_burst_flood_gate_below_threshold(self):
        """Burst window at exactly 300 packets does NOT trigger burst_flood."""
        flow = FlowStats(client_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=80, proto="tcp")
        flow.pkt_count = 10
        flow.first_seen = time.time() - 5.0
        flow.last_seen = time.time()
        flow.burst_windows = deque([{"pkts": 300, "bytes": 30000}])

        hit, reason = evaluate_hard_threat([flow], flow_freq=0, flow_freq_threshold=200)
        self.assertFalse(hit)
        self.assertIsNone(reason)

    # -------------------------------------------------------------------
    # Gate: bot_like_small_packets — small_pkt_ratio > 0.95 + duration < 3
    # -------------------------------------------------------------------

    def test_bot_small_packets_gate(self):
        """Flow with >95% small packets and duration < 3s triggers bot gate."""
        flow = FlowStats(client_ip="10.0.0.2", dst_ip="1.1.1.1", dst_port=53, proto="udp")
        flow.first_seen = time.time() - 2.0  # duration = 2s (< 3)
        flow.last_seen = time.time()
        flow.pkt_count = 100
        # 97 small packets (< 120 bytes) + 3 large → ratio = 0.97
        flow.pkt_sizes = deque([50] * 97 + [1500] * 3)

        hit, reason = evaluate_hard_threat([flow], flow_freq=0, flow_freq_threshold=200)
        self.assertTrue(hit)
        self.assertEqual(reason, "bot_like_small_packets")

    def test_bot_small_packets_gate_long_duration_no_trigger(self):
        """Flow with >95% small packets but duration >= 3s does NOT trigger."""
        flow = FlowStats(client_ip="10.0.0.2", dst_ip="1.1.1.1", dst_port=53, proto="udp")
        flow.first_seen = time.time() - 5.0  # duration = 5s (>= 3)
        flow.last_seen = time.time()
        flow.pkt_count = 10
        flow.pkt_sizes = deque([50] * 10)  # 100% small

        hit, reason = evaluate_hard_threat([flow], flow_freq=0, flow_freq_threshold=200)
        self.assertFalse(hit)
        self.assertIsNone(reason)

    # -------------------------------------------------------------------
    # Gate: bot_regular_timing — interarrival_std_ms < 5 + pkts_per_sec > 100
    # -------------------------------------------------------------------

    def test_bot_regular_timing_gate(self):
        """Flow with very regular IAT (std < 5ms) and high PPS triggers gate."""
        flow = FlowStats(client_ip="10.0.0.3", dst_ip="2.2.2.2", dst_port=443, proto="tcp")
        flow.first_seen = time.time() - 2.0
        flow.last_seen = time.time()
        flow.pkt_count = 201  # 201 / 2s ≈ 100.5 pps (> 100 but ≤ 200 so PPS gate won't fire)
        # Very regular interarrival: all ~4ms → std ≈ 0
        flow.interarrival_times = deque([4.0] * 100)

        hit, reason = evaluate_hard_threat([flow], flow_freq=0, flow_freq_threshold=200)
        self.assertTrue(hit)
        self.assertEqual(reason, "bot_regular_timing")

    def test_bot_regular_timing_gate_low_pps_no_trigger(self):
        """Regular IAT but low PPS (< 100) does NOT trigger."""
        flow = FlowStats(client_ip="10.0.0.3", dst_ip="2.2.2.2", dst_port=443, proto="tcp")
        flow.first_seen = time.time() - 10.0
        flow.last_seen = time.time()
        flow.pkt_count = 50  # 50 / 10s = 5 pps (< 100)
        flow.interarrival_times = deque([4.0] * 50)

        hit, reason = evaluate_hard_threat([flow], flow_freq=0, flow_freq_threshold=200)
        self.assertFalse(hit)
        self.assertIsNone(reason)

    # -------------------------------------------------------------------
    # No gate fires on benign flow
    # -------------------------------------------------------------------

    def test_benign_flow_no_gate_fires(self):
        """Normal traffic flow triggers no hard gates."""
        flow = FlowStats(client_ip="10.0.0.5", dst_ip="8.8.4.4", dst_port=443, proto="tcp")
        flow.first_seen = time.time() - 30.0
        flow.last_seen = time.time()
        flow.pkt_count = 50  # ~1.7 pps
        flow.pkt_sizes = deque([1200] * 50)  # all large packets
        flow.interarrival_times = deque([500.0 + i * 10 for i in range(50)])  # irregular

        hit, reason = evaluate_hard_threat([flow], flow_freq=0, flow_freq_threshold=200)
        self.assertFalse(hit)
        self.assertIsNone(reason)

    # -------------------------------------------------------------------
    # Flow frequency gate
    # -------------------------------------------------------------------

    def test_flow_frequency_gate(self):
        """flow_freq >= flow_freq_threshold triggers flow_frequency gate."""
        hit, reason = evaluate_hard_threat([], flow_freq=200, flow_freq_threshold=200)
        self.assertTrue(hit)
        self.assertEqual(reason, "flow_frequency")

    # -------------------------------------------------------------------
    # Flows with < 5 packets are skipped
    # -------------------------------------------------------------------

    def test_low_pkt_count_skipped(self):
        """Flows with pkt_count < 5 are skipped by gate evaluation."""
        flow = FlowStats(client_ip="10.0.0.6", dst_ip="8.8.8.8", dst_port=80, proto="tcp")
        flow.first_seen = time.time() - 0.01
        flow.last_seen = time.time()
        flow.pkt_count = 4  # below threshold
        # Would trigger PPS if not skipped: 4 / 0.01 = 400

        hit, reason = evaluate_hard_threat([flow], flow_freq=0, flow_freq_threshold=200)
        self.assertFalse(hit)
        self.assertIsNone(reason)


if __name__ == "__main__":
    unittest.main()
