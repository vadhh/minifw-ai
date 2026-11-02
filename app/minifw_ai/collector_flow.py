"""
Flow Collector for RitAPI V-Sentinel MiniFW-AI
Collects flow-level statistics from conntrack for MLP feature extraction.
"""

from __future__ import annotations
import logging
import subprocess
import time
import hashlib
from pathlib import Path
from typing import Iterator, Optional
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass, field
import math
import ipaddress


@dataclass(frozen=True)
class ConntrackFlow:
    client_ip: str
    dst_ip: str
    dst_port: int
    proto: str
    src_port: int
    packets_out: Optional[int] = None
    bytes_out: Optional[int] = None
    packets_in: Optional[int] = None
    bytes_in: Optional[int] = None
    observed_at: Optional[float] = field(default=None, compare=False)

    @property
    def counters(self):
        return (self.packets_out, self.bytes_out, self.packets_in, self.bytes_in)


@dataclass
class FlowStats:
    """Track statistics for a single flow (5-tuple)"""

    client_ip: str
    dst_ip: str
    dst_port: int
    proto: str

    # Timing
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    # Packet/byte counters
    pkt_count: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0

    # Packet sizes for stats
    pkt_sizes: deque = field(default_factory=lambda: deque(maxlen=1000))

    # Inter-arrival times (in ms)
    interarrival_times: deque = field(default_factory=lambda: deque(maxlen=500))
    last_pkt_time: Optional[float] = None

    # Burst tracking (1-second windows)
    burst_windows: deque = field(
        default_factory=lambda: deque(maxlen=60)
    )  # last 60 seconds
    current_window_start: float = field(default_factory=time.time)
    current_window_pkts: int = 0
    current_window_bytes: int = 0

    # Domain/DNS info (optional, will be enriched later)
    domain: str = ""
    sni: str = ""
    tls_seen: bool = False

    # TLS detail fields — populated by Zeek ssl.log enrichment
    tls_handshake_ms: float = 0.0        # Handshake duration from Zeek ssl.log
    alpn_h2: float = 0.0                 # 1.0 if ALPN negotiated h2 (HTTP/2)
    cert_self_signed_suspect: float = 0.0  # 1.0 if cert chain length == 1 (self-signed)
    src_port: int = 0
    packet_timing_available: bool = True
    packet_metadata_only: bool = False
    counter_baseline: Optional[tuple] = None
    counter_started_at: Optional[float] = None
    counter_elapsed: float = 0.0
    tls_version: str = ""
    vpn_protocol: str = ""
    wg_initiator: int = -1
    wg_responder: int = -1
    wg_started_at: float = 0.0

    def update(self, pkt_size: int, direction: str = "out", *, observed_at: Optional[float] = None) -> None:
        """Update flow stats with new packet"""
        now = time.time() if observed_at is None else observed_at
        self.last_seen = now
        self.pkt_count += 1

        if direction == "out":
            self.bytes_sent += pkt_size
        else:
            self.bytes_recv += pkt_size

        self.pkt_sizes.append(pkt_size)

        # Inter-arrival time
        if self.last_pkt_time is not None:
            iat_ms = (now - self.last_pkt_time) * 1000
            self.interarrival_times.append(iat_ms)
        self.last_pkt_time = now

        # Burst tracking
        if now - self.current_window_start >= 1.0:
            # Save current window and start new one
            self.burst_windows.append(
                {"pkts": self.current_window_pkts, "bytes": self.current_window_bytes}
            )
            self.current_window_start = now
            self.current_window_pkts = 0
            self.current_window_bytes = 0

        self.current_window_pkts += 1
        self.current_window_bytes += pkt_size

    def get_duration(self) -> float:
        """Get flow duration in seconds"""
        if self.packet_metadata_only:
            return max(0.0, self.last_seen - self.first_seen)
        if not self.packet_timing_available:
            return max(0.1, self.counter_elapsed)
        return max(0.1, self.last_seen - self.first_seen)

    def get_total_bytes(self) -> int:
        """Get total bytes (sent + received)"""
        return self.bytes_sent + self.bytes_recv

    def get_bytes_per_sec(self) -> float:
        """Calculate bytes per second"""
        duration = self.get_duration()
        return self.get_total_bytes() / duration if duration > 0 else 0.0

    def get_pkts_per_sec(self) -> float:
        """Calculate packets per second"""
        duration = self.get_duration()
        return self.pkt_count / duration if duration > 0 else 0.0

    # Property shortcuts for convenience (used in hard gates)
    @property
    def duration(self) -> float:
        """Shortcut for get_duration()"""
        return self.get_duration()

    @property
    def pkts_per_sec(self) -> float:
        """Shortcut for get_pkts_per_sec()"""
        return self.get_pkts_per_sec()

    @property
    def bytes_per_sec(self) -> float:
        """Shortcut for get_bytes_per_sec()"""
        return self.get_bytes_per_sec()

    @property
    def max_burst_pkts_1s(self) -> int:
        """Shortcut for get_max_burst_pkts_1s()"""
        return self.get_max_burst_pkts_1s()

    @property
    def max_burst_bytes_1s(self) -> int:
        """Shortcut for get_max_burst_bytes_1s()"""
        return self.get_max_burst_bytes_1s()

    @property
    def small_pkt_ratio(self) -> float:
        """Shortcut for get_small_pkt_ratio()"""
        return self.get_small_pkt_ratio()

    @property
    def interarrival_std_ms(self) -> float:
        """Shortcut for get_interarrival_std_ms()"""
        return self.get_interarrival_std_ms()

    def get_avg_pkt_size(self) -> float:
        """Calculate average packet size"""
        if not self.pkt_sizes:
            return 0.0
        return sum(self.pkt_sizes) / len(self.pkt_sizes)

    def get_pkt_size_std(self) -> float:
        """Calculate packet size standard deviation"""
        if len(self.pkt_sizes) < 2:
            return 0.0
        avg = self.get_avg_pkt_size()
        variance = sum((x - avg) ** 2 for x in self.pkt_sizes) / len(self.pkt_sizes)
        return math.sqrt(variance)

    def get_inbound_outbound_ratio(self) -> float:
        """Calculate ratio of inbound to outbound bytes"""
        if self.bytes_recv == 0 and self.bytes_sent == 0:
            return 1.0
        return self.bytes_recv / (self.bytes_sent + 1)

    def get_max_burst_pkts_1s(self) -> int:
        """Get maximum burst packets in any 1-second window"""
        if not self.burst_windows:
            return self.current_window_pkts
        return max(self.current_window_pkts, max(w["pkts"] for w in self.burst_windows))

    def get_max_burst_bytes_1s(self) -> int:
        """Get maximum burst bytes in any 1-second window"""
        if not self.burst_windows:
            return self.current_window_bytes
        return max(self.current_window_bytes, max(w["bytes"] for w in self.burst_windows))

    def get_interarrival_mean_ms(self) -> float:
        """Get mean inter-arrival time in milliseconds"""
        if not self.interarrival_times:
            return 0.0
        return sum(self.interarrival_times) / len(self.interarrival_times)

    def get_interarrival_std_ms(self) -> float:
        """Get standard deviation of inter-arrival times"""
        if len(self.interarrival_times) < 2:
            return 0.0
        mean = self.get_interarrival_mean_ms()
        variance = sum((x - mean) ** 2 for x in self.interarrival_times) / len(
            self.interarrival_times
        )
        return math.sqrt(variance)

    def get_interarrival_p95_ms(self) -> float:
        """Get 95th percentile of inter-arrival times"""
        if not self.interarrival_times:
            return 0.0
        sorted_times = sorted(self.interarrival_times)
        idx = int(len(sorted_times) * 0.95)
        return sorted_times[idx] if idx < len(sorted_times) else sorted_times[-1]

    def get_small_pkt_ratio(self) -> float:
        """Get ratio of small packets (< 120 bytes)"""
        if not self.pkt_sizes:
            return 0.0
        small_count = sum(1 for s in self.pkt_sizes if s < 120)
        return small_count / len(self.pkt_sizes)


class FlowTracker:
    """Track all active flows and compute statistics"""

    def __init__(self, flow_timeout: int = 300, max_flows: int = 20000):
        """
        Args:
            flow_timeout: Flow timeout in seconds (default 5 minutes)
            max_flows: Maximum number of active flows to retain (LRU eviction)
        """
        self.flows: OrderedDict[tuple, FlowStats] = OrderedDict()
        self.flow_timeout = flow_timeout
        self.max_flows = max_flows
        self.last_cleanup = time.time()

        # Domain frequency counter for domain_repeat_5min feature
        # Tracks (domain -> [timestamp, ...]) within a 5-minute sliding window
        self._domain_timestamps: dict[str, deque] = {}
        self._domain_freq_window = 300  # 5 minutes in seconds

    def _flow_key(self, client_ip: str, dst_ip: str, dst_port: int, proto: str, src_port: int = 0) -> tuple:
        """Generate unique flow key"""
        return client_ip, src_port, dst_ip, dst_port, proto

    def update_flow(
        self,
        client_ip: str,
        dst_ip: str,
        dst_port: int,
        proto: str,
        pkt_size: int = 0,
        direction: str = "out",
        src_port: int = 0,
    ) -> FlowStats:
        """Update or create flow"""
        key = self._flow_key(client_ip, dst_ip, dst_port, proto, src_port)

        if key not in self.flows:
            if len(self.flows) >= self.max_flows:
                self.flows.popitem(last=False)
            self.flows[key] = FlowStats(
                client_ip=client_ip, dst_ip=dst_ip, dst_port=dst_port, proto=proto, src_port=src_port
            )
        else:
            self.flows.move_to_end(key)

        flow = self.flows[key]
        if pkt_size > 0:
            flow.update(pkt_size, direction)

        return flow

    def observe_conntrack(self, sample: ConntrackFlow) -> tuple[FlowStats, bool]:
        """Accumulate measured deltas; the initial snapshot is the baseline."""
        key = self._flow_key(sample.client_ip, sample.dst_ip, sample.dst_port, sample.proto, sample.src_port)
        previous = self.flows.get(key)
        counters = sample.counters
        reset = bool(previous and previous.counter_baseline and any(
            value is not None and old is not None and value < old
            for value, old in zip(counters, previous.counter_baseline)
        ))
        if reset:
            del self.flows[key]
        is_new = previous is None or reset
        flow = self.update_flow(sample.client_ip, sample.dst_ip, sample.dst_port, sample.proto,
                                src_port=sample.src_port)
        flow.packet_timing_available = False
        flow.last_seen = time.time()
        now = sample.observed_at if sample.observed_at is not None else time.monotonic()
        if flow.counter_started_at is None:
            flow.counter_started_at = now
        flow.counter_elapsed = now - flow.counter_started_at
        if flow.counter_baseline is not None:
            packets_out, bytes_out, packets_in, bytes_in = (
                value - old if value is not None and old is not None else 0
                for value, old in zip(counters, flow.counter_baseline)
            )
            flow.pkt_count += packets_out + packets_in
            flow.bytes_sent += bytes_out
            flow.bytes_recv += bytes_in
        flow.counter_baseline = counters
        return flow, is_new

    def get_flow(
        self, client_ip: str, dst_ip: str, dst_port: int, proto: str, src_port: int = 0
    ) -> Optional[FlowStats]:
        """Get flow stats if exists"""
        key = self._flow_key(client_ip, dst_ip, dst_port, proto, src_port)
        flow = self.flows.get(key)
        if flow is not None:
            self.flows.move_to_end(key)
        return flow

    def get_flows_for_client(self, client_ip: str) -> list[FlowStats]:
        """Get all active flows for a client IP"""
        return [flow for flow in self.flows.values() if flow.client_ip == client_ip]

    def enrich_with_dns(self, client_ip: str, domain: str) -> None:
        """Query-only logs support frequency, not DNS-answer/connection correlation."""
        if domain:
            self._record_domain(domain)

    def _record_domain(self, domain: str) -> None:
        """Record a domain query timestamp for frequency tracking."""
        now = time.time()
        if domain not in self._domain_timestamps:
            self._domain_timestamps[domain] = deque()
        ts = self._domain_timestamps[domain]
        ts.append(now)
        # Evict entries outside the 5-minute window
        cutoff = now - self._domain_freq_window
        while ts and ts[0] < cutoff:
            ts.popleft()
        # Prevent unbounded growth — cap at 10k unique domains
        if len(self._domain_timestamps) > 10000:
            oldest_key = next(iter(self._domain_timestamps))
            del self._domain_timestamps[oldest_key]

    def get_domain_repeat(self, domain: str) -> float:
        """Return number of times domain was seen in the last 5 minutes."""
        if not domain or domain not in self._domain_timestamps:
            return 0.0
        now = time.time()
        cutoff = now - self._domain_freq_window
        return float(sum(1 for t in self._domain_timestamps[domain] if t >= cutoff))

    def enrich_with_sni(
        self,
        client_ip: str,
        sni: str,
        handshake_ms: float = 0.0,
        alpn_h2: float = 0.0,
        cert_self_signed: float = 0.0,
        *,
        dst_ip: str = "",
        dst_port: int = 0,
        src_port: int = 0,
    ) -> None:
        """Enrich only an identified TLS connection, never other client flows."""
        if not (dst_ip and dst_port and src_port):
            return
        flow = self.get_flow(client_ip, dst_ip, dst_port, "tcp", src_port)
        if flow is not None:
            flow.sni = sni
            flow.tls_seen = True
            flow.tls_handshake_ms = handshake_ms
            flow.alpn_h2 = alpn_h2
            flow.cert_self_signed_suspect = cert_self_signed

    def cleanup_old_flows(self, force: bool = False) -> int:
        """Remove expired flows"""
        now = time.time()

        # Only cleanup every 60 seconds unless forced
        if not force and (now - self.last_cleanup) < 60:
            return 0

        self.last_cleanup = now
        expired_keys = []

        for key, flow in self.flows.items():
            if (now - flow.last_seen) > self.flow_timeout:
                expired_keys.append(key)

        for key in expired_keys:
            del self.flows[key]

        return len(expired_keys)

    def get_all_active_flows(self) -> list[FlowStats]:
        """Get all active flows"""
        return list(self.flows.values())

    def get_unique_dst_ports(self, client_ip: str) -> set[int]:
        """Get unique destination ports contacted by a client IP."""
        return {
            flow.dst_port
            for flow in self.flows.values()
            if flow.client_ip == client_ip
        }

    def detect_port_scan(
        self, client_ip: str, threshold: int = 15
    ) -> tuple[bool, int]:
        """Detect port scanning: many unique dst ports from single source.

        Returns (is_scanning, unique_port_count).
        """
        ports = self.get_unique_dst_ports(client_ip)
        return len(ports) >= threshold, len(ports)


def parse_conntrack_line(line: str, *, observed_at: Optional[float] = None) -> Optional[ConntrackFlow]:
    """Parse procfs or conntrack -L TCP/UDP original and reply counters."""
    try:
        parts = line.split()
        if not parts:
            return None
        proto = parts[2] if parts[0] in {"ipv4", "ipv6"} else parts[0]
        if proto not in {"tcp", "udp"}:
            return None
        directions = []
        for part in parts:
            if part.startswith("src="):
                directions.append({})
            if directions and "=" in part:
                key, value = part.split("=", 1)
                directions[-1].setdefault(key, value)
        if not directions:
            return None
        original = directions[0]
        reply = directions[1] if len(directions) > 1 else {}
        client_ip = str(ipaddress.ip_address(original["src"]))
        dst_ip = str(ipaddress.ip_address(original["dst"]))
        src_port, dst_port = int(original["sport"]), int(original["dport"])
        if not (0 < src_port <= 65535 and 0 < dst_port <= 65535):
            return None
        counters = [int(fields[key]) if key in fields else None
                    for fields in (original, reply) for key in ("packets", "bytes")]
        if any(value is not None and value < 0 for value in counters):
            return None
        return ConntrackFlow(client_ip, dst_ip, dst_port, proto, src_port, *counters,
                             observed_at=time.monotonic() if observed_at is None else observed_at)
    except (IndexError, KeyError, ValueError):
        return None


def _stream_conntrack_via_cli(poll_interval: float = 5.0) -> Iterator[tuple]:
    """
    Stream conntrack flows via the `conntrack -L` CLI tool.
    Used as a fallback when /proc/net/nf_conntrack is unavailable
    (e.g. Ubuntu 24.04 kernel 6.8 with CONFIG_NF_CONNTRACK_PROCFS=not set).
    Output format is identical to the procfs format — parse_conntrack_line() works unchanged.
    """
    while True:
        try:
            result = subprocess.run(
                ["conntrack", "-L", "-o", "extended"],
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            snapshot_at = time.monotonic()
            for line in result.stdout.splitlines():
                parsed = parse_conntrack_line(line.strip(), observed_at=snapshot_at)
                if parsed:
                    yield parsed
        except FileNotFoundError:
            logging.warning(
                "[FLOW] conntrack CLI not found — install with: apt install conntrack"
            )
            time.sleep(poll_interval)
        except subprocess.TimeoutExpired:
            logging.warning("[FLOW] conntrack -L timed out")
            time.sleep(poll_interval)
        except Exception:
            logging.exception("[FLOW] conntrack CLI error")
            time.sleep(poll_interval)
        else:
            time.sleep(poll_interval)


def stream_conntrack_flows(
    conntrack_path: str = "/proc/net/nf_conntrack",
) -> Iterator[tuple]:
    """
    Stream flows from conntrack.
    Prefers reading /proc/net/nf_conntrack directly; falls back to the
    `conntrack -L` CLI when the procfs path is absent (kernel 6.8+).
    Yields ConntrackFlow observations; repeated snapshots are not packets.
    """
    p = Path(conntrack_path)

    if not p.exists():
        logging.info(
            "[FLOW] %s not found — falling back to conntrack CLI", conntrack_path
        )
        yield from _stream_conntrack_via_cli()
        return

    while True:
        try:
            with p.open("r") as f:
                lines = f.readlines()
            snapshot_at = time.monotonic()
            for line in lines:
                parsed = parse_conntrack_line(line.strip(), observed_at=snapshot_at)
                if parsed:
                    yield parsed
            time.sleep(5)
        except Exception:
            logging.exception("[FLOW] Conntrack procfs read failed; retrying independently")
            time.sleep(5)
            continue


def build_feature_vector_24(flow: FlowStats, tracker: "FlowTracker | None" = None) -> list[float]:
    """
    Build 24-feature vector from FlowStats for MLP input.
    Order matches MLP schema v1 from the document.

    Args:
        flow: FlowStats instance for the connection being scored.
        tracker: Optional FlowTracker — required to populate domain_repeat_5min.
    """
    if not flow.packet_timing_available or flow.packet_metadata_only:
        raise ValueError("24-feature MLP requires packet timing/size data unavailable from conntrack snapshots")

    # Basic flow (8)
    duration_sec = flow.get_duration()
    pkt_count_total = float(flow.pkt_count)
    bytes_total = float(flow.get_total_bytes())
    bytes_per_sec = flow.get_bytes_per_sec()
    pkts_per_sec = flow.get_pkts_per_sec()
    avg_pkt_size = flow.get_avg_pkt_size()
    pkt_size_std = flow.get_pkt_size_std()
    inbound_outbound_ratio = flow.get_inbound_outbound_ratio()

    # Burst & periodicity (6)
    max_burst_pkts_1s = float(flow.get_max_burst_pkts_1s())
    max_burst_bytes_1s = float(flow.get_max_burst_bytes_1s())
    interarrival_mean_ms = flow.get_interarrival_mean_ms()
    interarrival_std_ms = flow.get_interarrival_std_ms()
    interarrival_p95_ms = flow.get_interarrival_p95_ms()
    small_pkt_ratio = flow.get_small_pkt_ratio()

    # TLS (6) — populated from Zeek ssl.log enrichment when Zeek is active
    tls_seen = 1.0 if flow.tls_seen else 0.0
    tls_handshake_time_ms = flow.tls_handshake_ms
    ja3_hash_bucket = 0.0  # Reserved — requires JA3 library
    sni_len = float(len(flow.sni)) if flow.sni else 0.0
    alpn_h2 = flow.alpn_h2
    cert_self_signed_suspect = flow.cert_self_signed_suspect

    # DNS / domain behavior (4)
    dns_seen = 1.0 if flow.domain else 0.0
    fqdn_len = float(len(flow.domain)) if flow.domain else 0.0
    subdomain_depth = float(flow.domain.count(".") - 1) if flow.domain else 0.0
    domain_repeat_5min = tracker.get_domain_repeat(flow.domain) if tracker else 0.0

    return [
        # Basic flow (8)
        duration_sec,
        pkt_count_total,
        bytes_total,
        bytes_per_sec,
        pkts_per_sec,
        avg_pkt_size,
        pkt_size_std,
        inbound_outbound_ratio,
        # Burst & periodicity (6)
        max_burst_pkts_1s,
        max_burst_bytes_1s,
        interarrival_mean_ms,
        interarrival_std_ms,
        interarrival_p95_ms,
        small_pkt_ratio,
        # TLS (6)
        tls_seen,
        tls_handshake_time_ms,
        ja3_hash_bucket,
        sni_len,
        alpn_h2,
        cert_self_signed_suspect,
        # DNS / domain behavior (4)
        dns_seen,
        fqdn_len,
        subdomain_depth,
        domain_repeat_5min,
    ]


def build_packet_features_14(flow: FlowStats) -> list[float]:
    """Measured capture statistics only; no fabricated TLS/DNS metadata."""
    if not flow.packet_timing_available or not flow.packet_metadata_only or flow.last_seen <= flow.first_seen:
        raise ValueError("packet14 requires real packet observations over a positive measured interval")
    return [flow.get_duration(), float(flow.pkt_count), float(flow.get_total_bytes()),
            flow.get_bytes_per_sec(), flow.get_pkts_per_sec(), flow.get_avg_pkt_size(),
            flow.get_pkt_size_std(), flow.get_inbound_outbound_ratio(),
            float(flow.get_max_burst_pkts_1s()), float(flow.get_max_burst_bytes_1s()),
            flow.get_interarrival_mean_ms(), flow.get_interarrival_std_ms(),
            flow.get_interarrival_p95_ms(), flow.get_small_pkt_ratio()]
