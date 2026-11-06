from __future__ import annotations
import os
import signal
import sys
import time
import uuid

import json
import logging
import subprocess
import ipaddress
from pathlib import Path
from typing import Any

from minifw_ai.policy import Policy
from minifw_ai.feeds import FeedMatcher
from minifw_ai.netutil import ip_in_any_subnet, ASNResolver
from minifw_ai.events import Event, EventWriter, now_iso
from minifw_ai.enforce import ipset_create, ipset_add, nft_apply_forward_drop
from minifw_ai.collector_dnsmasq import stream_dns_events_file
from minifw_ai.collector_runtime import stream_collector_events
from minifw_ai.collector_zeek import stream_zeek_sni_events
from minifw_ai.collector_packets import stream_packet_events, observe_packet, protocol_policy
from minifw_ai.burst import BurstTracker
from minifw_ai.client_window import (
    DEFAULT_BLOCK_TIMEOUT, ClientWindow, enforcement_approved, load_model, may_isolate,
)
from minifw_ai.audit import (
    audit_daemon_start, audit_daemon_stop, audit_config_loaded,
    audit_firewall_init, audit_firewall_init_failed,
    audit_state_transition, audit_ip_block,
)

# NEW: Import flow collector
from minifw_ai.collector_flow import (
    FlowTracker,
    build_feature_vector_24,
    build_packet_features_14,
    stream_conntrack_flows,
)

# NEW: Import state manager for dynamic state transitions (TODO 4.1/4.2)
from minifw_ai.state_manager import StateManager, ProtectionState

# DNS tunneling detection
from minifw_ai.dns_tunnel_detect import analyze_domain_tunneling, TunnelTracker

# NEW: Import MLP engine
try:
    from minifw_ai.utils.mlp_engine import get_mlp_detector

    MLP_AVAILABLE = True
except Exception:
    MLP_AVAILABLE = False
    get_mlp_detector = None

# NEW: Import YARA scanner
try:
    from minifw_ai.utils.yara_scanner import get_yara_scanner

    YARA_AVAILABLE = True
except Exception:
    YARA_AVAILABLE = False
    get_yara_scanner = None

# NEW: Import Prometheus metrics
try:
    from prometheus.metrics import (
        start_metrics_server,
        update_metrics,
        active_blocks,
    )
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False
    start_metrics_server = None
    update_metrics = None

# NEW: Import Sector Lock system
try:
    from minifw_ai.sector_lock import get_sector_lock, get_sector_config
    from minifw_ai.sector_config import get_threshold_adjustment, is_iomt_priority
    from minifw_ai.sector_rules import evaluate_sector, decide_sector_action

    SECTOR_LOCK_AVAILABLE = True
except ImportError:
    SECTOR_LOCK_AVAILABLE = False
    get_sector_lock = None
    evaluate_sector = None
    decide_sector_action = None


def segment_for_ip(ip: str, mapping: dict[str, list[str]]) -> str:
    address = ipaddress.ip_address(ip)
    best_segment, best_prefix = "default", -1
    for seg, cidrs in mapping.items():
        for cidr in cidrs:
            network = ipaddress.ip_network(cidr, strict=False)
            if address in network and network.prefixlen > best_prefix:
                best_segment, best_prefix = seg, network.prefixlen
    return best_segment


def _safe_int_cast(value: Any, default: int) -> int:
    """Safely cast a value to int, returning default on failure."""
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _env_flag(name: str, default: bool = True) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def score_and_decide(
    domain: str,
    denied: bool,
    sni_denied: bool,
    asn_denied: bool,
    burst_hit: int,
    weights: dict,
    thresholds,
    mlp_score: int = 0,
    yara_score: int = 0,
    hard_threat_override: bool = False,
    hard_threat_reason: str | None = None,
    pre_reasons: list[str] | None = None,
    ip_denied: bool = False,
    tunnel_score: int = 0,
    deny_domain_immediate: bool = False,
):
    score = 0
    reasons = list(pre_reasons) if pre_reasons else []

    if deny_domain_immediate and (denied or sni_denied):
        reasons.append("dns_denied_domain" if denied else "tls_sni_denied_domain")
        reasons.append("deny_domain_client_ipv4_isolation")
        return 100, reasons, "block"

    # CRITICAL: Hard threat override bypasses normal scoring
    if hard_threat_override:
        if hard_threat_reason:
            reasons.append(hard_threat_reason)
        reasons.append("hard_threat_gate_override")
        return 100, reasons, "block"

    if denied:
        score += _safe_int_cast(weights.get("dns_weight"), 40)
        reasons.append("dns_denied_domain")
    if sni_denied:
        score += _safe_int_cast(weights.get("sni_weight"), 35)
        reasons.append("tls_sni_denied_domain")
    if asn_denied:
        score += _safe_int_cast(weights.get("asn_weight"), 15)
        reasons.append("asn_denied")
    if ip_denied:
        score += _safe_int_cast(weights.get("ip_denied_weight"), 15)
        reasons.append("ip_denied_tor_anonymizer")
    if burst_hit:
        score += int(weights.get("burst_weight", 10))
        reasons.append("burst_behavior")

    # DNS tunneling score (direct add, not weighted — tunneling is inherently suspicious)
    if tunnel_score > 0:
        score += tunnel_score
        # Reasons already added via pre_reasons from tunnel analysis

    # NEW: Add MLP score (weight configurable, default 30)
    if mlp_score > 0:
        mlp_weight = int(weights.get("mlp_weight", 30))
        score += mlp_score * mlp_weight // 100  # mlp_score is 0-100
        reasons.append(f"mlp_threat_score_{mlp_score}")

    # NEW: Add YARA score (weight configurable, default 35)
    if yara_score > 0:
        yara_weight = int(weights.get("yara_weight", 35))
        score += yara_score * yara_weight // 100  # yara_score is 0-100
        reasons.append(f"yara_match_score_{yara_score}")

    score = max(0, min(100, score))

    block_thr = _safe_int_cast(thresholds.block_threshold, 90)
    monitor_thr = _safe_int_cast(thresholds.monitor_threshold, 60)

    if score >= block_thr:
        return score, reasons, "block"
    if score >= monitor_thr:
        return score, reasons, "monitor"
    return score, reasons, "allow"


def _build_sector_flow(
    client_ip: str,
    domain: str,
    flows: list,
    connection_count: int,
) -> dict:
    import datetime
    flow_for_sector: dict = {
        "src_ip": client_ip,
        "dst_host": domain,
        "hour": datetime.datetime.now().hour,
        "burst_conn_count": connection_count,
    }
    if flows:
        latest = flows[-1]
        flow_for_sector.update({
            "dst_ip": getattr(latest, "dst_ip", None),
            "dst_port": getattr(latest, "dst_port", None),
            "bytes_out": getattr(latest, "bytes_sent", 0),
            "bytes_in": getattr(latest, "bytes_recv", 0),
            "tls_used": getattr(latest, "tls_seen", False),
            "sni_present": bool(getattr(latest, "sni", "")),
            "pkt_count": getattr(latest, "pkt_count", 0),
        })
        iat = getattr(latest, "interarrival_times", [])
        if len(iat) >= 10:
            import statistics
            try:
                flow_for_sector["interarrival_std_ms"] = statistics.stdev(iat)
            except statistics.StatisticsError:
                pass
    return flow_for_sector


def evaluate_hard_threat(
    flows: list,
    port_scan_detected: bool = False,
) -> tuple[bool, str | None]:
    # Connection volume alone cannot distinguish ordinary HTTP from an attack.
    # Rule 0: Port scan detection (many unique dst ports)
    if port_scan_detected:
        return True, "port_scan"

    for flow in flows:
        if flow.pkt_count < 5:
            continue
        # Per-second packet gates need a complete measurement interval, not a partial TLS burst.
        if getattr(flow, "packet_metadata_only", False) and flow.get_duration() < 1.0:
            continue

        # Rule 1: PPS Saturation (>200 packets/sec)
        if flow.pkts_per_sec > 200:
            return True, "pps_saturation"

        # Rule 2: Burst Flood (>300 packets in 1 second)
        if flow.packet_timing_available and flow.max_burst_pkts_1s > 300:
            return True, "burst_flood"

        # Rule 3: Bot-like Small Packets (>95% small packets + short duration)
        if flow.packet_timing_available and flow.small_pkt_ratio > 0.95 and flow.duration < 3:
            return True, "bot_like_small_packets"

        # Rule 4: Extreme Interarrival Regularity (std < 5ms with high PPS)
        if (
            flow.packet_timing_available
            and flow.interarrival_std_ms < 5
            and flow.pkts_per_sec > 100
        ):
            return True, "bot_regular_timing"

    return False, None


def init_mlp_detector(ai_enabled: bool) -> tuple[Any, bool]:
    if not ai_enabled:
        return None, False
    if not MLP_AVAILABLE:
        logging.warning("[MLP] MLP engine not available (install scikit-learn)")
        return None, False

    mlp_model_path = os.environ.get("MINIFW_MLP_MODEL")
    mlp_threshold = float(os.environ.get("MINIFW_MLP_THRESHOLD", "0.5"))

    if mlp_model_path and Path(mlp_model_path).exists():
        try:
            mlp_detector = get_mlp_detector(
                model_path=mlp_model_path, threshold=mlp_threshold
            )
            if mlp_detector.model_loaded:
                logging.info(f"[MLP] Loaded model from: {mlp_model_path}")
                logging.info(f"[MLP] Threshold: {mlp_threshold}")
                return mlp_detector, True
        except Exception as e:
            logging.warning(f"[MLP] Failed to load model: {e}")
    else:
        logging.info(
            "[MLP] No model configured (set MINIFW_MLP_MODEL environment variable)"
        )

    return None, False


def init_yara_scanner(ai_enabled: bool) -> tuple[Any, bool]:
    if not ai_enabled:
        return None, False
    if not YARA_AVAILABLE:
        logging.warning("[YARA] YARA scanner not available (install yara-python)")
        return None, False

    yara_rules_dir = os.environ.get("MINIFW_YARA_RULES")
    if yara_rules_dir and Path(yara_rules_dir).exists():
        try:
            yara_scanner = get_yara_scanner(rules_dir=yara_rules_dir)
            if yara_scanner.rules_loaded:
                stats = yara_scanner.get_stats()
                logging.info(f"[YARA] Loaded rules from: {yara_rules_dir}")
                logging.info(f"[YARA] Rules loaded: {stats['rules_loaded']}")
                return yara_scanner, True
        except Exception as e:
            logging.warning(f"[YARA] Failed to load rules: {e}")
    else:
        logging.info(
            "[YARA] No rules configured (set MINIFW_YARA_RULES environment variable)"
        )

    return None, False


def _resolve_decision_owner(reasons: list[str]) -> str:
    # First: an AI block can land on an event already carrying monitor-level protocol/MLP/YARA reasons.
    if "ai_window_rate" in reasons:
        return "AI Engine (client window)"
    if any(reason.startswith(("tls_version_below_minimum:", "vpn_tunnel:")) for reason in reasons):
        return "Protocol Policy"
    if any(reason.startswith("hard_threat_gate") for reason in reasons):
        return "Hard Gate"
    if any(reason == "mlp_threat_score" or reason.startswith("mlp_threat_score_") for reason in reasons):
        return "AI Engine (MLP)"
    if any(reason.startswith(("yara_", "yara_match")) for reason in reasons):
        return "YARA Scanner"
    return "Policy Engine"


def _ip_in_subnets(ip: str, subnets: list[str]) -> bool:
    """Return True if ip falls within any of the given CIDR subnets."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(s, strict=False) for s in subnets)
    except (ValueError, TypeError):
        return False


def run():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )

    # Register SIGTERM handler so audit_daemon_stop fires on systemctl stop
    def _handle_sigterm(signum, frame):
        logging.info("Caught SIGTERM, shutting down.")
        audit_daemon_stop("sigterm")
        sys.exit(0)

    signal.signal(signal.SIGTERM, _handle_sigterm)

    # Start Prometheus metrics server if available
    if METRICS_AVAILABLE:
        metrics_port = _safe_int_cast(os.environ.get("PROMETHEUS_PORT"), 9090)
        start_metrics_server(metrics_port)

    policy_path = os.environ.get("MINIFW_POLICY", "/opt/minifw_ai/config/policy.json")
    feeds_dir = os.environ.get("MINIFW_FEEDS", "/opt/minifw_ai/config/feeds")
    log_path = os.environ.get("MINIFW_LOG", "/opt/minifw_ai/logs/events.jsonl")

    # NEW: Flow records output path
    flow_records_path = os.environ.get(
        "MINIFW_FLOW_RECORDS", "/opt/minifw_ai/logs/flow_records.jsonl"
    )

    pol = Policy(policy_path)
    feeds = FeedMatcher(feeds_dir)
    writer = EventWriter(log_path)
    audit_config_loaded(policy_path, feeds_dir)

    # Initialize ASN resolver for IP-to-ASN lookup
    asn_resolver = ASNResolver()
    asn_prefixes_path = os.environ.get(
        "MINIFW_ASN_PREFIXES", str(Path(feeds_dir) / "asn_prefixes.txt")
    )
    asn_resolver.load(asn_prefixes_path)

    # Determine initial protection state from environment
    _initial_ai = _env_flag("AI_ENABLED", True)
    _initial_degraded = os.environ.get("DEGRADED_MODE", "0") == "1"
    if _initial_degraded or not _initial_ai:
        _initial_state = ProtectionState.BASELINE_PROTECTION
    else:
        _initial_state = ProtectionState.AI_ENHANCED_PROTECTION

    state_manager = StateManager(initial_state=_initial_state)
    logging.info(
        f"[STATE] Initial protection state: {state_manager.get_current_state().value}"
    )

    # NEW: Initialize Sector Lock (Factory-Set Configuration)
    sector_lock = None
    sector_config = {}
    sector_name = "unknown"
    iomt_subnets = []  # For hospital sector

    if SECTOR_LOCK_AVAILABLE:
        try:
            sector_lock = get_sector_lock()
            sector_config = sector_lock.get_sector_config()
            sector_name = sector_lock.get_sector()

            logging.info(f"[SECTOR_LOCK] Device sector: {sector_name} (LOCKED)")
            logging.info(
                f"[SECTOR_LOCK] Config: {sector_config.get('description', 'N/A')}"
            )

            # Load sector-specific feeds
            extra_feeds = sector_config.get("extra_feeds", [])
            if extra_feeds:
                loaded = feeds.load_sector_feeds(extra_feeds)
                logging.info(
                    f"[SECTOR_LOCK] Loaded {loaded} sector-specific feed patterns"
                )

            # Finance sector: Load Tor exit node IPs when block_tor or block_anonymizers is enabled
            if sector_config.get("block_tor") or sector_config.get("block_anonymizers"):
                tor_path = os.environ.get(
                    "MINIFW_TOR_EXITS",
                    str(Path(feeds_dir) / "tor_exit_nodes.txt"),
                )
                tor_count = feeds.load_tor_exits(tor_path)
                logging.info(
                    f"[SECTOR_LOCK] Tor/anonymizer blocking enabled: loaded {tor_count} exit IPs"
                )

            # Education sector: SafeSearch domain protection
            if sector_config.get("force_safesearch"):
                safesearch_domains = sector_config.get("safesearch_domains", [])
                # Protect bare domain AND all subdomains (fnmatch: *.google.com covers www.google.com, etc.)
                protected = []
                for d in safesearch_domains:
                    protected.append(d)
                    if not d.startswith("*."):
                        protected.append(f"*.{d}")
                feeds.allow_domains.extend(protected)
                logging.info(
                    f"[SECTOR_LOCK] Search-domain allowlist: {len(protected)} patterns; restricted search requires the generated dnsmasq overrides"
                )

            # Education sector: VPN/proxy blocking confirmation
            if sector_config.get("block_vpns") or sector_config.get("block_proxies"):
                logging.info(
                    "[SECTOR_LOCK] VPN/proxy provider domain matching enabled; optional packet metadata detects WireGuard patterns"
                )

            # Get IoMT subnets for hospital sector (from policy.json, not hardcoded)
            if sector_lock.is_hospital():
                iomt_subnets = pol.cfg.get("iomt_subnets", [])
                if iomt_subnets:
                    logging.info(
                        f"[SECTOR_LOCK] Hospital mode: IoMT subnets = {iomt_subnets}"
                    )
                else:
                    logging.warning(
                        "[SECTOR_LOCK] Hospital mode but no iomt_subnets in policy.json"
                    )

        except RuntimeError as e:
            logging.critical(f"[SECTOR_LOCK] FATAL: {e}")
            logging.critical(
                "[SECTOR_LOCK] Device cannot start without valid sector config"
            )
            return
        except Exception as e:
            logging.error(
                f"[SECTOR_LOCK] Warning: {e} - continuing without sector lock"
            )
    else:
        logging.warning("[SECTOR_LOCK] Sector lock module not available")

    # NEW: Initialize flow tracker with LRU capping
    max_flows = _safe_int_cast(os.environ.get("MINIFW_MAX_FLOWS"), 20000)
    flow_tracker = FlowTracker(flow_timeout=300, max_flows=max_flows)

    # NEW: Initialize AI modules (Layer 2) with graceful degradation
    mlp_detector, mlp_enabled = init_mlp_detector(state_manager.is_ai_enabled())
    yara_scanner, yara_enabled = init_yara_scanner(state_manager.is_ai_enabled())

    # NEW: Create flow records writer
    flow_records_file = Path(flow_records_path)
    flow_records_file.parent.mkdir(parents=True, exist_ok=True)

    enf = pol.enforcement()
    set_name = enf.get("ipset_name_v4", "minifw_block_v4")
    timeout = _safe_int_cast(enf.get("ip_timeout_seconds"), 86400)
    table = enf.get("nft_table", "inet")
    table_name = enf.get("nft_table_name", "minifw")
    chain = enf.get("nft_chain", "forward")

    if os.environ.get("DEMO_MODE", "0") == "1":
        logging.info("[DEMO_MODE] Skipping nftables/ipset init (no root required in demo)")
        audit_firewall_init(set_name, f"{table} {table_name} [DEMO_MODE - skipped]")
    else:
        try:
            ipset_create(set_name, timeout, family=table, table_name=table_name)
            nft_apply_forward_drop(set_name, table=table, table_name=table_name, chain=chain)
            audit_firewall_init(set_name, f"{table} {table_name}")
        except (ValueError, subprocess.CalledProcessError) as e:
            logging.critical(
                f"FATAL: Could not initialize firewall rules. Exiting. Error: {e}"
            )
            audit_firewall_init_failed(str(e))
            raise SystemExit(1)

    burst_cfg = pol.burst()
    monitor_qpm = _safe_int_cast(burst_cfg.get("dns_queries_per_minute_monitor"), 120)
    block_qpm = _safe_int_cast(burst_cfg.get("dns_queries_per_minute_block"), 240)
    burst = BurstTracker(window_seconds=60)
    tunnel_tracker = TunnelTracker(window_seconds=300)
    port_scan_threshold = _safe_int_cast(os.environ.get("MINIFW_PORT_SCAN_THRESHOLD"), 15)
    tunnel_subdomain_threshold = _safe_int_cast(
        os.environ.get("MINIFW_TUNNEL_SUBDOMAIN_THRESHOLD"), 20
    )

    seg_map = pol.segment_subnets()
    weights = pol.features()
    col = pol.collectors()
    dns_log = col.get("dnsmasq_log_path", "/var/log/dnsmasq.log")
    zeek_ssl = col.get("zeek_ssl_log_path", "/var/log/zeek/ssl.log")
    use_zeek = bool(col.get("use_zeek_sni", False))

    sources = {}
    packet_interface = os.environ.get("MINIFW_PACKET_INTERFACE", col.get("packet_interface", ""))
    if use_zeek and not packet_interface:
        sources["zeek"] = lambda: stream_zeek_sni_events(zeek_ssl)
    conntrack_path = os.environ.get("MINIFW_CONNTRACK_PATH", "/proc/net/nf_conntrack")
    client_subnets = [ipaddress.ip_network(cidr, strict=False) for cidrs in seg_map.values() for cidr in cidrs]
    controls = pol.cfg.get("protocol_controls", {})
    if controls and not packet_interface:
        logging.warning("[PROTOCOL] TLS version/WireGuard metadata unavailable without MINIFW_PACKET_INTERFACE")
    if packet_interface:
        sources["packet"] = lambda: stream_packet_events(packet_interface)
    elif os.environ.get("MINIFW_DISABLE_FLOWS", "0") != "1":
        sources["flow"] = lambda: stream_conntrack_flows(conntrack_path)
    flow_freq_window = _safe_int_cast(os.environ.get("MINIFW_FLOW_FREQ_WINDOW_SEC"), 60)
    flow_freq_tracker = BurstTracker(window_seconds=flow_freq_window, max_size=20000)
    if packet_interface:
        logging.info("[TELEMETRY] Packet metadata on %s; packet14 model required; no TLS decryption", packet_interface)
    else:
        logging.warning("[TELEMETRY] Conntrack provides counter deltas, not packet timing/size distributions; 24-feature MLP disabled for these observations")

    dns_source = os.environ.get("MINIFW_DNS_SOURCE", "file")
    if dns_source == "none" or _initial_degraded:
        logging.warning("[DNS] Disabled; flow decisions continue independently")
    elif dns_source == "journald":
        from minifw_ai.collector_journald import stream_dns_events_journald
        unit = os.environ.get("MINIFW_JOURNALD_UNIT", "systemd-resolved")
        sources["dns"] = lambda: stream_dns_events_journald(unit=unit)
    elif dns_source == "udp":
        from minifw_ai.collector_dnsmasq import stream_dns_events_udp
        dns_port = int(os.environ.get("MINIFW_DNS_UDP_PORT", "5514"))
        sources["dns"] = lambda: stream_dns_events_udp(port=dns_port)
    else:
        sources["dns"] = lambda: stream_dns_events_file(dns_log)

    flow_export_counter = 0
    flow_export_interval = 100
    guard_interface = os.environ.get("MINIFW_EGRESS_GUARD_INTERFACE", "")
    if guard_interface:
        from minifw_ai.egress_guard import DEFAULT_DOH_LIST, apply as apply_egress_guard, load_doh_list
        # Empty MINIFW_EGRESS_DOH_LIST disables the DoH address list; a missing configured file fails startup.
        doh_path = os.environ.get("MINIFW_EGRESS_DOH_LIST", DEFAULT_DOH_LIST)
        apply_egress_guard(guard_interface, _env_flag("MINIFW_EGRESS_BLOCK_IPV6", False),
                           load_doh_list(doh_path) if doh_path else ())
    audit_daemon_start(sector_name, state_manager.get_current_state().value)

    from minifw_ai.runtime_health import RuntimeHealth
    health = RuntimeHealth(os.environ.get("MINIFW_HEALTH_FILE", str(Path(log_path).with_name("runtime-health.json"))),
                           sources, table_name, chain, set_name)
    # Client-window AI: may isolate on its own only for fast password guessing (see client_window.py).
    window_model = load_model()
    ai_cfg = pol.cfg.get("ai_enforcement", {}) or {}
    ai_timeout = _safe_int_cast(ai_cfg.get("block_timeout_seconds"), DEFAULT_BLOCK_TIMEOUT)
    # The first conntrack snapshot after a (re)start, e.g. Save->Apply, reports every open connection as new.
    ai_window = ClientWindow(ignore_before=time.time() + 10)
    for source, observation in stream_collector_events(sources):
        health.observe("tick")
        client_ip, domain, flow_for_event, new_flow = None, "", None, None
        if source == "dns":
            client_ip, domain = observation
            if client_ip is not None and domain is not None:
                state_manager.record_dns_event(client_ip, domain)
                flow_tracker.enrich_with_dns(client_ip, domain)
        elif source == "flow":
            flow_for_event, is_new = flow_tracker.observe_conntrack(observation)
            client_ip = observation.client_ip
            if is_new:
                flow_freq_tracker.add(client_ip)
                new_flow = flow_for_event
        elif source == "packet":
            flow_for_event, is_new = observe_packet(flow_tracker, observation, client_subnets)
            if flow_for_event is not None:
                state_manager.record_packet_event()
                client_ip = flow_for_event.client_ip
                if is_new:
                    flow_freq_tracker.add(client_ip)
                    new_flow = flow_for_event
        elif source == "zeek":
            evt = observation
            if evt.dst_ip and evt.dst_port and evt.src_port:
                client_ip = evt.client_ip
                existing = flow_tracker.get_flow(client_ip, evt.dst_ip, evt.dst_port, "tcp", evt.src_port)
                flow_for_event = flow_tracker.update_flow(client_ip, evt.dst_ip, evt.dst_port, "tcp", src_port=evt.src_port)
                if existing is None:
                    flow_for_event.packet_timing_available = False
                if existing is None:
                    flow_freq_tracker.add(client_ip)
                    new_flow = flow_for_event
                flow_tracker.enrich_with_sni(client_ip, evt.sni, evt.handshake_ms,
                    evt.alpn_h2, evt.cert_self_signed, dst_ip=evt.dst_ip,
                    dst_port=evt.dst_port, src_port=evt.src_port)
        elif source == "tick":
            flow_tracker.cleanup_old_flows()

        # Dynamic state transition check (TODO 4.1/4.2)
        state_changed, new_state, transition_reason = (
            state_manager.check_and_transition()
        )
        if state_changed:
            _ai_on = state_manager.is_ai_enabled()
            mlp_detector, mlp_enabled = init_mlp_detector(_ai_on)
            yara_scanner, yara_enabled = init_yara_scanner(_ai_on)
            logging.warning(
                f"[STATE_TRANSITION] {new_state.value} | MLP={mlp_enabled} YARA={yara_enabled} | {transition_reason}"
            )
            old = (ProtectionState.BASELINE_PROTECTION if new_state == ProtectionState.AI_ENHANCED_PROTECTION
                   else ProtectionState.AI_ENHANCED_PROTECTION)
            audit_state_transition(old.value, new_state.value, transition_reason)

        if client_ip is None:
            continue
        if domain is None:
            domain = ""

        mlp_score = 0
        mlp_proba = 0.0
        mlp_ran = False
        yara_score = 0
        yara_matches = []
        hard_threat = False
        hard_threat_reason = None
        score = 0
        action = "allow"
        reasons = []
        window_features = None
        ai_window_probability = None
        ai_window_mode = "not_run"
        try:
            # Count each new TCP connection once, in any protection state so the window is warm when AI turns on.
            # TCP only: per-query UDP 5-tuples (DNS to the gateway resolver) would reach 30+/min in normal use.
            if new_flow is not None and new_flow.proto == "tcp":
                window_features = ai_window.add(client_ip, new_flow.dst_ip, new_flow.dst_port, new_flow.first_seen)
            segment = segment_for_ip(client_ip, seg_map)
            thr = pol.thresholds(segment)

            # NEW: Apply sector-specific threshold adjustments
            if sector_config:
                block_adj = sector_config.get("block_threshold_adjustment", 0)
                monitor_adj = sector_config.get("monitor_threshold_adjustment", 0)
                if block_adj or monitor_adj:
                    # Create adjusted thresholds
                    from minifw_ai.policy import SegmentThreshold

                    thr = SegmentThreshold(
                        max(10, thr.block_threshold + block_adj),
                        max(10, thr.monitor_threshold + monitor_adj),
                    )

            if feeds.domain_allowed(domain):
                denied = False
            else:
                denied = feeds.domain_denied(domain)

            sni = flow_for_event.sni if flow_for_event is not None else ""
            sni_denied = bool(
                sni and (not feeds.domain_allowed(sni)) and feeds.domain_denied(sni)
            )

            destination_ip = flow_for_event.dst_ip if flow_for_event is not None else ""
            destination_asn = asn_resolver.lookup(destination_ip) if destination_ip and asn_resolver.loaded else None
            asn_denied = bool(destination_asn and feeds.asn_denied(destination_asn))
            destination_ip_denied = bool(destination_ip and feeds.ip_denied(destination_ip))

            qpm = burst.add(client_ip) if source == "dns" else burst.get_rate(client_ip)
            burst_hit = int(qpm >= monitor_qpm or qpm >= block_qpm)

            # Port scan detection
            port_scan_hit, port_count = flow_tracker.detect_port_scan(
                client_ip, threshold=port_scan_threshold
            )

            # Layer 1: Hard threat gates (mandatory)
            flows_for_client = flow_tracker.get_flows_for_client(client_ip)
            flow_freq = flow_freq_tracker.get_rate(client_ip)
            hard_threat, hard_threat_reason = evaluate_hard_threat(
                flows_for_client,
                port_scan_detected=port_scan_hit,
            )
            if hard_threat:
                logging.warning(
                    f"[HARD_GATE] Triggered: {client_ip} - {hard_threat_reason}"
                )

            # DNS tunneling detection
            tunnel_score, tunnel_reasons = analyze_domain_tunneling(domain)
            is_sustained_tunnel, tunnel_unique = tunnel_tracker.check_sustained_tunneling(
                domain, threshold=tunnel_subdomain_threshold
            )
            if is_sustained_tunnel:
                tunnel_score = min(tunnel_score + 40, 100)
                tunnel_reasons.append(f"dns_tunnel_sustained_{tunnel_unique}_subdomains")
            if tunnel_score > 0:
                reasons.extend(tunnel_reasons)

            # Layer 2: AI risk amplifier (conditional)
            flow_for_ai = flow_for_event
            if (
                state_manager.is_ai_enabled()
                and mlp_enabled
                and mlp_detector
                and flow_for_ai
                and flow_for_ai.packet_timing_available
                and mlp_detector.can_infer(flow_for_ai)
                and flow_for_ai.pkt_count >= 5
            ):
                try:
                    previous_inferences = mlp_detector.total_inferences
                    is_threat, proba = mlp_detector.is_suspicious(
                        flow_for_ai, return_probability=True
                    )
                    mlp_proba = proba
                    mlp_ran = mlp_detector.total_inferences > previous_inferences
                    # The new synthetic packet model is evaluation-only until representative validation.
                    if is_threat and mlp_detector.feature_schema != "packet14-v1":
                        mlp_score = int(proba * 100)
                except Exception:
                    logging.warning(
                        "[MLP] Inference failed; continuing without MLP", exc_info=True
                    )

            if state_manager.is_ai_enabled() and yara_enabled and yara_scanner:
                try:
                    payload = f"{domain} {sni}".encode("utf-8")
                    matches = yara_scanner.scan_payload(payload, timeout=5)
                    if matches:
                        yara_matches = matches
                        severity_scores = {
                            "critical": 100,
                            "high": 75,
                            "medium": 50,
                            "low": 25,
                        }
                        max_severity_score = max(
                            severity_scores.get(m.get_severity(), 25) for m in matches
                        )
                        yara_score = max_severity_score
                        for match in matches[:3]:
                            reasons.append(f"yara_{match.rule}")
                except Exception:
                    logging.warning(
                        "[YARA] Scan failed; continuing without YARA", exc_info=True
                    )

            score, reasons, action = score_and_decide(
                domain,
                denied,
                sni_denied,
                asn_denied,
                burst_hit,
                weights,
                thr,
                mlp_score,
                yara_score,
                hard_threat_override=hard_threat,
                ip_denied=destination_ip_denied,
                hard_threat_reason=hard_threat_reason,
                pre_reasons=reasons,
                tunnel_score=tunnel_score,
                deny_domain_immediate=sector_name in {"finance", "education"},
            )

            if flow_for_event is not None:
                protocol_action, protocol_reasons = protocol_policy(flow_for_event, controls)
                if protocol_action:
                    reasons.extend(protocol_reasons)
                    if protocol_action == "block":
                        action, score = "block", 100
                    elif action == "allow":
                        action = "monitor"

            # Sector rules layer — runs after base scoring, can upgrade action
            if evaluate_sector and flow_for_event is not None and sector_name in {"finance", "government"}:
                _flow_s = _build_sector_flow(client_ip, domain, [flow_for_event], flow_freq)
                _flow_s["dst_asn"] = destination_asn
                _flow_s["is_internal"] = ip_in_any_subnet(destination_ip, [cidr for cidrs in seg_map.values() for cidr in cidrs])
                cfg = {"blocked_asns": feeds.deny_asn} if sector_name == "finance" else None
                _s_detections = evaluate_sector(sector_name, _flow_s, cfg)
                _s_decision = decide_sector_action(sector_name, _s_detections)
                if _s_decision and _s_decision["final_action"] == "block" and action != "block":
                    action = "block"
                    score = max(score, int(_s_decision["confidence"] * 100))
                    reasons.append(f"sector_rule:{_s_decision.get('trigger_type', 'sector_override')}")
                    reasons.append(_s_decision["reason"][:120])
                elif _s_decision and _s_decision["final_action"] in {"alert", "monitor"} and action == "allow":
                    action = "monitor"
                    reasons.append(f"sector_rule:{_s_decision.get('trigger_type', 'sector_alert')}")

            # AI-only decision: blocks only what the rules above left unblocked; without approval it is shadow scoring.
            if state_manager.is_ai_enabled() and window_model and window_features:
                try:
                    ai_window_probability = window_model.probability(window_features)
                    ai_window_mode = "enforcing" if enforcement_approved(window_model) else "shadow_only"
                    if action != "block" and may_isolate(window_model, ai_window_probability, segment, client_ip, ai_cfg):
                        action = "block"
                        score = max(score, int(ai_window_probability * 100))
                        reasons.append("ai_window_rate")
                except Exception:
                    logging.warning("[AI_WINDOW] Scoring failed; continuing without client-window AI", exc_info=True)

            if action == "block" and ipaddress.ip_address(client_ip).version != 4:
                action = "monitor"
                reasons.append("ipv6_enforcement_unsupported")
            if action == "block":
                block_timeout = ai_timeout if "ai_window_rate" in reasons else timeout
                added = ipset_add(set_name, client_ip, block_timeout, family=table, table_name=table_name,
                                  refresh=bool(denied or sni_denied))
                if added is False:
                    continue
                audit_ip_block(client_ip, score, reasons, domain, sector_name)

            # Hospital sector IoMT high-priority alerting
            event_severity = "info"
            if sector_lock and sector_lock.is_hospital() and iomt_subnets:
                if ip_in_any_subnet(client_ip, iomt_subnets):
                    if score >= thr.monitor_threshold:
                        event_severity = sector_config.get("alert_severity_boost", "info")
                        logging.critical(
                            f"[IOMT_ALERT] Medical device anomaly: {client_ip} -> {domain} "
                            f"(score={score}, severity={event_severity})"
                        )
                        # Add IoMT flag to reasons
                        if "iomt_device_alert" not in reasons:
                            reasons.append("iomt_device_alert")

            ev = Event(
                ts=now_iso(),
                segment=segment,
                client_ip=client_ip,
                domain=domain,
                action=action,
                score=score,
                reasons=reasons,
                sector=sector_name,
                severity=event_severity,
                trace_id=uuid.uuid4().hex[:8].upper(),
                decision_owner=_resolve_decision_owner(reasons),
                dst_ip=destination_ip,
                dst_port=flow_for_event.dst_port if flow_for_event else 0,
                src_port=flow_for_event.src_port if flow_for_event else 0,
                proto=flow_for_event.proto if flow_for_event else "dns",
                telemetry_source=source,
                mlp_status="disabled_unsupported_packet_features" if flow_for_event and not flow_for_event.packet_timing_available else ("inferred" if mlp_ran else "not_run"),
                sni=sni,
                tls_version=flow_for_event.tls_version if flow_for_event else "",
                vpn_protocol=flow_for_event.vpn_protocol if flow_for_event else "",
                mlp_probability=mlp_proba if mlp_ran else None,
                mlp_schema=mlp_detector.feature_schema if mlp_ran else "",
                mlp_features=mlp_detector.last_features if mlp_ran else None,
                mlp_mode=("shadow_only" if mlp_detector.feature_schema == "packet14-v1" else "scoring") if mlp_ran else "not_run",
                ai_window_n60=window_features["n60"] if window_features else None,
                ai_window_probability=ai_window_probability,
                ai_window_mode=ai_window_mode,
                ai_window_model_sha256=window_model.sha256 if ai_window_probability is not None else "",
            )

            # HIPAA: Redact domain/SNI from event logs when sector requires it
            if sector_config.get("redact_payloads"):
                ev.domain = "[REDACTED]"

            # Education: tag events from student subnet
            if sector_config.get("log_student_activity"):
                student_subnets = seg_map.get("student", [])
                if _ip_in_subnets(client_ip, student_subnets):
                    ev.student_flagged = True

            # Education: tag events where VPN/proxy YARA rule fired
            if sector_config.get("block_vpns") or sector_config.get("block_proxies"):
                if action == "block" and any("VpnProxy" in r for r in ev.reasons):
                    ev.vpn_block_enforced = True

            # Strict-logging sectors: mark all events as audit-mode
            if sector_config.get("strict_logging"):
                ev.audit_mode = True

            writer.write(ev)
            health.observe(source)

            # Update Prometheus metrics
            if METRICS_AVAILABLE and update_metrics:
                flow_count = len(flow_tracker.get_all_active_flows())
                update_metrics(
                    ev,
                    flow_count=flow_count,
                    hard_gate_reason=hard_threat_reason if hard_threat else None,
                )
                if action == "block":
                    active_blocks.inc()
        except KeyboardInterrupt:
            logging.info("Caught KeyboardInterrupt, shutting down.")
            audit_daemon_stop("keyboard_interrupt")
            break
        except Exception:
            logging.error("Unhandled exception in main event loop", exc_info=True)

        # NEW: Export flow records periodically
        flow_export_counter += 1
        if flow_export_counter >= flow_export_interval:
            # Cleanup old flows
            cleaned = flow_tracker.cleanup_old_flows()

            # Export active flows with features
            active_flows = flow_tracker.get_all_active_flows()

            try:
                with flow_records_file.open("a", encoding="utf-8") as f:
                    for flow in active_flows:
                        # Only export flows with reasonable data
                        if flow.pkt_count < 5:  # Skip very small flows
                            continue

                        features = (build_packet_features_14(flow) if flow.packet_metadata_only else
                                    build_feature_vector_24(flow, tracker=flow_tracker)) if flow.packet_timing_available and flow.last_seen > flow.first_seen else None

                        # HIPAA: Redact domain/SNI from flow records when sector requires it
                        _redact = sector_config.get("redact_payloads", False)

                        record = {
                            "timestamp": flow.first_seen,
                            "client_ip": flow.client_ip,
                            "dst_ip": flow.dst_ip,
                            "dst_port": flow.dst_port,
                            "proto": flow.proto,
                            "domain": "[REDACTED]" if _redact else flow.domain,
                            "sni": "[REDACTED]" if _redact else flow.sni,
                            "segment": segment_for_ip(flow.client_ip, seg_map),
                            "features": None if flow.packet_metadata_only else features,
                            "packet_features": features if flow.packet_metadata_only else None,
                            "packet_feature_schema": "packet14-v1" if flow.packet_metadata_only else "",
                            "src_port": flow.src_port,
                            "packet_timing_available": flow.packet_timing_available,
                            "mlp_status": ("eligible_packet14_only" if flow.packet_metadata_only else "eligible") if features is not None else "disabled_unsupported_packet_features",
                            "duration": flow.get_duration(),
                            "packets": flow.pkt_count,
                            "bytes": flow.get_total_bytes(),
                            # Include decision info if available
                            "action": action if flow is flow_for_event else None,
                            "score": score if flow is flow_for_event else None,
                            # NEW: AI Verdict (auditability)
                            "ai_verdict": (
                                ("threat" if mlp_proba >= mlp_detector.threshold else "normal")
                                if mlp_ran and flow is flow_for_event else None
                            ),
                            "ai_confidence": (
                                mlp_proba
                                if mlp_ran and flow is flow_for_event
                                else None
                            ),
                            "hard_threat_override": (
                                hard_threat if flow is flow_for_event else None
                            ),
                            "hard_threat_reason": (
                                hard_threat_reason
                                if (flow is flow_for_event and hard_threat)
                                else None
                            ),
                            # NEW: Include MLP prediction if available
                            "mlp_enabled": mlp_enabled,
                            "mlp_mode": ("shadow_only" if flow.packet_metadata_only else "scoring") if mlp_ran and flow is flow_for_event else "not_run",
                            "mlp_proba": mlp_proba if flow is flow_for_event else None,
                            "mlp_score": mlp_score if flow is flow_for_event else None,
                            # NEW: Include YARA matches if available
                            "yara_enabled": yara_enabled,
                            "yara_score": (
                                yara_score if flow is flow_for_event else None
                            ),
                            "yara_matches": (
                                [m.to_dict() for m in yara_matches]
                                if (flow is flow_for_event and yara_matches)
                                else []
                            ),
                            "label": None,  # To be labeled later for training
                            "label_reason": None,
                        }

                        f.write(json.dumps(record, ensure_ascii=False) + "\n")

            except OSError:
                logging.error("Flow export unavailable; enforcement continues", exc_info=True)
                flow_export_counter = 0
                continue

            # Reset counter
            flow_export_counter = 0

            # Print status
            if len(active_flows) > 0:
                print(
                    f"[FlowCollector] Exported {len(active_flows)} flows, cleaned {cleaned} old flows"
                )


if __name__ == "__main__":
    run()
