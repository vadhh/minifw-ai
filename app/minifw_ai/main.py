from __future__ import annotations
import os
import logging
from collections import OrderedDict

from minifw_ai.policy import Policy
from minifw_ai.feeds import FeedMatcher
from minifw_ai.netutil import ip_in_any_subnet
from minifw_ai.events import Event, EventWriter, now_iso
from minifw_ai.enforce import ipset_create, ipset_add, nft_apply_forward_drop
from minifw_ai.collector_dnsmasq import stream_dns_events_file
from minifw_ai.collector_zeek import stream_zeek_sni_events
from minifw_ai.burst import BurstTracker

def _safe_int_cast(value, default: int) -> int:
    """Helper to safely cast a value from a policy file to an int."""
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (ValueError, TypeError):
        logging.warning(f"Could not cast '{value}' to int, using default {default}")
        return default

def segment_for_ip(ip: str, mapping: dict[str, list[str]]) -> str:
    for seg, cidrs in mapping.items():
        if ip_in_any_subnet(ip, cidrs):
            return seg
    return "default"

def score_and_decide(domain: str, denied: bool, sni_denied: bool, asn_denied: bool, burst_hit: int, weights: dict, thresholds):
    score = 0
    reasons = []

    if denied:
        score += _safe_int_cast(weights.get("dns_weight"), 40)
        reasons.append("dns_denied_domain")
    if sni_denied:
        score += _safe_int_cast(weights.get("sni_weight"), 35)
        reasons.append("tls_sni_denied_domain")
    if asn_denied:
        score += _safe_int_cast(weights.get("asn_weight"), 15)
        reasons.append("asn_denied")
    if burst_hit:
        score += _safe_int_cast(weights.get("burst_weight"), 10)
        reasons.append("burst_behavior")

    score = max(0, min(100, score))

    block_thr = _safe_int_cast(thresholds.block_threshold, 90)
    monitor_thr = _safe_int_cast(thresholds.monitor_threshold, 60)

    if score >= block_thr:
        return score, reasons, "block"
    if score >= monitor_thr:
        return score, reasons, "monitor"
    return score, reasons, "allow"

def run():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    policy_path = os.environ.get("MINIFW_POLICY", "/opt/minifw_ai/config/policy.json")
    feeds_dir = os.environ.get("MINIFW_FEEDS", "/opt/minifw_ai/config/feeds")
    log_path = os.environ.get("MINIFW_LOG", "/opt/minifw_ai/logs/events.jsonl")

    pol = Policy(policy_path)
    feeds = FeedMatcher(feeds_dir)
    writer = EventWriter(log_path)

    enf = pol.enforcement()
    set_name = enf.get("ipset_name_v4", "minifw_block_v4")
    timeout = _safe_int_cast(enf.get("ip_timeout_seconds"), 86400)
    table = enf.get("nft_table", "inet")
    chain = enf.get("nft_chain", "forward")

    try:
        ipset_create(set_name, timeout)
        nft_apply_forward_drop(set_name, table=table, chain=chain)
    except (ValueError, subprocess.CalledProcessError) as e:
        logging.critical(f"FATAL: Could not initialize firewall rules. Exiting. Error: {e}")
        return # Exit if firewall can't be set up

    burst_cfg = pol.burst()
    monitor_qpm = _safe_int_cast(burst_cfg.get("dns_queries_per_minute_monitor"), 120)
    block_qpm = _safe_int_cast(burst_cfg.get("dns_queries_per_minute_block"), 240)
    burst = BurstTracker(window_seconds=60)

    seg_map = pol.segment_subnets()
    weights = pol.features()
    col = pol.collectors()
    dns_log = col.get("dnsmasq_log_path", "/var/log/dnsmasq.log")
    zeek_ssl = col.get("zeek_ssl_log_path", "/var/log/zeek/ssl.log")
    use_zeek = bool(col.get("use_zeek_sni", False))

    zeek_iter = None
    MAX_SNI_CACHE_SIZE = 10000 
    last_sni = OrderedDict()
    
    if use_zeek:
        try:
            zeek_iter = stream_zeek_sni_events(zeek_ssl)
        except Exception:
            logging.error("Failed to start Zeek SNI event stream.", exc_info=True)
            zeek_iter = None

    def pump_zeek():
        if zeek_iter is None:
            return
        for _ in range(3):
            try:
                client_ip, sni = next(zeek_iter)
                last_sni[client_ip] = sni
                if len(last_sni) > MAX_SNI_CACHE_SIZE:
                    last_sni.popitem(last=False)
            except StopIteration:
                break # Gracefully handle end of stream
            except Exception:
                logging.warning("Error pumping zeek event", exc_info=True)
                break

    # Main Event Loop (File Driven)
    logging.info("Starting MiniFW-AI event loop...")
    for client_ip, domain in stream_dns_events_file(log_path=dns_log):
        try:
            pump_zeek()

            segment = segment_for_ip(client_ip, seg_map)
            thr = pol.thresholds(segment)

            if feeds.domain_allowed(domain):
                denied = False
            else:
                denied = feeds.domain_denied(domain)

            sni = last_sni.get(client_ip, "")
            sni_denied = bool(sni and (not feeds.domain_allowed(sni)) and feeds.domain_denied(sni))

            asn_denied = False  # placeholder for offline ASN integration

            qpm = burst.add(client_ip)
            burst_hit = 1 if (qpm >= block_qpm or qpm >= monitor_qpm) else 0

            score, reasons, action = score_and_decide(domain, denied, sni_denied, asn_denied, burst_hit, weights, thr)

            if action == "block":
                ipset_add(set_name, client_ip, timeout)

            writer.write(Event(ts=now_iso(), segment=segment, client_ip=client_ip, domain=domain,
                               action=action, score=score, reasons=reasons))
        except KeyboardInterrupt:
            logging.info("Caught KeyboardInterrupt, shutting down.")
            break
        except Exception:
            logging.error("Unhandled exception in main event loop", exc_info=True)


if __name__ == "__main__":
    run()
