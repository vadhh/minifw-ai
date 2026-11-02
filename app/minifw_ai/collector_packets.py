"""Optional local packet metadata from tshark; no payload, keys or PCAP is exported."""

from dataclasses import dataclass
import ipaddress
import logging
import math
import pwd
import re
import subprocess

FIELDS = ["frame.time_epoch", "frame.len", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
          "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tls.handshake.type",
          "tls.handshake.version", "tls.handshake.extensions.supported_version",
          "tls.handshake.extensions_server_name", "wg.type", "wg.sender", "wg.receiver",
          "udp.length", "wg.bad_packet_length"]
TLS_VERSIONS = {0x0301: "TLSv1.0", 0x0302: "TLSv1.1", 0x0303: "TLSv1.2", 0x0304: "TLSv1.3"}


@dataclass(frozen=True)
class PacketObservation:
    observed_at: float
    size: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    tls_version: str = ""
    sni: str = ""
    wg_type: int = 0
    wg_sender: int = -1
    wg_receiver: int = -1


def parse_packet_fields(line):
    fields = line.rstrip("\r\n").split("\t")
    if len(fields) != len(FIELDS):
        return None
    try:
        stamp, size = float(fields[0]), int(fields[1])
        if not math.isfinite(stamp) or stamp <= 0 or not 1 <= size <= 262144:
            return None
        src, dst = str(ipaddress.ip_address(fields[2] or fields[4])), str(ipaddress.ip_address(fields[3] or fields[5]))
        proto = "tcp" if fields[6] else "udp"
        sport, dport = int(fields[6] or fields[8]), int(fields[7] or fields[9])
        if not (0 < sport <= 65535 and 0 < dport <= 65535):
            return None
        version = ""
        # Only ServerHello selects the version; TLS 1.3's legacy field is 0x0303.
        if fields[10] == "2":
            version = TLS_VERSIONS.get(int(fields[12] or fields[11], 0), "")
        wg_type = int(fields[14] or "0", 0)
        if wg_type:
            length = int(fields[17])
            if (fields[18] or (wg_type == 1 and length != 156) or (wg_type == 2 and length != 100)
                    or (wg_type == 4 and (length < 40 or (length - 40) % 16))):
                wg_type = 0
        return PacketObservation(stamp, size, src, dst, sport, dport, proto, version,
                                 fields[13] if fields[10] == "1" else "",
                                 wg_type, int(fields[15] or "-1", 0),
                                 int(fields[16] or "-1", 0))
    except (ValueError, IndexError):
        return None


def stream_packet_events(interface):
    if not re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_.:-]{0,14}", interface) or interface == "any":
        raise ValueError("Choose one explicit client-facing interface; 'any' duplicates forwarded packets")
    command = ["tshark", "-l", "-n", "-r", "-", "-T", "fields",
               "-E", "occurrence=f"]
    for field in FIELDS:
        command.extend(["-e", field])
    # A pipe avoids tshark's default on-disk temporary capture; stderr preserves loss/errors.
    capture = subprocess.Popen(["dumpcap", "-p", "-i", interface, "-f", "ip or ip6", "-P", "-w", "-"],
                               stdout=subprocess.PIPE)
    decoder = None
    try:
        account = pwd.getpwnam("nobody")
        decoder = subprocess.Popen(command, stdin=capture.stdout, stdout=subprocess.PIPE, text=True, bufsize=1,
                                   user=account.pw_uid, group=account.pw_gid, extra_groups=[],
                                   env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent"})
        capture.stdout.close()
        for line in decoder.stdout:
            observation = parse_packet_fields(line)
            if observation is not None:
                yield observation
        raise RuntimeError(f"Packet metadata sensor stopped: exit={decoder.wait()}")
    finally:
        for process in [decoder, capture]:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def observe_packet(tracker, packet, client_subnets):
    reverse = tracker.get_flow(packet.dst_ip, packet.src_ip, packet.src_port, packet.proto, packet.dst_port)
    direct = tracker.get_flow(packet.src_ip, packet.dst_ip, packet.dst_port, packet.proto, packet.src_port)
    inbound = reverse is not None and direct is None
    if reverse is None and direct is None:
        src_client = any(ipaddress.ip_address(packet.src_ip) in net for net in client_subnets)
        dst_client = any(ipaddress.ip_address(packet.dst_ip) in net for net in client_subnets)
        if not src_client and not dst_client:
            return None, False
        inbound = dst_client and not src_client
    src, dst = (packet.dst_ip, packet.src_ip) if inbound else (packet.src_ip, packet.dst_ip)
    sport, dport = (packet.dst_port, packet.src_port) if inbound else (packet.src_port, packet.dst_port)
    previous = tracker.get_flow(src, dst, dport, packet.proto, sport)
    flow = tracker.update_flow(src, dst, dport, packet.proto, src_port=sport)
    if previous is None:
        flow.first_seen = flow.last_seen = flow.current_window_start = packet.observed_at
    if flow.last_pkt_time is not None and packet.observed_at < flow.last_pkt_time:
        logging.warning("[PACKET] Reordered timestamp; measurement ignored")
        return None, False
    flow.update(packet.size, "in" if inbound else "out", observed_at=packet.observed_at)
    flow.packet_metadata_only = True
    if packet.tls_version and inbound:
        flow.tls_version = packet.tls_version
        flow.tls_seen = True
    if packet.sni and not inbound:
        flow.sni = packet.sni
        flow.tls_seen = True
    # Require both directions and a matching transport index, not a provider name/UDP port.
    if packet.wg_type == 1 and not inbound:
        flow.wg_initiator = packet.wg_sender
        flow.wg_started_at = packet.observed_at
        flow.wg_responder = -1
    elif (packet.wg_type == 2 and inbound and packet.wg_receiver == flow.wg_initiator
          and flow.wg_initiator >= 0 and packet.observed_at - flow.wg_started_at <= 30):
        flow.wg_responder = packet.wg_sender
    elif (packet.wg_type == 4 and not inbound and flow.wg_responder >= 0
          and packet.wg_receiver == flow.wg_responder):
        flow.vpn_protocol = "wireguard"
    return flow, previous is None


def protocol_policy(flow, controls):
    minimum = controls.get("minimum_tls_version", "")
    order = list(TLS_VERSIONS.values())
    if minimum and minimum not in order:
        raise ValueError("Unsupported minimum TLS version")
    if minimum in order and flow.tls_version in order and order.index(flow.tls_version) < order.index(minimum):
        return "block", [f"tls_version_below_minimum:{flow.tls_version}:{minimum}"]
    if flow.vpn_protocol:
        return ("block" if controls.get("block_vpn_tunnels", False) else "monitor"), [f"vpn_tunnel:{flow.vpn_protocol}"]
    return "", []
