from __future__ import annotations
import time
from pathlib import Path
from typing import Iterator, Optional, NamedTuple


class ZeekSSLEvent(NamedTuple):
    client_ip: str
    sni: str
    handshake_ms: float        # Reserved — ssl.log lacks direct timing; 0.0 until conn.log integration
    alpn_h2: float             # 1.0 if ALPN negotiated h2 (HTTP/2), else 0.0
    cert_self_signed: float    # 1.0 if cert_chain has exactly 1 entry (self-signed proxy heuristic)


# Zeek ssl.log TSV column indices (standard Zeek 5.x/6.x schema)
# ts uid id.orig_h id.orig_p id.resp_h id.resp_p version cipher curve
# server_name resumed last_alert next_protocol established cert_chain_fuids ...
_COL_CLIENT_IP  = 2
_COL_SERVER_NAME = 9   # SNI — "server_name" field
_COL_NEXT_PROTO  = 12  # ALPN — "next_protocol" field (e.g. "h2", "http/1.1", "-")
_COL_CERT_CHAIN  = 14  # "cert_chain_fuids" — comma-separated FUIDs or "-"


def tail_lines(path: Path) -> Iterator[str]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line.rstrip("\n")


def parse_zeek_ssl_tsv(line: str) -> Optional[ZeekSSLEvent]:
    """
    Parse a single line from Zeek ssl.log (TSV format).

    Returns a ZeekSSLEvent or None if the line is a comment, header, or unparseable.
    Extracts: client_ip, SNI, ALPN (h2 flag), cert chain length (self-signed heuristic).
    """
    if not line or line.startswith("#"):
        return None
    parts = line.split("\t")
    if len(parts) <= _COL_SERVER_NAME:
        return None

    try:
        client_ip = parts[_COL_CLIENT_IP].strip()
        if not client_ip or client_ip == "-":
            return None

        sni = parts[_COL_SERVER_NAME].strip()
        if sni == "-":
            sni = ""

        # ALPN — 1.0 if HTTP/2 was negotiated
        next_proto = parts[_COL_NEXT_PROTO].strip() if len(parts) > _COL_NEXT_PROTO else "-"
        alpn_h2 = 1.0 if next_proto.lower() in ("h2", "h2c") else 0.0

        # Self-signed heuristic: exactly one cert in chain suggests MITM proxy or self-signed cert
        cert_chain_raw = parts[_COL_CERT_CHAIN].strip() if len(parts) > _COL_CERT_CHAIN else "-"
        if cert_chain_raw and cert_chain_raw != "-":
            chain_len = len([c for c in cert_chain_raw.split(",") if c.strip()])
            cert_self_signed = 1.0 if chain_len == 1 else 0.0
        else:
            cert_self_signed = 0.0

        if client_ip and (sni or alpn_h2 or cert_self_signed):
            return ZeekSSLEvent(
                client_ip=client_ip,
                sni=sni,
                handshake_ms=0.0,  # ssl.log lacks direct timing; requires conn.log correlation
                alpn_h2=alpn_h2,
                cert_self_signed=cert_self_signed,
            )
    except Exception:
        return None
    return None


def stream_zeek_sni_events(log_path: str) -> Iterator[ZeekSSLEvent]:
    """
    Tail Zeek ssl.log and yield ZeekSSLEvent for each parsed TLS connection.
    Returns an empty iterator if the log path does not exist (Zeek not installed).
    """
    import logging as _logging
    p = Path(log_path)
    if not p.exists():
        _logging.info("[ZEEK] ssl.log not found at %s — SNI enrichment disabled", p)
        return
    for ln in tail_lines(p):
        evt = parse_zeek_ssl_tsv(ln)
        if evt:
            yield evt
