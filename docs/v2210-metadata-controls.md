# v2.2.10 metadata controls — laboratory operation

Use separate disposable Financial and Education gateways. Both packages are named `minifw-ai`. These controls are opt-in laboratory candidates, not a production approval. Use the package hash and build-manifest commit to identify a candidate; the version remains 2.2.10.

## Data sources and scope

| Control | Source | Implemented behavior | Limit |
| --- | --- | --- | --- |
| SafeSearch | Generated dnsmasq configuration | Exact-host CNAME overrides to Google forced-search, Bing strict and YouTube restricted endpoints | Only configured resolver clients/hostnames; no forced DNS, DoH/DoT or general IPv6 restriction; browser/content acceptance separate |
| TLS minimum version | Visible ServerHello from local packet metadata | Compare negotiated version; isolate client forwarded IPv4 below configured minimum | Reactive after handshake metadata, not an inline guarantee; initial handshake/data can precede response; no TLS decryption |
| WireGuard pattern | UDP handshake initiation, response and transport indices/lengths | Monitor by default; optional client forwarded IPv4 isolation | No cryptographic authentication, OpenVPN/IPsec/obfuscation/all-VPN claim; requires observing handshake and transport |
| Measured AI | Local frame sizes and capture timestamps | Separate `packet14-v1` model, actual inference and explicit feature/probability export | Synthetic training; shadow only; representative accuracy/false-positive validation missing |

The existing conntrack reader still measures counter deltas and cannot supply packet timing. Enabling the packet interface selects the packet source instead of conntrack and Zeek enrichment, so counters/timing are not mixed across sources. Packet mode supplies its own visible TLS metadata. Missing sensor tooling/interfaces must be treated as unavailable coverage, not healthy protection. DNS collection remains independent. Packet mode currently needs an explicit client-facing interface and configured client subnets; do not use `any`, which duplicates forwarded observations. Capture startup, losses, GRO/offload effects, load and long-lived sessions need additional validation.

Initial packets whose two endpoints both belong to configured client subnets are skipped rather than guessing the client direction. Intra-site packet attribution needs SYN/conntrack correlation before claiming coverage. The verified tests use unambiguous client-to-server tuples across the isolated routed link.

`dumpcap -P -w -` feeds `tshark -r -` through a memory pipe. No raw PCAP, application payload or key material is written/exported by this path. Packet decoding runs as `nobody`, with no supplementary groups and a minimal environment; it does not inherit application secrets or key-log settings. The capture helper and enforcement engine still require privilege. This does not resolve the existing dashboard-root concern.

## Controlled lab verification

The native lab tools used are tshark/Wireshark 4.0.17, wireguard-tools 1.0.20210914, dnsmasq 2.90 and the package's Python 3.11/scikit-learn 1.5.2 environment. Install tools only in the isolated VM; they are not required client software for the product.

```bash
sudo apt-get install --no-install-recommends tshark wireguard-tools dnsutils
```

Copy `testing/lab_gateway_acceptance.py`, `testing/lab_sandbox.py` and `testing/fixtures/lesson.webm` adjacent under `/var/tmp` in the matching `minifw-monday-*` VM. The driver checks the installed and selected package versions are the expected v2.2.10 edition and creates its own client/server namespaces. Verify the package hash and installed payload before running it.

```bash
# In minifw-monday-education only; use its actual exact-hash package path.
sudo /opt/minifw_ai/venv/bin/python /var/tmp/lab_gateway_acceptance.py education /absolute/path/minifw-ai_2.2.10-education_amd64.deb --metadata
# Financial uses its separate VM, financial argument and finance package.
```

The driver configures an explicit `mfcg` interface, requires a fresh packet decision for readiness, demonstrates packet-model inference with DNS disabled, exercises TLS 1.0/1.2/1.3, creates a real kernel WireGuard tunnel, tests monitor and block policy, and runs client DNS queries against the generated restricted resolver. It restores the original deployment-state file and mode and removes its override/namespaces. Export only whitelisted public artifacts; `server.key` and WireGuard private keys remain private.

## Optional sensor configuration

The lab driver installs these temporary systemd environment overrides. Manual experiments should use a dedicated override file in the lab VM and an actual client-facing interface:

```ini
[Service]
Environment=MINIFW_PACKET_INTERFACE=mfcg
Environment=MINIFW_MLP_MODEL=/opt/minifw_ai/models/mlp_packet14.pkl
Environment=AI_ENABLED=1
Environment=DEGRADED_MODE=0
```

Set `AI_ENABLED=0` to disable inference; persisted state cannot override that instruction. Valid packet observations can support AI telemetry health without DNS. A quiet or failed capture must not generate fake health events. The packet14 model checks its feature order, scaler, class labels and exact scikit-learn version. The original 24-feature model remains separate and rejects packet-only metadata that lacks its TLS/DNS inputs.

Both policies provide:

```json
"protocol_controls": {
  "minimum_tls_version": "TLSv1.2",
  "block_vpn_tunnels": false
}
```

Changing `block_vpn_tunnels` to `true` enables the tested WireGuard-pattern isolation action. Default monitoring avoids assuming every observed VPN is unauthorized. A block isolates the client's forwarded IPv4 source, not only one destination. IPv6 and host INPUT/OUTPUT are outside that enforcement scope. Rule decisions and `mlp_probability` are separate: `packet14-v1` reports `mlp_mode=shadow_only` and contributes zero enforcement score, regardless of its probability. A high probability on legitimate lab HTTP was observed, so classification must not be presented as validated protection.

Per-second packet gates require a complete measured second. This is a measurement eligibility condition, not a changed detection threshold. Existing policy thresholds/weights remain unchanged. Feature arrays use captured frame lengths/timestamps: basic counts/rates and ratio, size samples (last 1,000), intervals (last 500), and a bounded history of completed burst windows plus the current window. They describe observed interface traffic, not guaranteed lossless wire measurements. Packet14 exports have separate fields and are not silently mixed into legacy24 training records.

## SafeSearch resolver configuration

Generate an independently validated configuration file. The module does not restart DNS or alter client settings automatically:

```bash
# Inside the lab VM; parent directory must exist.
sudo /opt/minifw_ai/venv/bin/python /opt/minifw_ai/app/minifw_ai/safesearch.py --output /var/tmp/minifw-safesearch.conf
sudo dnsmasq --test --conf-file=/var/tmp/minifw-safesearch.conf
```

Review/back up an existing resolver configuration before integrating the file into that lab resolver and restarting it. The automated driver uses the generated file directly and records exact client answers. Endpoint IPv4 addresses are resolved at generation time, checked for public addresses and stored as local records so dnsmasq can resolve its CNAME targets. Re-generate when provider addresses change. Google `.com` and `.co.id` search aliases, Bing `www`/Edge search, and Google's documented YouTube restricted hostnames are included. Accounts and other unlisted hostnames are untouched; `youtube.com` is deliberately not aliased because Google's guidance warns that doing so can break YouTube. The legacy search-domain allowlist is not itself a resolver restriction. DuckDuckGo and unlisted country domains remain outside this implementation.

Provider guidance supports these network mappings: [Google SafeSearch](https://support.google.com/websearch/answer/186669), [Bing strict search](https://support.microsoft.com/en-us/bing/blocking-explicit-content-with-safesearch), [YouTube restricted DNS](https://support.google.com/a/answer/6214622). The resolver override is not a guarantee that alternate DNS, encrypted DNS, direct-IP access or every browser/platform path is restricted.

## Reproduction and remaining validation

The experimental model recipe is `scripts/generate_packet_model.py`, reusing the existing synthetic generator's first 14 fields. Run it with the pinned Debian environment; the original model is preserved:

```bash
/opt/minifw_ai/venv/bin/python scripts/generate_packet_model.py models/mlp_packet14.pkl
```

It uses 2,000 synthetic examples and does not report them as real Financial/Education accuracy. The selected model/version and actual feature arrays belong in the evidence. Serialization/version constraints follow [scikit-learn's model persistence guidance](https://scikit-learn.org/stable/model_persistence.html). TLS metadata fields are documented by [Wireshark](https://www.wireshark.org/docs/dfref/t/tls.html); the handshake/transport pattern is grounded in the [WireGuard protocol](https://www.wireguard.com/protocol/) and [Wireshark WireGuard fields](https://www.wireshark.org/docs/dfref/w/wg.html).

Continue with representative labeled real metadata, independent holdouts, false-positive/false-negative measurements, sustained learning/video/payment traffic, sensor-loss/failure tests, offload/capture calibration, response-latency measurements and operational policy review. The narrow lab results do not validate all VPNs, production AI accuracy or readiness. The consolidated Monday report records successful and failed tests and exact candidate hashes.
