# v2.2.10 measured-model validation protocol

The packet14 model is synthetic and remains shadow-only. Successful inference is a functional check. The existing known-benign HTTP failure and the controlled corpus are quality failures/controls, not Financial/Education accuracy estimates. Do not retrain on the tiny acceptance corpus or tune thresholds to hide telemetry/classification defects.

## Required source and labels

Collect metadata only from explicitly authorized representative Financial and Education environments. No TLS decryption, raw payloads, credentials, private keys or required client agents. Use the same client-facing capture interface/schema as the candidate; record offload configuration, sampling/loss, runtime/model hashes, capture times and collection gaps. Export 14 finite measured features with an unambiguous connection identity, sector, scenario, time span, pseudonymous environment/device, label source and review status. Pseudonymize addresses consistently before sharing; preserve grouping so related sessions cannot leak across splits.

Finance needs legitimate login/MFA retries, payments, API access, statements, authorized bulk transfers, updates and backups, plus controlled confirmed threats with independently recorded ground truth. Education needs lesson browsing, decoded video over long sessions, searches, staff services, concurrent classes, updates and approved remote access, plus controlled denied activity/tunnels and independently labelled threats. Include IPv4/IPv6, TCP/UDP/QUIC, NAT, new/midstream sessions, quiet/missing collectors, reboot/restart, capture losses and varied legitimate volume. A connection to a policy-denied domain is a policy violation label; it is not automatically a malware label.

## Independent evaluation

Freeze a candidate model and feature implementation before scoring. Split by organization/environment, device/session and time; never randomly mix snapshots or related connections between training and evaluation. Keep unseen institutions and later periods as held-out evaluation. Have a second authorized reviewer check labels. Record uncertain labels separately and never convert them to benign or threat just to fill a class.

Publish per-scenario counts, false positives/negatives with uncertainty, inference failures/unsupported inputs, calibration, decision latency, collector/drop statistics and actual forwarded outcomes. Distinguish rule/hard-gate decisions from model probabilities and zero shadow score. Include high-volume legitimate services and approved VPN use. Agree acceptance criteria with the owners before inspecting holdout scores. Keep the model shadow-only until representative results and an independent review justify any enforcement change.

## What the laboratory corpus establishes

The versioned driver creates labelled real packet measurements from known fictional HTTP/TLS/learning traffic. Labels come from the controlled fixture, not from the model or its enforcement decision. Repeated runs within one VM are correlated and cannot establish institutional accuracy or confidence intervals. An actual OpenVPN tunnel and five bypass probes establish specific coverage gaps. This corpus is a reproducible telemetry/quality control; representative data collection and sector validation remain unfinished.
