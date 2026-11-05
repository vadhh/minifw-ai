# MiniFW-AI: model and dataset research

4 November 2026 · Standalone Financial and Education · Research recommendation

## Recommendation

Train and compare a small Random Forest and the existing small MLP using MiniFW’s own measured packet features. Start with HIKARI-2021 raw packet captures and their ground truth; use selected IoT-23 captures for additional malware coverage and a separately reserved external test. Neither dataset qualifies automatic blocking without representative Financial and Education normal-traffic validation. This recommendation is an engineering judgment, not a measured accuracy result. [S1–S3]

No verified, ready-to-install pretrained threat model compatible with MiniFW’s present feature contract was found in the sources reviewed. CESNET offers pretrained traffic models, but their task and inputs differ; Kitsune supplies an anomaly-detection implementation with a different extractor and scoring contract. [S8–S9]

The AI delivery gate remains open. Research does not close it, and retraining alone does not enable enforcement: the current packet14 inference path explicitly remains shadow-only. Do not bypass that restriction by mislabelling a model’s schema. VPN expansion and ARCHANGEL device binding remain outside scope.

## Dataset shortlist

| Dataset | Available material and reuse terms | Fit and decision |
| --- | --- | --- |
| HIKARI-2021, record version 1.4.0 | PCAPs, ground truth and derived tables; CC BY 4.0 verified in the publisher API. The current record also contains 2022 additions. [S1] | First feasibility pilot for web/encrypted traffic. Re-extract MiniFW features; prove the PCAP-to-label join before using it. Keep capture years and scenarios explicit. |
| IoT-23, version 1.0.0 | Full archive about 21.5 GB; raw traffic and labelled flows. CC BY 4.0 verified in publisher metadata. Twenty malware and three benign IoT captures. [S2] | Useful malware supplement and external test, with captures assigned to distinct roles. IoT normal traffic does not represent a bank or school. Previously evaluated captures are not a pristine unseen test. |
| UWF-ZeekData24 | Publisher states CC BY 4.0 and describes PCAP/parquet availability. The inspected Data24 directory exposes CSV and parquet only. [S4] | Promising enterprise benchmark, conditional on obtaining matching PCAP and labels. Current tables are not packet14 input. Raw-capture access remains unconfirmed. |
| CIC-IDS2017 with LYCOS corrections | Original PCAP and flow tables; LYCOS documents extraction/label corrections. Publisher pages request citation but do not establish clear commercial reuse permission in this review. [S5–S6] | Secondary research benchmark after permission and label review. Original and corrected versions share captures: they are not independent datasets for a train/test split. |
| UNSW-NB15 | PCAP, labels and extracted tables. Authors explicitly require agreement for commercial use. [S7] | Hold out of the commercial training pipeline until agreement is obtained. Public download availability is insufficient. |
| UQ NetFlow datasets, v2/v3 | Derived CSVs use 43/53 features, respectively, rather than MiniFW’s 14. Sources include UNSW and other collections. [S10] | Useful for a separate NetFlow research track. Not a shortcut for this collector; check source and derivative terms individually. |
| CESNET-TLS-Year22 | CC BY 4.0 dataset, about 30.5 GB, labelled by web service. Packet representations use payload-length sequences rather than MiniFW’s complete frame-length statistics. [S11] | Optional application-diversity research. Service labels are not benign/malicious ground truth; do not label the entire dataset safe. |

CC BY 4.0 permits commercial adaptation subject to its terms, including attribution, a licence link and indicating changes. Preserve a provenance and attribution record with derived data and the model handoff. This finding concerns the stated dataset licence; it is not a blanket clearance of privacy or third-party rights. [S3]

HIKARI’s paper distinguishes background and benign traffic and reports attacks discovered in background traffic. Do not equate background with verified safe traffic, or mark every flow in an attack-named capture malicious. Confirm label meaning, direction, timestamp alignment and attack timing. [S12]

## Which model to use

| Candidate | Why consider it | Decision |
| --- | --- | --- |
| Small Random Forest, trained locally | Suitable baseline for numerical tabular features; existing loader uses a generic predict_proba interface. CPU cost and artifact size need measurement. | First challenger to the MLP. Potential bundle compatibility is inferred from code, not tested here. |
| Existing small MLP, retrained | Already integrated with the feature/scaler pipeline. Retaining the architecture makes data-quality improvements easier to isolate. | Required comparison. Replace synthetic-only training with vetted measured examples; do not assume this fixes false isolation. |
| Logistic regression | Cheap reference for whether more complex models actually help. | Optional baseline within the same experiment, not another product feature. |
| Kitsune / KitNET | Author implementation uses incremental stateful statistics and autoencoders; MIT code, anomaly RMSE output. [S8] | Later experiment. Requires clean normal training, score calibration and a different extractor/integration. It is not a universal pretrained threat model. |
| CESNET 30pktTCNET / mm-CESNET-v2 | Public pretrained traffic embeddings/classifiers use packet sequences and, for the older model, flow statistics. [S9] | Later transfer-learning research. Application/domain classification is not firewall attack classification; no compatible threat head was established. |

Do not choose by a paper’s headline accuracy. Select on held-out false client isolation, threat recall at that operating point, detection delay, coverage, CPU, memory and enforcement stability. A model score must be calibrated and evaluated before being treated as a probability.

## Fit with MiniFW’s implementation

Local source reviewed: app/minifw_ai/utils/mlp_engine.py, collector_flow.py, collector_packets.py, main.py and scripts/generate_packet_model.py. These are implementation observations, not online claims.

The packet14-v1 vector contains duration, packet and byte counts, byte/packet rates, mean and standard deviation of packet size, direction ratio, one-second packet/byte burst maxima, interarrival mean/standard deviation/95th percentile and small-packet ratio. These require measured packet timestamps, lengths and direction. A similarly named CSV column from another extractor is not evidence of equivalent semantics.

The loader requires exactly 14 features in the declared order, matching scaler names, classes [0, 1] and the installed scikit-learn version. A Random Forest would still need the scaler required by this bundle contract and must be trained on the same transformed input. Verify model type, metadata, output interpretation and runtime compatibility in an isolated guest before any release.

Current packet inference starts after a flow has sufficient packets. Training on completed-flow statistics would introduce information unavailable at the decision time. Replay captures through the production extractor and generate examples at the same eligible flow prefixes. All prefixes of a flow must stay in the same split. Exclude prefixes whose malicious label depends on an attack that has not started yet, unless temporal ground truth justifies the label.

Existing synthetic packet training and earlier public-capture evaluations are insufficient for sector enforcement acceptance. No new accuracy measurement, training run or model installation was performed in this research.

## Concrete next experiment

- Pin HIKARI record 6463389, version 1.4.0. Begin with the 271.1 MB Monday_2021-04-12_0611.pcap and the 97.3 MB ground-truth archive, about 368.4 MB combined. This is a label/extractor pilot, not a balanced training corpus. Retain publisher checksums and compute SHA-256 after download. [S1]
- Verify the ground-truth join using protocol, endpoint tuple, direction and time. Report matched, ambiguous, unmatched and unsupported flows separately. Unknown labels must not silently become benign. The join has not yet been reproduced.
- Expand only after that check to multiple labelled HIKARI sessions and selected IoT-23 sessions. Keep all examples from each capture/session together; fit preprocessing and any resampling on training data only. Reserve entire independent captures for evaluation. Avoid endpoint identifiers as predictive shortcuts.
- Obtain approved representative normal workflows separately for each edition: financial login/API/upload/export/backup and software updates; education LMS, exams, conferencing, video and downloads. Include legitimate bursts and concurrent users. Public datasets alone cannot establish sector readiness.
- Compare the small MLP and Random Forest with one frozen test set and fixed decision policy. Record precision/recall, false isolation per client-session/day, eligible coverage, delay and resource use. Check each attack family and each edition separately.
- Only after quality qualification, test explicit AI contribution in isolated guests: a model-caused kernel block on a labelled threat the deterministic rules would otherwise allow; legitimate traffic preserved; attribution visible; disable/rollback and model-failure behavior verified. Repeat the F1 legitimate-load and F2 load → full-log → deny → recovery acceptance sequences with AI active.

Agree the false-isolation budget before tuning. For perspective, a 0.1% false-positive rate over 10,000 normal flows implies about ten false alarms on average; client isolation can amplify the cost. Zero failures in 3,000 independent sessions gives only an approximate 95% upper bound of 0.1%, not proof of safety at packet-inference scale. Correlated flow prefixes do not count as independent sessions. These are illustrations, not passed gates or an approved target.

Friday remains a target, not a model-quality guarantee. If representative false-isolation and AI-enforcement gates cannot be demonstrated, report the blocker and keep the delivery decision on HOLD.

## Sources and verification limits

Primary publisher, author and official project sources were checked online on 4 November 2026. Dataset metadata and file listings were inspected; large PCAP archives were not downloaded or replayed. Listed sizes are decimal and approximate. Commercial terms described as unresolved require clarification, not an assumption of prohibition or permission.

- [S1] HIKARI publisher record, version 1.4.0: https://zenodo.org/records/6463389 ; licence/file metadata: https://zenodo.org/api/records/6463389
- [S2] IoT-23 publisher record: https://zenodo.org/records/4743746 ; metadata: https://zenodo.org/api/records/4743746 ; author details: https://www.stratosphereips.org/datasets-iot23
- [S3] Creative Commons Attribution 4.0: https://creativecommons.org/licenses/by/4.0/
- [S4] UWF publisher and inspected directory: https://datasets.uwf.edu/ ; https://datasets.uwf.edu/data/UWF-ZeekData24/
- [S5] CIC-IDS2017 publisher: https://www.unb.ca/cic/datasets/ids-2017.html
- [S6] LYCOS authors and correction paper: https://lycos-ids.univ-lemans.fr/ ; https://www.scitepress.org/Papers/2022/107740/pdf/index.html
- [S7] UNSW-NB15 publisher and commercial-use terms: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- [S8] Kitsune author implementation and paper: https://github.com/ymirsky/Kitsune-py ; https://arxiv.org/abs/1802.09089
- [S9] CESNET pretrained model documentation: https://cesnet.github.io/cesnet-models/
- [S10] University of Queensland dataset catalogue: https://staff.itee.uq.edu.au/marius/NIDS_datasets/
- [S11] CESNET-TLS-Year22 publisher record: https://zenodo.org/records/10608607 ; metadata: https://zenodo.org/api/records/10608607
- [S12] HIKARI author paper: https://doi.org/10.3390/app11177868

Dataset selection and proposed experiments are recommendations. No published performance figure is represented as MiniFW performance. This report changes no application code, installed model or release package.
