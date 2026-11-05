---
title: Public packet datasets for MiniFW enforcement models
author: St4rdhoom
date: 2026-11-04
branch: fix/monday-core-20261102
touches:
  - docs/2026-11-04_model-dataset-research-report.md
---

## Decided
Research recommends a locally trained small Random Forest versus the existing MLP on re-extracted packet14 features. HIKARI version 1.4.0 is Zenodo record 6463389, includes 2022 additions, and is CC BY 4.0 per API. IoT-23 record 4743746 is CC BY 4.0 and useful as supplementary malware coverage. Require independent captures and representative normal Financial/Education workflows before AI enforcement. Report delivered as DOCX.
## Tried and ruled out
CESNET pretrained traffic classifiers and Kitsune do not directly satisfy packet14 threat classification. UNSW-NB15 explicitly requires commercial-use agreement. UWF Data24 exposed CSV/parquet only despite the landing page describing PCAP availability. CIC and LYCOS share captures and cannot be independent holdouts.
## Watch out
No data replay, training or installation was performed. Packet14 remains explicitly shadow-only in main.py; retraining cannot close enforcement acceptance alone. Whole-flow CSV training leaks future features into early online decisions. Keep prefixes grouped by flow/capture and uncertain labels excluded. Recheck source terms before data acquisition; details and URLs are in the research report.
