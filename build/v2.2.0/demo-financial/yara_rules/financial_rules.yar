/*
  MiniFW-AI Financial Sector YARA Rules — v2.2.0
  Sector: finance (PCI-DSS / SWIFT / Banking)

  Scanned payload: UTF-8 bytes of "{domain} {sni}" per DNS event.

  Rule categories:
    financial_banking_trojan   — TrickBot, Zeus, Dridex, IcedID, Emotet targeting banks
    financial_swift_fraud      — SWIFT wire fraud, MT103/MT202 intercept, gateway abuse
    financial_card_exfil       — POS malware, card skimmer C2, payment data exfiltration
    financial_credential_theft — Credential harvesting targeting banking / ERP systems
    financial_c2_anonymizer    — Tor exit nodes, VPN tunnels, anonymizers on trading floor
    financial_insider_threat   — Internal data exfil from treasury / ERP / settlement systems
    financial_fraud_infra      — Generic fraud infrastructure: drop zones, staging, redirectors

  Severity → YARA score mapping (in main.py):
    critical → 100  (×0.35 weight = +35 pts)
    high     →  75  (×0.35 weight = +26 pts)
    medium   →  50  (×0.35 weight = +17 pts)
    low      →  25  (×0.35 weight = +8  pts)
*/

// ─────────────────────────────────────────────────────────────────────────────
// 1. BANKING TROJANS
// ─────────────────────────────────────────────────────────────────────────────

rule FinancialBankingTrojan
{
    meta:
        category    = "financial_banking_trojan"
        severity    = "critical"
        description = "Detects banking trojan C2 beacons and staging domains targeting financial institutions"
        author      = "MiniFW-AI"
        pci_dss     = "Requirement 6.4 — Malicious software controls"

    strings:
        // TrickBot — modular banking trojan, primary demo trigger
        $trickbot_c2    = "trickbot"                nocase
        $trickbot_gate  = "trickbot-gate"            nocase
        $trickbot_srv   = "tbot-srv"                 nocase

        // Zeus / Zbot family — oldest financial trojan family
        $zeus           = "zbot"                     nocase
        $zeus_panel     = "zeus-panel"               nocase
        $gameover_zeus  = "gameover"                 nocase

        // Dridex — major banking trojan targeting wire transfers
        $dridex         = "dridex"                   nocase
        $dridex_c2      = "dridex-c2"                nocase

        // IcedID / BokBot — banking trojan with webinject capability
        $icedid         = "icedid"                   nocase
        $bokbot         = "bokbot"                   nocase

        // Emotet — banking trojan / loader, targets financial sector
        $emotet         = "emotet"                   nocase
        $emotet_c2      = "emotet-c2"                nocase

        // Ursnif / Gozi — banking credential stealer
        $ursnif         = "ursnif"                   nocase
        $gozi           = "gozi"                     nocase

        // Qakbot / QBot — banking trojan with ERP module
        $qakbot         = "qakbot"                   nocase
        $qbot           = "qbot-c2"                  nocase

        // Generic banking C2 infrastructure patterns in DNS hostnames
        $bank_c2        = "banking-c2"               nocase
        $fin_trojan     = "fin-trojan"               nocase
        $finserv_rat    = "finserv-rat"              nocase

    condition:
        any of them
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. SWIFT FRAUD
// ─────────────────────────────────────────────────────────────────────────────

rule FinancialSwiftFraud
{
    meta:
        category    = "financial_swift_fraud"
        severity    = "critical"
        description = "Detects SWIFT wire fraud, MT103/MT202 intercept attempts, and interbank settlement abuse"
        author      = "MiniFW-AI"
        pci_dss     = "Requirement 10.6 — Review logs for anomalies"
        swift_cscf  = "SWIFT Customer Security Controls Framework — Control 2.1"

    strings:
        // Demo trigger domains — exact matches
        $swift_intercept = "swift-intercept"         nocase
        $wire_redirect   = "wire-redirect"           nocase

        // SWIFT message type abuse in DNS
        $mt103_abuse    = "mt103"                    nocase
        $mt202_abuse    = "mt202"                    nocase
        $mt940_probe    = "mt940"                    nocase

        // Wire transfer fraud infrastructure
        $wire_fraud     = "wire-fraud"               nocase
        $wire_hijack    = "wire-hijack"              nocase
        $swift_gate     = "swift-gate"               nocase
        $swift_api      = "swift-api"                nocase
        $swift_proxy    = "swift-proxy"              nocase

        // Settlement / interbank attack patterns
        $settle_redir   = "settle-redir"             nocase
        $interbank_c2   = "interbank-c2"             nocase
        $bic_spoof      = "bic-spoof"                nocase
        $iban_harvest   = "iban-harvest"             nocase

        // Real-world SWIFT attack infrastructure naming patterns
        $swift_drop     = "swift-drop"               nocase
        $transfer_hijack = "transfer-hijack"         nocase
        $payment_redir  = "payment-redir"            nocase

    condition:
        any of them
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. CARD DATA EXFILTRATION
// ─────────────────────────────────────────────────────────────────────────────

rule FinancialCardExfil
{
    meta:
        category    = "financial_card_exfil"
        severity    = "critical"
        description = "Detects payment card data exfiltration, POS malware C2, and skimmer infrastructure"
        author      = "MiniFW-AI"
        pci_dss     = "Requirement 3.4 — Protect stored cardholder data"

    strings:
        // Demo trigger — payment collection exfil domain
        $payment_collect = "payment-collect"         nocase

        // POS malware families
        $pos_malware    = "pos-malware"              nocase
        $backoff        = "backoff-pos"              nocase
        $alina          = "alina-pos"                nocase
        $vskimmer       = "vskimmer"                 nocase

        // Card skimmer C2 and staging patterns in DNS
        $skimmer_c2     = "skimmer-c2"              nocase
        $card_skim      = "card-skim"               nocase
        $card_dump      = "card-dump"               nocase
        $track_data     = "track-data"              nocase

        // Card data exfiltration infrastructure
        $card_exfil     = "card-exfil"              nocase
        $pan_exfil      = "pan-exfil"               nocase
        $cvv_collect    = "cvv-collect"             nocase
        $cc_drop        = "cc-drop"                 nocase
        $fullz_drop     = "fullz-drop"              nocase

        // Generic payment fraud infrastructure
        $pay_fraud      = "pay-fraud"               nocase
        $carding_c2     = "carding-c2"              nocase
        $bin_attack     = "bin-attack"              nocase

    condition:
        any of them
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. CREDENTIAL THEFT — FINANCIAL SYSTEMS
// ─────────────────────────────────────────────────────────────────────────────

rule FinancialCredentialTheft
{
    meta:
        category    = "financial_credential_theft"
        severity    = "high"
        description = "Detects credential harvesting tools and staging infrastructure targeting banking and ERP systems"
        author      = "MiniFW-AI"
        pci_dss     = "Requirement 8.2 — Individual user authentication"

    strings:
        // Demo trigger — credential stealer staging domain
        $cred_stealer   = "cred-stealer"            nocase

        // Credential harvesting tool signatures in DNS exfil
        $credential_harvest = "credential-harvest"   nocase
        $cred_harvest   = "cred-harvest"             nocase
        $pass_harvest   = "pass-harvest"             nocase

        // Financial system targeting — ERP / treasury / banking portal
        $erp_cred       = "erp-cred"                nocase
        $sap_cred       = "sap-cred"                nocase
        $oracle_cred    = "oracle-cred"             nocase
        $treasury_cred  = "treasury-cred"           nocase
        $banking_cred   = "banking-cred"            nocase

        // Credential dump exfil patterns
        $ntlm_dump      = "ntlm-dump"               nocase
        $hash_exfil     = "hash-exfil"              nocase
        $passwd_dump    = "passwd-dump"             nocase
        $kerberoast     = "kerberoast"              nocase

        // Brute force / spray infrastructure in financial sector
        $cred_spray     = "cred-spray"              nocase
        $pass_spray     = "pass-spray"              nocase
        $brute_finance  = "brute-finance"           nocase

    condition:
        any of them
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. C2 VIA ANONYMIZERS — TRADING FLOOR CONTEXT
// ─────────────────────────────────────────────────────────────────────────────

rule FinancialAnonymizerC2
{
    meta:
        category    = "financial_c2_anonymizer"
        severity    = "high"
        description = "Detects Tor exit nodes, anonymizer proxies, and C2 tunnels from financial network segments"
        author      = "MiniFW-AI"
        pci_dss     = "Requirement 1.3 — Restrict inbound and outbound traffic"

    strings:
        // Demo trigger — Tor exit node from trading floor
        $tor_exit       = "tor-exit"                nocase

        // Tor infrastructure patterns in DNS
        $onion_proxy    = "onion-proxy"             nocase
        $tor_relay      = "tor-relay"               nocase
        $tor_node       = "tor-node"                nocase
        $tor_gate       = "tor-gate"                nocase
        $exit_node      = "exit-node"               nocase

        // VPN / anonymizer abuse in financial context
        $vpn_anon       = "vpn-anon"                nocase
        $anon_proxy     = "anon-proxy"              nocase
        $hide_vpn       = "hide-vpn"                nocase

        // I2P / Freenet alternative anonymizer patterns
        $i2p_c2         = "i2p-c2"                  nocase
        $freenet_gate   = "freenet-gate"            nocase

        // DNS-over-HTTPS / DNS tunnel exfil (evading corporate DNS)
        $doh_tunnel     = "doh-tunnel"              nocase
        $dns_exfil      = "dns-exfil"               nocase
        $dns_tunnel     = "dns-tunnel"              nocase

    condition:
        any of them
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. INSIDER THREAT — ERP / TREASURY DATA EXFIL
// ─────────────────────────────────────────────────────────────────────────────

rule FinancialInsiderThreat
{
    meta:
        category    = "financial_insider_threat"
        severity    = "high"
        description = "Detects unauthorized data exfiltration from treasury, ERP, and settlement systems consistent with insider threat"
        author      = "MiniFW-AI"
        pci_dss     = "Requirement 12.7 — Screen potential personnel"

    strings:
        // ERP data exfiltration patterns
        $erp_exfil      = "erp-exfil"               nocase
        $sap_exfil      = "sap-exfil"               nocase
        $oracle_exfil   = "oracle-exfil"            nocase

        // Treasury and settlement data leakage
        $treasury_leak  = "treasury-leak"           nocase
        $settlement_exfil = "settlement-exfil"      nocase
        $portfolio_dump = "portfolio-dump"          nocase
        $client_exfil   = "client-exfil"            nocase
        $account_dump   = "account-dump"            nocase

        // Large data staging infrastructure used by insiders
        $bulk_upload    = "bulk-upload"             nocase
        $data_mule      = "data-mule"               nocase
        $exfil_stage    = "exfil-stage"             nocase
        $drop_zone      = "drop-zone"               nocase

        // Clipboard / screen capture C2 (financial espionage tooling)
        $screen_grab    = "screen-grab"             nocase
        $clip_exfil     = "clip-exfil"              nocase
        $keylog_drop    = "keylog-drop"             nocase

    condition:
        any of them
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. GENERIC FINANCIAL FRAUD INFRASTRUCTURE
// ─────────────────────────────────────────────────────────────────────────────

rule FinancialFraudInfrastructure
{
    meta:
        category    = "financial_fraud_infra"
        severity    = "medium"
        description = "Detects generic financial fraud infrastructure — drop zones, redirect chains, staging hosts"
        author      = "MiniFW-AI"
        pci_dss     = "Requirement 11.5 — Deploy intrusion-detection mechanisms"

    strings:
        // Generic fraud drop and redirect infrastructure
        $fraud_drop     = "fraud-drop"              nocase
        $fraud_gate     = "fraud-gate"              nocase
        $fraud_relay    = "fraud-relay"             nocase
        $fin_drop       = "fin-drop"                nocase

        // Money mule / money laundering infrastructure
        $mule_drop      = "mule-drop"               nocase
        $launder_gate   = "launder-gate"            nocase
        $aml_bypass     = "aml-bypass"              nocase

        // Ransomware targeting financial institutions
        $fin_ransom     = "fin-ransom"              nocase
        $bank_ransom    = "bank-ransom"             nocase
        $lockbit_fin    = "lockbit"                 nocase
        $blackcat_fin   = "blackcat"                nocase
        $conti_fin      = "conti-fin"               nocase

        // Market manipulation / trading attack infrastructure
        $market_manip   = "market-manip"            nocase
        $algo_inject    = "algo-inject"             nocase
        $hft_spoof      = "hft-spoof"               nocase
        $order_spoof    = "order-spoof"             nocase

        // Regulatory evasion patterns
        $kyc_bypass     = "kyc-bypass"              nocase
        $fatf_evade     = "fatf-evade"              nocase
        $ofac_bypass    = "ofac-bypass"             nocase

    condition:
        any of them
}
