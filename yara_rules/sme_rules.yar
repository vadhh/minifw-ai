/*
  MiniFW-AI establishment sector YARA rules (SME/Retail).

  Categories:
    sme_ransomware     — Generic ransomware families commonly targeting SMEs
                         (Locky, WannaCry, Cerber, Dharma, STOP/DJVU)
    sme_cryptominer    — Cryptomining pool beacons and miner process patterns
    sme_credential     — Credential theft tools and dump patterns
                         (Mimikatz, LaZagne, credential spray indicators)

  All rules scan the DNS query domain + SNI field concatenated as UTF-8 bytes,
  identical to how hospital_rules.yar works.  Strings are chosen to match the
  demo injector domains while being realistic enough for training demos.

  Severity levels: high, medium
*/

rule SmeRansomware
{
    meta:
        category    = "sme_ransomware"
        severity    = "high"
        description = "Detects ransomware families commonly targeting SME and retail environments"
        author      = "MiniFW-AI"

    strings:
        // Locky ransomware — domain used as demo trigger
        $locky          = "Locky"                               nocase

        // WannaCry / WannaCrypt
        $wannacry       = "WannaCry"                            nocase
        $wannacrypt     = "WannaCrypt"                          nocase
        $wcrypt_ext     = ".WCRYPT"

        // Cerber ransomware
        $cerber         = "Cerber"                              nocase
        $cerber_ext     = ".cerber"

        // Dharma / CrySiS family
        $dharma         = "dharma"                              nocase
        $crysis         = "crysis"                              nocase

        // STOP/DJVU — most common SME ransomware
        $djvu_note      = "readme_restore"                      nocase
        $stop_note      = "_openme.txt"                         nocase

        // Generic decryption demand strings
        $decrypt_note   = "decrypt-files"                       nocase
        $ransom_demand  = "ransom-payment"                      nocase
        $pay_btc        = "pay-bitcoin"                         nocase

    condition:
        any of them
}

rule SmeCryptoMiner
{
    meta:
        category    = "sme_cryptominer"
        severity    = "medium"
        description = "Detects cryptomining pool beacons and miner C2 patterns"
        author      = "MiniFW-AI"

    strings:
        // XMRig miner — domain used as demo trigger
        $xmrig          = "xmrig"                               nocase

        // Common Monero pool hostnames
        $xmr_pool       = "xmr-pool"                            nocase
        $crypto_mine    = "crypto-mine"                         nocase
        $monero_pool    = "monero-pool"                         nocase

        // Coinhive / CryptoLoot (browser miners)
        $coinhive       = "coinhive"                            nocase
        $cryptoloot     = "cryptoloot"                          nocase
        $minero         = "minero.pw"                           nocase

        // Stratum protocol indicators in DNS
        $stratum        = "stratum+"                            nocase
        $pool_mine      = "pool.mine"                           nocase

    condition:
        any of them
}

rule SmeCredentialTheft
{
    meta:
        category    = "sme_credential"
        severity    = "high"
        description = "Detects credential theft tool signatures and exfiltration staging domains"
        author      = "MiniFW-AI"

    strings:
        // Mimikatz
        $mimikatz       = "mimikatz"                            nocase
        $sekurlsa       = "sekurlsa"                            nocase
        $lsadump        = "lsadump"                             nocase

        // LaZagne credential dumper
        $lazagne        = "lazagne"                             nocase

        // Generic credential exfil staging patterns in DNS hostnames
        $cred_dump      = "cred-dump"                           nocase
        $hash_dump      = "hashdump"                            nocase
        $passwd_exfil   = "passwd-exfil"                        nocase

    condition:
        any of them
}
