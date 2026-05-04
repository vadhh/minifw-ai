rule GovAptC2
{
    meta:
        category    = "gov_apt_c2"
        severity    = "critical"
        description = "Detects APT C2 beacons and state-sponsored exfiltration infrastructure"
        author      = "MiniFW-AI"

    strings:
        $a1 = "apt28-c2"           nocase
        $a2 = "sovereign-exfil"    nocase
        $a3 = "cozy-bear"          nocase
        $a4 = "fancy-bear"         nocase
        $a5 = "apt29"              nocase

    condition:
        any of them
}

rule GovTorRelay
{
    meta:
        category    = "gov_tor_relay"
        severity    = "critical"
        description = "Detects Tor exit relay access from government networks — anonymisation violates sovereignty policy"
        author      = "MiniFW-AI"

    strings:
        $t1 = "tor-state-relay"    nocase
        $t2 = "onion-gw"           nocase
        $t3 = "tor-exit"           nocase
        $t4 = ".onion."            nocase

    condition:
        any of them
}

rule GovDataLeak
{
    meta:
        category    = "gov_data_leak"
        severity    = "critical"
        description = "Detects access to government document leak infrastructure"
        author      = "MiniFW-AI"

    strings:
        $d1 = "govdocs-leak"       nocase
        $d2 = "sovereign-dump"     nocase
        $d3 = "classified-drop"    nocase

    condition:
        any of them
}

rule GovPhishingPortal
{
    meta:
        category    = "gov_phishing"
        severity    = "high"
        description = "Detects phishing pages mimicking government login portals"
        author      = "MiniFW-AI"

    strings:
        $p1 = "gov-login-verify"   nocase
        $p2 = "portal-update.net"  nocase
        $p3 = "official-gov-auth"  nocase

    condition:
        any of them
}
