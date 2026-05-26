rule LegalRansomwareC2
{
    meta:
        category    = "legal_ransomware_c2"
        severity    = "critical"
        description = "Detects ransomware C2 beacons targeting legal document management systems"
        author      = "MiniFW-AI"

    strings:
        $r1 = "clio-encrypt"      nocase
        $r2 = "lexisnexis-ransom" nocase
        $r3 = "case-mgmt-c2"      nocase
        $r4 = "ransomware-legal"  nocase

    condition:
        any of them
}

rule LegalDataExfiltration
{
    meta:
        category    = "legal_data_exfiltration"
        severity    = "high"
        description = "Detects unauthorized cloud upload and exfiltration of case files"
        author      = "MiniFW-AI"

    strings:
        $e1 = "gdrive-exfil"   nocase
        $e2 = "onedrive-leak"  nocase
        $e3 = "case-upload.io" nocase
        $e4 = "dropbox-case"   nocase

    condition:
        any of them
}

rule LegalPrivilegeViolation
{
    meta:
        category    = "legal_privilege_violation"
        severity    = "critical"
        description = "Detects attorney-client privilege breach and opposing counsel data harvesting"
        author      = "MiniFW-AI"

    strings:
        $p1 = "opposing-counsel.harvest" nocase
        $p2 = "case-data.darkweb"        nocase
        $p3 = "privilege-breach"         nocase
        $p4 = "client-data.dump"         nocase

    condition:
        any of them
}

rule LegalTorExitRelay
{
    meta:
        category    = "legal_tor_exit"
        severity    = "high"
        description = "Detects Tor exit relay queries from client meeting rooms and guest subnets"
        author      = "MiniFW-AI"

    strings:
        $t1 = "tor-exit-relay" nocase
        $t2 = "onion-gw"       nocase
        $t3 = ".onion-"        nocase

    condition:
        any of them
}
