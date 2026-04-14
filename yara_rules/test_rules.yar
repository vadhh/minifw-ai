/*
  MiniFW-AI bundled YARA rules — test and baseline detection set.

  Categories:
    gambling   — Online gambling / illegal betting site keywords (ID-market focus)
    malware    — Common malware execution patterns
    api_abuse  — Web injection and directory traversal patterns

  These rules are intentionally broad for CI testing. Production deployments
  should extend with sector-specific rule sets via MINIFW_YARA_RULES.
*/

rule GamblingKeywords
{
    meta:
        category    = "gambling"
        severity    = "high"
        description = "Detects online gambling and illegal betting site keywords"
        author      = "MiniFW-AI"

    strings:
        $slot_gacor   = "slot gacor"   nocase
        $togel        = "togel"        nocase
        $casino       = "casino"       nocase
        $poker_online = "poker online" nocase
        $judi_online  = "judi online"  nocase
        $bandar_bola  = "bandar bola"  nocase

    condition:
        any of them
}

rule MalwarePatterns
{
    meta:
        category    = "malware"
        severity    = "critical"
        description = "Detects common malware command execution and webshell patterns"
        author      = "MiniFW-AI"

    strings:
        $ps_enc    = "powershell -enc"   nocase
        $webshell  = "eval($_POST"       nocase
        $revshell  = "/dev/tcp/"
        $mshta     = "mshta http"        nocase
        $certutil  = "certutil -decode"  nocase

    condition:
        any of them
}

rule ApiAbuse
{
    meta:
        category    = "api_abuse"
        severity    = "high"
        description = "Detects SQL injection, XSS, and path traversal attempts"
        author      = "MiniFW-AI"

    strings:
        $sqli_classic   = "' OR 1=1"           nocase
        $sqli_union     = "UNION SELECT"        nocase
        $xss_script     = "<script>"            nocase
        $path_traversal = "../../etc/passwd"

    condition:
        any of them
}
