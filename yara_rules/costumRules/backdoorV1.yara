rule Backdoor_ASP_WebShell {
    meta:
        description = "Detects Backdoor:ASP/WebShell"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "webshell"
        $s2 = { 77 65 62 73 68 65 6C 6C }
        $s3 = "<%="
        $s4 = "Request.Form"

    condition:
        (filesize < 100KB) and any of ($s*)
}

rule Backdoor_ASP_Yorcirekrikseng_A {
    meta:
        description = "Detects Backdoor:ASP/Yorcirekrikseng.A"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Yorcirekrikseng"
        $s2 = { 59 6F 72 63 69 72 65 6B 72 69 6B 73 65 6E 67 }
        $s3 = "cmd.exe"
        $s4 = "ExecuteGlobal"

    condition:
        (filesize < 100KB) and any of ($s*)
}

rule Backdoor_HTML_WebShell {
    meta:
        description = "Detects Backdoor:HTML/WebShell"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "webshell"
        $s2 = { 77 65 62 73 68 65 6C 6C }
        $s3 = "<script>"
        $s4 = "eval(String.fromCharCode"

    condition:
        (filesize < 100KB) and any of ($s*)
}

rule Backdoor_Java_Meterpreter {
    meta:
        description = "Detects Backdoor:Java/Meterpreter"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Meterpreter"
        $s2 = { 4D 65 74 65 72 70 72 65 74 65 72 }
        $s3 = "Payload"
        $s4 = "import metasploit"

    condition:
        (filesize < 200KB) and any of ($s*)
}

rule Backdoor_JS_Dirtelti_MTR {
    meta:
        description = "Detects Backdoor:JS/Dirtelti.MTR"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Dirtelti"
        $s2 = { 44 69 72 74 65 6C 74 69 }
        $s3 = "eval"
        $s4 = "XMLHttpRequest"

    condition:
        (filesize < 100KB) and any of ($s*)
}

rule Backdoor_JS_Relvelshe_A {
    meta:
        description = "Detects Backdoor:JS/Relvelshe.A"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Relvelshe"
        $s2 = { 52 65 6C 76 65 6C 73 68 65 }
        $s3 = "new Function"
        $s4 = "window.location"

    condition:
        (filesize < 100KB) and any of ($s*)
}

rule Backdoor_Linux_Dakkotoni_A_MTB {
    meta:
        description = "Detects Backdoor:Linux/Dakkotoni.A!MTB"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Dakkotoni"
        $s2 = { 44 61 6B 6B 6F 74 6F 6E 69 }
        $s3 = "/bin/sh"
        $s4 = "/usr/bin/perl"

    condition:
        (filesize < 200KB) and any of ($s*)
}

rule Backdoor_Linux_Dakkotoni_az_MTB {
    meta:
        description = "Detects Backdoor:Linux/Dakkotoni.az!MTB"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Dakkotoni"
        $s2 = { 44 61 6B 6B 6F 74 6F 6E 69 }
        $s3 = "/bin/bash"
        $s4 = "/usr/bin/python"

    condition:
        (filesize < 200KB) and any of ($s*)
}

rule Backdoor_Linux_SambaShell_A_MTB {
    meta:
        description = "Detects Backdoor:Linux/SambaShell.A!MTB"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "SambaShell"
        $s2 = { 53 61 6D 62 61 53 68 65 6C 6C }
        $s3 = "/etc/samba"
        $s4 = "/usr/sbin/smbd"

    condition:
        (filesize < 200KB) and any of ($s*)
}

rule Backdoor_MacOS_Emprye_C_MTB {
    meta:
        description = "Detects Backdoor:MacOS/Emprye.C!MTB"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Emprye"
        $s2 = { 45 6D 70 72 79 65 }
        $s3 = "/usr/bin/osascript"
        $s4 = "/System/Library/"

    condition:
        (filesize < 200KB) and any of ($s*)
}