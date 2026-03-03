rule Trojan_MacOS_Empyre_A_MTB
{
    meta:
        description = "Detects Trojan:MacOS/Empyre.A!MTB"
        author = "YourName"
        date = "2024-07-06"
        hash = "Optional hash of a known sample"

    strings:
        $s1 = "empire_string_1" // Example: "empire_auth_token"
        $s2 = "empire_string_2" // Example: "empire_url"
        $s3 = { 6A 52 68 33 5C 00 00 } // Example byte pattern

    condition:
        any of them
}

rule Trojan_MacOS_Empyre_B_MTB
{
    meta:
        description = "Detects Trojan:MacOS/Empyre.B!MTB"
        author = "YourName"
        date = "2024-07-06"
        hash = "Optional hash of a known sample"

    strings:
        $s1 = "empire_b_string_1" // Example: "empire_b_auth_token"
        $s2 = "empire_b_string_2" // Example: "empire_b_url"
        $s3 = { 8A 23 67 45 12 00 00 } // Example byte pattern

    condition:
        any of them
}

rule Trojan_MacOS_Empyre_D_MTB
{
    meta:
        description = "Detects Trojan:MacOS/Empyre.D!MTB"
        author = "YourName"
        date = "2024-07-06"
        hash = "Optional hash of a known sample"

    strings:
        $s1 = "empire_d_string_1" // Example: "empire_d_auth_token"
        $s2 = "empire_d_string_2" // Example: "empire_d_url"
        $s3 = { 9C 45 34 67 89 00 00 } // Example byte pattern

    condition:
        any of them
}

rule Trojan_MacOS_Empyre_E_MTB
{
    meta:
        description = "Detects Trojan:MacOS/Empyre.E!MTB"
        author = "YourName"
        date = "2024-07-06"
        hash = "Optional hash of a known sample"

    strings:
        $s1 = "empire_e_string_1" // Example: "empire_e_auth_token"
        $s2 = "empire_e_string_2" // Example: "empire_e_url"
        $s3 = { 4B 67 89 12 34 00 00 } // Example byte pattern

    condition:
        any of them
}

rule Trojan_MacOS_Getshell
{
    meta:
        description = "Detects Trojan:MacOS/Getshell"
        author = "YourName"
        date = "2024-07-06"
        hash = "Optional hash of a known sample"

    strings:
        $s1 = "getshell_string_1" // Example: "shell_cmd"
        $s2 = "getshell_string_2" // Example: "shell_exec"
        $s3 = { 6B 23 45 67 89 00 00 } // Example byte pattern

    condition:
        any of them
}

rule Trojan_MacOS_Mettle_A_MTB
{
    meta:
        description = "Detects Trojan:MacOS/Mettle.A!MTB"
        author = "YourName"
        date = "2024-07-06"
        hash = "Optional hash of a known sample"

    strings:
        $s1 = "mettle_string_1" // Example: "mettle_cmd"
        $s2 = "mettle_string_2" // Example: "mettle_exec"
        $s3 = { 7C 34 56 78 90 00 00 } // Example byte pattern

    condition:
        any of them
}

rule Trojan_MacOS_Rakkotonak_A
{
    meta:
        description = "Detects Trojan:MacOS/Rakkotonak.A"
        author = "YourName"
        date = "2024-07-06"
        hash = "Optional hash of a known sample"

    strings:
        $s1 = "rakkotonak_string_1" // Example: "rakkotonak_cmd"
        $s2 = "rakkotonak_string_2" // Example: "rakkotonak_exec"
        $s3 = { 8D 45 67 89 01 00 00 } // Example byte pattern

    condition:
        any of them
}

rule Trojan_MacOS_Shemala_A
{
    meta:
        description = "Detects Trojan:MacOS/Shemala.A"
        author = "YourName"
        date = "2024-07-06"
        hash = "Optional hash of a known sample"

    strings:
        $s1 = "shemala_string_1" // Example: "shemala_cmd"
        $s2 = "shemala_string_2" // Example: "shemala_exec"
        $s3 = { 9E 56 78 90 12 00 00 } // Example byte pattern

    condition:
        any of them
}

rule Trojan_MacOS_X_Getshell
{
    meta:
        description = "Detects Trojan:MacOS_X/Getshell"
        author = "YourName"
        date = "2024-07-06"
        hash = "Optional hash of a known sample"

    strings:
        $s1 = "getshell_x_string_1" // Example: "shell_cmd_x"
        $s2 = "getshell_x_string_2" // Example: "shell_exec_x"
        $s3 = { 6F 12 34 56 78 00 00 } // Example byte pattern

    condition:
        any of them
}

rule Trojan_MSIL_Rozena_HNF_MTB
{
    meta:
        description = "Detects Trojan:MSIL/Rozena.HNF!MTB"
        author = "YourName"
        date = "2024-07-06"
        hash = "Optional hash of a known sample"

    strings:
        $s1 = "rozena_string_1" // Example: "rozena_cmd"
        $s2 = "rozena_string_2" // Example: "rozena_exec"
        $s3 = { 7F 23 45 67 89 00 00 } // Example byte pattern

    condition:
        any of them
}

rule Trojan_Perl_ExploitTracesR
{
    meta:
        description = "Detects Trojan:Perl/ExploitTracesR"
        author = "YourName"
        date = "2024-07-06"
        hash = "Optional hash of a known sample"

    strings:
        $s1 = "perl_exploit_string_1" // Example: "exploit_cmd"
        $s2 = "perl_exploit_string_2" // Example: "exploit_exec"
        $s3 = { 8F 45 67 89 12 00 00 } // Example byte pattern

    condition:
        any of them
}

rule Trojan_PHP_RevWebshell_YA_MTB
{
    meta:
        description = "Detects Trojan:PHP/RevWebshell.YA!MTB"
        author = "YourName"
        date = "2024-07-06"
        hash = "Optional hash of a known sample"

    strings:
        $s1 = "php_webshell_string_1" // Example: "webshell_cmd"
        $s2 = "php_webshell_string_2" // Example: "webshell_exec"
        $s3 = { 9F 56 78 90 12 00 00 } // Example byte pattern

    condition:
        any of them
}