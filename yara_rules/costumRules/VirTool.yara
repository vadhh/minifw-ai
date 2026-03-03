rule VirTool_Java_Donk_ldr {
    meta:
        description = "Detects VirTool:Java/Donk!ldr"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Donk"
        $s2 = { 64 6F 6E 6B 6C 6F 61 64 65 72 20 63 6C 61 73 73 }
        $s3 = "JavaLoader" nocase

    condition:
        (any of ($s*))
}

rule VirTool_Java_Meterpreter_A {
    meta:
        description = "Detects VirTool:Java/Meterpreter.A"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Meterpreter"
        $s2 = { 4D 65 74 65 72 70 72 65 74 65 72 20 63 6C 61 73 73 }
        $s3 = "JavaMeterpreter" nocase

    condition:
        (any of ($s*))
}

rule VirTool_Java_Meterpreter_A_MTB {
    meta:
        description = "Detects VirTool:Java/Meterpreter.A!MTB"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Meterpreter"
        $s2 = { 6A 61 76 61 2E 6D 65 74 65 72 70 72 65 74 65 72 2E 63 6C 61 73 73 }
        $s3 = "JavaMeterpreterMTB" nocase

    condition:
        (any of ($s*))
}

rule VirTool_MSIL_ClozFlitr_A_MTB {
    meta:
        description = "Detects VirTool:MSIL/ClozFlitr.A!MTB"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "ClozFlitr"
        $s2 = { 43 6C 6F 7A 46 6C 69 74 72 2E 41 20 63 6C 61 73 73 }
        $s3 = "MSILClozFlitrMTB" nocase

    condition:
        (uint16(0) == 0x4D5A) and (any of ($s*))
}

rule VirTool_Perl_BahAtt {
    meta:
        description = "Detects VirTool:Perl/BahAtt"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "BahAtt"
        $s2 = { 24 62 61 68 61 74 74 3D 27 68 74 74 70 3A 2F 2F }
        $s3 = "PerlBahAtt" nocase

    condition:
        (any of ($s*))
}

rule VirTool_PHP_Meterpreter_A_MTB {
    meta:
        description = "Detects VirTool:PHP/Meterpreter.A!MTB"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Meterpreter"
        $s2 = { 24 6D 65 74 65 72 70 72 65 74 65 72 3D 27 68 74 74 70 3A 2F 2F }
        $s3 = "PHP_MeterpreterMTB" nocase

    condition:
        (any of ($s*))
}

rule VirTool_PHP_Meterpreter_B {
    meta:
        description = "Detects VirTool:PHP/Meterpreter.B"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Meterpreter"
        $s2 = { 24 6D 65 74 65 72 70 72 65 74 65 72 3D 27 68 74 74 70 3A 2F 2F 77 77 77 }
        $s3 = "PHP_MeterpreterB" nocase

    condition:
        (any of ($s*))
}

rule VirTool_PHP_MetSrv_A_MTB {
    meta:
        description = "Detects VirTool:PHP/MetSrv.A!MTB"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "MetSrv"
        $s2 = { 24 6D 65 74 73 72 76 3D 27 68 74 74 70 3A 2F 2F }
        $s3 = "PHP_MetSrvMTB" nocase

    condition:
        (any of ($s*))
}

rule VirTool_PowerShell_Audicious_A_MTB {
    meta:
        description = "Detects VirTool:PowerShell/Audicious.A!MTB"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Audicious"
        $s2 = { 24 61 75 64 69 63 69 6F 75 73 3D 47 65 74 2D 43 6F 6E 74 65 6E 74 }
        $s3 = "PowerShellAudiciousMTB" nocase

    condition:
        (any of ($s*))
}

rule VirTool_PowerShell_Etiquee_A_MTB {
    meta:
        description = "Detects VirTool:PowerShell/Etiquee.A!MTB"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Etiquee"
        $s2 = { 24 65 74 69 71 75 65 65 3D 47 65 74 2D 43 6F 6E 74 65 6E 74 }
        $s3 = "PowerShellEtiqueeMTB" nocase

    condition:
        (any of ($s*))
}

rule VirTool_PowerShell_Shrewd_A_MTB {
    meta:
        description = "Detects VirTool:PowerShell/Shrewd.A!MTB"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Shrewd"
        $s2 = { 24 73 68 72 65 77 64 3D 47 65 74 2D 43 6F 6E 74 65 6E 74 }
        $s3 = "PowerShellShrewdMTB" nocase

    condition:
        (any of ($s*))
}

rule VirTool_Python_MetSrv_A_MTB {
    meta:
        description = "Detects VirTool:Python/MetSrv.A!MTB"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "MetSrv"
        $s2 = { 6D 65 74 73 72 76 3D 27 68 74 74 70 3A 2F 2F }
        $s3 = "PythonMetSrvMTB" nocase

    condition:
        (any of ($s*))
}

rule VirTool_SWF_Injector {
    meta:
        description = "Detects VirTool:SWF/Injector"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Injector"
        $s2 = { 69 6E 6A 65 63 74 6F 72 20 73 77 66 }
        $s3 = "SWFInjector" nocase

    condition:
        (any of ($s*))
}

rule VirTool_Win32_Cathar_A_MTB {
    meta:
        description = "Detects VirTool:Win32/Cathar.A!MTB"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Cathar"
        $s2 = { 63 61 74 68 61 72 2E 61 20 63 6C 61 73 73 }
        $s3 = "Win32CatharAMTB" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule VirTool_Win32_Cathar_B_MTB {
    meta:
        description = "Detects VirTool:Win32/Cathar.B!MTB"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Cathar"
        $s2 = { 63 61 74 68 61 72 2E 62 20 63 6C 61 73 73 }
        $s3 = "Win32CatharBMTB" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule VirTool_Win32_CobaltStrike_A {
    meta:
        description = "Detects VirTool:Win32/CobaltStrike.A"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "CobaltStrike"
        $s2 = { 43 6F 62 61 6C 74 53 74 72 69 6B 65 2E 41 }
        $s3 = "Win32CobaltStrike" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule VirTool_Win32_Harpederping_A_MTB {
    meta:
        description = "Detects VirTool:Win32/Harpederping.A!MTB"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Harpederping"
        $s2 = { 68 61 72 70 65 64 65 72 70 69 6E 67 2E 61 }
        $s3 = "Win32HarpederpingMTB" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule VirTool_Win32_Inoculate_A {
    meta:
        description = "Detects VirTool:Win32/Inoculate.A"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Inoculate"
        $s2 = { 49 6E 6F 63 75 6C 61 74 65 2E 41 }
        $s3 = "Win32InoculateA" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule VirTool_Win32_KernelMemMod {
    meta:
        description = "Detects VirTool:Win32/KernelMemMod"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "KernelMemMod"
        $s2 = { 4B 65 72 6E 65 6C 4D 65 6D 4D 6F 64 }
        $s3 = "Win32KernelMemMod" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule VirTool_Win32_Meterpreter {
    meta:
        description = "Detects VirTool:Win32/Meterpreter"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Meterpreter"
        $s2 = { 4D 65 74 65 72 70 72 65 74 65 72 20 63 6C 61 73 73 }
        $s3 = "Win32Meterpreter" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule VirTool_Win32_Tabloid_MTB {
    meta:
        description = "Detects VirTool:Win32/Tabloid!MTB"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Tabloid"
        $s2 = { 54 61 62 6C 6F 69 64 21 4D 54 42 }
        $s3 = "Win32TabloidMTB" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule VirTool_Win32_Tabloid_MTB_V1 {
    meta:
        description = "Detects VirTool:Win32/Tabloid!MTB"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Tabloid"
        $s2 = { 54 61 62 6C 6F 69 64 21 4D 54 42 }
        $s3 = "Win32TabloidMTB" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule Virus_DOS_EICAR_Test_File {
    meta:
        description = "Detects Virus:DOS/EICAR_Test_File"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $eicar_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        $eicar_hex = { 58 35 4F 21 50 25 40 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24 45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 21 24 48 2B 48 2A }

    condition:
        any of ($*)
}

rule Virus_VBS_Inor_E_gen {
    meta:
        description = "Detects Virus:VBS/Inor.E.gen"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "VBS/Inor"
        $s2 = { 56 42 53 2F 49 6E 6F 72 2E 45 2E 67 65 6E }
        $s3 = "VBSInorEgen" nocase

    condition:
        (any of ($s*))
}