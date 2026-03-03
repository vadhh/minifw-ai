rule HackTool_Win32_RemoteAdmin_MSR {
    meta:
        description = "Detects HackTool:Win32/RemoteAdmin!MSR"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "RemoteAdmin"
        $string2 = "AdminTool"
        $string3 = "RemoteControl"
    condition:
        any of them
}

rule HackTool_Win32_Sqlinject_A {
    meta:
        description = "Detects HackTool:Win32/Sqlinject.A"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "SQL Injection"
        $string2 = "sqlmap"
        $string3 = "inject"
    condition:
        any of them
}

rule HackTool_Win32_SQLShell_MSR {
    meta:
        description = "Detects HackTool:Win32/SQLShell!MSR"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "SQLShell"
        $string2 = "SQLcmd"
        $string3 = "DBShell"
    condition:
        any of them
}

rule HackTool_Win32_Wincred_H {
    meta:
        description = "Detects HackTool:Win32/Wincred.H"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Wincred"
        $string2 = "CredentialDump"
        $string3 = "Win32_Credential"
    condition:
        any of them
}

rule HackTool_Win64_AutoKMS {
    meta:
        description = "Detects HackTool:Win64/AutoKMS"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "AutoKMS"
        $string2 = "KMS Activation"
        $string3 = "AutoKMS.exe"
    condition:
        any of them
}

rule HackTool_Win64_Fgdump {
    meta:
        description = "Detects HackTool:Win64/Fgdump"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "fgdump"
        $string2 = "password dump"
        $string3 = "fgdump.exe"
    condition:
        any of them
}

rule HackTool_Win64_Juicypotato {
    meta:
        description = "Detects HackTool:Win64/Juicypotato"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "JuicyPotato"
        $string2 = "COM Object"
        $string3 = "Potato exploit"
    condition:
        any of them
}

rule HackTool_Win64_Meterpreter_MSR {
    meta:
        description = "Detects HackTool:Win64/Meterpreter!MSR"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Meterpreter"
        $string2 = "payload"
        $string3 = "met.dll"
    condition:
        any of them
}

rule HackTool_Win64_Meterpreter_A_dll {
    meta:
        description = "Detects HackTool:Win64/Meterpreter.A!dll"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Meterpreter"
        $string2 = "payload"
        $string3 = "meterpreter.dll"
    condition:
        any of them
}

rule HackTool_Win64_UACMe_pz {
    meta:
        description = "Detects HackTool:Win64/UACMe!pz"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "UACMe"
        $string2 = "UAC bypass"
        $string3 = "UACMe.exe"
    condition:
        any of them
}

rule HackTool_Win32_Mikatz {
    meta:
        description = "Detects HackTool:Win32/Mikatz"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Mikatz"
        $string2 = "password dump"
        $string3 = "Mikatz.exe"
    condition:
        any of them
}

rule HackTool_Win32_Mikatz_dha {
    meta:
        description = "Detects HackTool:Win32/Mikatz!dha"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Mikatz"
        $string2 = "credential theft"
        $string3 = "Mikatz!dha"
    condition:
        any of them
}

rule HackTool_Win32_Mimikatz {
    meta:
        description = "Detects HackTool:Win32/Mimikatz"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Mimikatz"
        $string2 = "password dump"
        $string3 = "Mimikatz.exe"
    condition:
        any of them
}

rule HackTool_Win32_Mimikatz_pc {
    meta:
        description = "Detects HackTool:Win32/Mimikatz!pc"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Mimikatz"
        $string2 = "credential theft"
        $string3 = "Mimikatz!pc"
    condition:
        any of them
}

rule HackTool_Win32_Mimikatz_D {
    meta:
        description = "Detects HackTool:Win32/Mimikatz.D"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Mimikatz"
        $string2 = "credential dump"
        $string3 = "Mimikatz.D"
    condition:
        any of them
}

rule HackTool_Win32_Netcat {
    meta:
        description = "Detects HackTool:Win32/Netcat"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Netcat"
        $string2 = "nc.exe"
        $string3 = "network tool"
    condition:
        any of them
}

rule HackTool_Win32_Netcat_MSR {
    meta:
        description = "Detects HackTool:Win32/Netcat!MSR"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Netcat"
        $string2 = "nc.exe"
        $string3 = "Netcat!MSR"
    condition:
        any of them
}

rule HackTool_Win32_PowerSploit_A {
    meta:
        description = "Detects HackTool:Win32/PowerSploit.A"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "PowerSploit"
        $string2 = "PowerShell exploitation"
        $string3 = "PowerSploit.ps1"
    condition:
        any of them
}

rule HackTool_Win32_PowerSploitHijack_A_dll {
    meta:
        description = "Detects HackTool:Win32/PowersploitHijack.A!dll"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "PowerSploit"
        $string2 = "PowerShell hijack"
        $string3 = "PowersploitHijack.dll"
    condition:
        any of them
}

rule HackTool_Win32_PWDump_C {
    meta:
        description = "Detects HackTool:Win32/PWDump.C"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "PWDump"
        $string2 = "password dump"
        $string3 = "PWDump.C"
    condition:
        any of them
}

rule HackTool_Win32_Keygen {
    meta:
        description = "Detects HackTool:Win32/Keygen"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "keygen"
        $string2 = "key generator"
        $string3 = "crack"
    condition:
        any of them
}

rule HackTool_Win32_Kitrap_A {
    meta:
        description = "Detects HackTool:Win32/Kitrap.A"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Kitrap"
        $string2 = "exploit"
        $string3 = "Kitrap.A"
    condition:
        any of them
}

rule HackTool_Win32_LSADump_dha {
    meta:
        description = "Detects HackTool:Win32/LSADump!dha"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "LSADump"
        $string2 = "LSA Secrets"
        $string3 = "LSADump!dha"
    condition:
        any of them
}

rule HackTool_Win32_Malgent_MSR {
    meta:
        description = "Detects HackTool:Win32/Malgent!MSR"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Malgent"
        $string2 = "malicious agent"
        $string3 = "Malgent!MSR"
    condition:
        any of them
}

rule HackTool_Win32_Meterpreter {
    meta:
        description = "Detects HackTool:Win32/Meterpreter"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Meterpreter"
        $string2 = "payload"
        $string3 = "met.dll"
    condition:
        any of them
}

rule HackTool_Win32_Meterpreter_dll {
    meta:
        description = "Detects HackTool:Win32/Meterpreter!dll"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Meterpreter"
        $string2 = "payload"
        $string3 = "meterpreter.dll"
    condition:
        any of them
}

rule HackTool_Win32_Meterpreter_MSR {
    meta:
        description = "Detects HackTool:Win32/Meterpreter!MSR"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Meterpreter"
        $string2 = "payload"
        $string3 = "Meterpreter!MSR"
    condition:
        any of them
}

rule HackTool_Win32_Meterpreter_pz {
    meta:
        description = "Detects HackTool:Win32/Meterpreter!pz"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Meterpreter"
        $string2 = "payload"
        $string3 = "Meterpreter!pz"
    condition:
        any of them
}

rule HackTool_Win32_Meterpreter_A {
    meta:
        description = "Detects HackTool:Win32/Meterpreter.A"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Meterpreter"
        $string2 = "payload"
        $string3 = "Meterpreter.A"
    condition:
        any of them
}

rule HackTool_Win32_Meterpreter_A_dll {
    meta:
        description = "Detects HackTool:Win32/Meterpreter.A!dll"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Meterpreter"
        $string2 = "payload"
        $string3 = "Meterpreter.A.dll"
    condition:
        any of them
}

rule HackTool_Python_TalkBack_B_MTB {
    meta:
        description = "Detects HackTool:Python/TalkBack.B!MTB"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "TalkBack"
        $string2 = "reverse shell"
        $string3 = "TalkBack.B"
    condition:
        any of them
}

rule HackTool_Python_WeevelyShellR_MTB {
    meta:
        description = "Detects HackTool:Python/WeevelyShellR!MTB"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Weevely"
        $string2 = "remote shell"
        $string3 = "WeevelyShellR"
    condition:
        any of them
}

rule HackTool_Python_WeevelyShellRC_MTB {
    meta:
        description = "Detects HackTool:Python/WeevelyShellRC!MTB"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Weevely"
        $string2 = "remote command"
        $string3 = "WeevelyShellRC"
    condition:
        any of them
}

rule HackTool_Win32_Agent {
    meta:
        description = "Detects HackTool:Win32/Agent"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Agent"
        $string2 = "malicious agent"
        $string3 = "Win32_Agent"
    condition:
        any of them
}

rule HackTool_Win32_AutoKMS {
    meta:
        description = "Detects HackTool:Win32/AutoKMS"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "AutoKMS"
        $string2 = "KMS Activation"
        $string3 = "AutoKMS.exe"
    condition:
        any of them
}

rule HackTool_Win32_Elavate_B {
    meta:
        description = "Detects HackTool:Win32/Elavate.B"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Elavate"
        $string2 = "privilege escalation"
        $string3 = "Elavate.B"
    condition:
        any of them
}

rule HackTool_Win32_Fgdump {
    meta:
        description = "Detects HackTool:Win32/Fgdump"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "fgdump"
        $string2 = "password dump"
        $string3 = "fgdump.exe"
    condition:
        any of them
}

rule HackTool_Win32_Gsecdump {
    meta:
        description = "Detects HackTool:Win32/Gsecdump"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "gsecdump"
        $string2 = "password dump"
        $string3 = "gsecdump.exe"
    condition:
        any of them
}

rule HackTool_Win32_Incognito {
    meta:
        description = "Detects HackTool:Win32/Incognito"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Incognito"
        $string2 = "token manipulation"
        $string3 = "Incognito.exe"
    condition:
        any of them
}

rule HackTool_Win32_Injector {
    meta:
        description = "Detects HackTool:Win32/Injector"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Injector"
        $string2 = "code injection"
        $string3 = "Injector.exe"
    condition:
        any of them
}

rule HackTool_Python_Impacket_V {
    meta:
        description = "Detects HackTool:Python/Impacket.V"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Impacket"
        $string2 = "Impacket.V"
        $string3 = "impacket.py"
    condition:
        any of them
}

rule HackTool_Python_Impacket_W {
    meta:
        description = "Detects HackTool:Python/Impacket.W"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Impacket"
        $string2 = "Impacket.W"
        $string3 = "impacket.py"
    condition:
        any of them
}

rule HackTool_Python_Impacket_X {
    meta:
        description = "Detects HackTool:Python/Impacket.X"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Impacket"
        $string2 = "Impacket.X"
        $string3 = "impacket.py"
    condition:
        any of them
}

rule HackTool_Python_Impacket_Y {
    meta:
        description = "Detects HackTool:Python/Impacket.Y"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Impacket"
        $string2 = "Impacket.Y"
        $string3 = "impacket.py"
    condition:
        any of them
}

rule HackTool_Python_Impacket_Z {
    meta:
        description = "Detects HackTool:Python/Impacket.Z"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Impacket"
        $string2 = "Impacket.Z"
        $string3 = "impacket.py"
    condition:
        any of them
}

rule HackTool_Python_Mimipenguin_a_MTB {
    meta:
        description = "Detects HackTool:Python/Mimipenguin.a!MTB"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Mimipenguin"
        $string2 = "credential dump"
        $string3 = "Mimipenguin.a"
    condition:
        any of them
}

rule HackTool_Python_Multiverze {
    meta:
        description = "Detects HackTool:Python/Multiverze"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Multiverze"
        $string2 = "multiverse"
        $string3 = "multiverze.py"
    condition:
        any of them
}

rule HackTool_Python_Sagnt_D_MTB {
    meta:
        description = "Detects HackTool:Python/Sagnt.D!MTB"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Sagnt"
        $string2 = "Sagnt.D"
        $string3 = "Sagnt.py"
    condition:
        any of them
}

rule HackTool_Python_Sagnt_G_MTB {
    meta:
        description = "Detects HackTool:Python/Sagnt.G!MTB"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Sagnt"
        $string2 = "Sagnt.G"
        $string3 = "Sagnt.py"
    condition:
        any of them
}

rule HackTool_Python_Smbexec {
    meta:
        description = "Detects HackTool:Python/Smbexec"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Smbexec"
        $string2 = "smbexec.py"
        $string3 = "SMB execution"
    condition:
        any of them
}

rule HackTool_Python_Impacket_AV {
    meta:
        description = "Detects HackTool:Python/Impacket.AV"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Impacket"
        $string2 = "Impacket.AV"
        $string3 = "impacket"
    condition:
        any of them
}

rule HackTool_Python_Impacket_AW_ping {
    meta:
        description = "Detects HackTool:Python/Impacket.AW!ping"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Impacket"
        $string2 = "Impacket.AW"
        $string3 = "ping"
    condition:
        any of them
}

rule HackTool_Python_Impacket_AY {
    meta:
        description = "Detects HackTool:Python/Impacket.AY"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Impacket"
        $string2 = "Impacket.AY"
        $string3 = "impacket"
    condition:
        any of them
}

rule HackTool_Python_Impacket_AZ {
    meta:
        description = "Detects HackTool:Python/Impacket.AZ"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Impacket"
        $string2 = "Impacket.AZ"
        $string3 = "impacket"
    condition:
        any of them
}

rule HackTool_Python_Impacket_N {
    meta:
        description = "Detects HackTool:Python/Impacket.N"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Impacket"
        $string2 = "Impacket.N"
        $string3 = "impacket"
    condition:
        any of them
}

rule HackTool_Python_Impacket_P {
    meta:
        description = "Detects HackTool:Python/Impacket.P"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Impacket"
        $string2 = "Impacket.P"
        $string3 = "impacket"
    condition:
        any of them
}

rule HackTool_Python_Impacket_Q {
    meta:
        description = "Detects HackTool:Python/Impacket.Q"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Impacket"
        $string2 = "Impacket.Q"
        $string3 = "impacket"
    condition:
        any of them
}

rule HackTool_Python_Impacket_S {
    meta:
        description = "Detects HackTool:Python/Impacket.S"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Impacket"
        $string2 = "Impacket.S"
        $string3 = "impacket"
    condition:
        any of them
}

rule HackTool_Python_Impacket_T {
    meta:
        description = "Detects HackTool:Python/Impacket.T"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Impacket"
        $string2 = "Impacket.T"
        $string3 = "impacket"
    condition:
        any of them
}

rule HackTool_Python_Impacket_U {
    meta:
        description = "Detects HackTool:Python/Impacket.U"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Impacket"
        $string2 = "Impacket.U"
        $string3 = "impacket"
    condition:
        any of them
}

rule HackTool_PowerShell_PowerView_A {
    meta:
        description = "Detects HackTool:PowerShell/PowerView.A"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "PowerView"
        $string2 = "PowerView.ps1"
        $string3 = "PowerView.A"
    condition:
        any of them
}

rule HackTool_PowerShell_PowerView_F {
    meta:
        description = "Detects HackTool:PowerShell/PowerView.F"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "PowerView"
        $string2 = "PowerView.ps1"
        $string3 = "PowerView.F"
    condition:
        any of them
}

rule HackTool_PowerShell_Spritz {
    meta:
        description = "Detects HackTool:PowerShell/Spritz"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Spritz"
        $string2 = "PowerShell script"
        $string3 = "Spritz.ps1"
    condition:
        any of them
}

rule HackTool_Python_Impacket {
    meta:
        description = "Detects HackTool:Python/Impacket"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Impacket"
        $string2 = "impacket"
        $string3 = "python"
    condition:
        any of them
}

rule HackTool_Python_Impacket_MTB {
    meta:
        description = "Detects HackTool:Python/Impacket.!MTB"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Impacket"
        $string2 = "impacket"
        $string3 = "MTB"
    condition:
        any of them
}

rule HackTool_Python_Impacket_AB {
    meta:
        description = "Detects HackTool:Python/Impacket.AB"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Impacket"
        $string2 = "Impacket.AB"
        $string3 = "impacket"
    condition:
        any of them
}

rule HackTool_Python_Impacket_AD {
    meta:
        description = "Detects HackTool:Python/Impacket.AD"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Impacket"
        $string2 = "Impacket.AD"
        $string3 = "impacket"
    condition:
        any of them
}

rule HackTool_Python_Impacket_AM {
    meta:
        description = "Detects HackTool:Python/Impacket.AM"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Impacket"
        $string2 = "Impacket.AM"
        $string3 = "impacket"
    condition:
        any of them
}

rule HackTool_Python_Impacket_AP {
    meta:
        description = "Detects HackTool:Python/Impacket.AP"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Impacket"
        $string2 = "Impacket.AP"
        $string3 = "impacket"
    condition:
        any of them
}

rule HackTool_Python_Impacket_AR {
    meta:
        description = "Detects HackTool:Python/Impacket.AR"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Impacket"
        $string2 = "Impacket.AR"
        $string3 = "impacket"
    condition:
        any of them
}

rule HackTool_PowerShell_Latmov {
    meta:
        description = "Detects HackTool:PowerShell/Latmov"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Latmov"
        $string2 = "lateral movement"
        $string3 = "Latmov.ps1"
    condition:
        any of them
}

rule HackTool_PowerShell_Latmov_AB_MTB {
    meta:
        description = "Detects HackTool:PowerShell/Latmov.AB!MTB"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Latmov"
        $string2 = "lateral movement"
        $string3 = "Latmov.AB"
    condition:
        any of them
}

rule HackTool_PowerShell_Meterpreter {
    meta:
        description = "Detects HackTool:PowerShell/Meterpreter"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Meterpreter"
        $string2 = "reverse shell"
        $string3 = "Meterpreter.ps1"
    condition:
        any of them
}

rule HackTool_PowerShell_Mimikatz_MTB {
    meta:
        description = "Detects HackTool:PowerShell/Mimikatz!MTB"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Mimikatz"
        $string2 = "credential dump"
        $string3 = "Mimikatz.ps1"
    condition:
        any of them
}

rule HackTool_PowerShell_Powerpuff_A {
    meta:
        description = "Detects HackTool:PowerShell/Powerpuff.A"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Powerpuff"
        $string2 = "Powerpuff.A"
        $string3 = "Powerpuff.ps1"
    condition:
        any of them
}

rule HackTool_PowerShell_PowerSploit {
    meta:
        description = "Detects HackTool:PowerShell/PowerSploit"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "PowerSploit"
        $string2 = "PowerSploit.ps1"
        $string3 = "PowerShell exploitation"
    condition:
        any of them
}

rule HackTool_PowerShell_PowerSploit_MTB {
    meta:
        description = "Detects HackTool:PowerShell/PowerSploit!MTB"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "PowerSploit"
        $string2 = "PowerSploit.ps1"
        $string3 = "MTB"
    condition:
        any of them
}

rule HackTool_PowerShell_PowerSploit_E {
    meta:
        description = "Detects HackTool:PowerShell/PowerSploit.E"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "PowerSploit"
        $string2 = "PowerSploit.E"
        $string3 = "PowerSploit.ps1"
    condition:
        any of them
}

rule HackTool_PowerShell_PowerSploit_RL_MTB {
    meta:
        description = "Detects HackTool:PowerShell/PowerSploit.RL!MTB"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "PowerSploit"
        $string2 = "PowerSploit.ps1"
        $string3 = "RL!MTB"
    condition:
        any of them
}

rule HackTool_PowerShell_PowerView {
    meta:
        description = "Detects HackTool:PowerShell/PowerView"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "PowerView"
        $string2 = "PowerView.ps1"
        $string3 = "PowerShell script"
    condition:
        any of them
}

rule HackTool_Perl_NiktoScanner_A {
    meta:
        description = "Detects HackTool:Perl/NiktoScanner.A"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Nikto"
        $string2 = "web server scanner"
        $string3 = "nikto.pl"
    condition:
        any of them
}

rule HackTool_Perl_Smtpd_A {
    meta:
        description = "Detects HackTool:Perl/Smtpd.A"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Smtpd"
        $string2 = "SMTP daemon"
        $string3 = "smtpd.pl"
    condition:
        any of them
}

rule HackTool_PowerShell_MTB {
    meta:
        description = "Detects HackTool:PowerShell!MTB"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "PowerShell"
        $string2 = "PowerShell script"
        $string3 = "MTB"
    condition:
        any of them
}

rule HackTool_PowerShell_BloodHound_G_MSR {
    meta:
        description = "Detects HackTool:PowerShell/BloodHound.G!MSR"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "BloodHound"
        $string2 = "Active Directory"
        $string3 = "BloodHound.ps1"
    condition:
        any of them
}

rule HackTool_PowerShell_EmpireAgent {
    meta:
        description = "Detects HackTool:PowerShell/EmpireAgent"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Empire"
        $string2 = "EmpireAgent"
        $string3 = "Empire.ps1"
    condition:
        any of them
}

rule HackTool_PowerShell_EmpireGetClipboardContents {
    meta:
        description = "Detects HackTool:PowerShell/EmpireGetClipboardContents"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Empire"
        $string2 = "GetClipboardContents"
        $string3 = "Empire.ps1"
    condition:
        any of them
}

rule HackTool_PowerShell_EmpireGetScreenshot_A {
    meta:
        description = "Detects HackTool:PowerShell/EmpireGetScreenshot.A"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Empire"
        $string2 = "GetScreenshot"
        $string3 = "Empire.ps1"
    condition:
        any of them
}

rule HackTool_PowerShell_ExploitEternalBlue {
    meta:
        description = "Detects HackTool:PowerShell/ExploitEternalBlue"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "EternalBlue"
        $string2 = "exploit"
        $string3 = "EternalBlue.ps1"
    condition:
        any of them
}

rule HackTool_PowerShell_Inveigh {
    meta:
        description = "Detects HackTool:PowerShell/Inveigh"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Inveigh"
        $string2 = "PowerShell sniffer"
        $string3 = "Inveigh.ps1"
    condition:
        any of them
}

rule HackTool_PowerShell_KeeThief {
    meta:
        description = "Detects HackTool:PowerShell/KeeThief"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "KeeThief"
        $string2 = "KeePass exploit"
        $string3 = "KeeThief.ps1"
    condition:
        any of them
}

rule HackTool_AndroidOS_Mesploit_A {
    meta:
        description = "Detects HackTool:AndroidOS/Mesploit.A"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Mesploit"
        $string2 = "Android exploit"
        $string3 = "Mesploit.apk"
    condition:
        any of them
}

rule HackTool_AndroidOS_Mesploit_B_MTB {
    meta:
        description = "Detects HackTool:AndroidOS/Mesploit.B!MTB"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Mesploit"
        $string2 = "Android exploit"
        $string3 = "Mesploit.B"
    condition:
        any of them
}

rule HackTool_AndroidOS_Metasploit_D_MTB {
    meta:
        description = "Detects HackTool:AndroidOS/Metasploit.D!MTB"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Metasploit"
        $string2 = "Android exploit"
        $string3 = "Metasploit.D"
    condition:
        any of them
}

rule HackTool_Linux_AirCrack_A_MTB {
    meta:
        description = "Detects HackTool:Linux/AirCrack.A!MTB"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "AirCrack"
        $string2 = "Wi-Fi cracking"
        $string3 = "aircrack-ng"
    condition:
        any of them
}

rule HackTool_Linux_Cymoyhoa_A_MTB {
    meta:
        description = "Detects HackTool:Linux/Cymoyhoa.A!MTB"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Cymoyhoa"
        $string2 = "Linux exploit"
        $string3 = "Cymoyhoa.A"
    condition:
        any of them
}

rule HackTool_Linux_PthToolkitGen_MTB {
    meta:
        description = "Detects HackTool:Linux/PthToolkitGen!MTB"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "PthToolkitGen"
        $string2 = "Pass-the-Hash toolkit"
        $string3 = "PthToolkitGen"
    condition:
        any of them
}

rule HackTool_Linux_PthToolkitGen_ZZ {
    meta:
        description = "Detects HackTool:Linux/PthToolkitGen.ZZ"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "PthToolkitGen"
        $string2 = "Pass-the-Hash toolkit"
        $string3 = "PthToolkitGen.ZZ"
    condition:
        any of them
}

rule HackTool_Linux_Sandcar_A_MTB {
    meta:
        description = "Detects HackTool:Linux/Sandcar.A!MTB"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Sandcar"
        $string2 = "Linux exploit"
        $string3 = "Sandcar.A"
    condition:
        any of them
}

rule HackTool_MSIL_AutoKMS {
    meta:
        description = "Detects HackTool:MSIL/AutoKMS"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "AutoKMS"
        $string2 = "KMS activation"
        $string3 = "AutoKMS.exe"
    condition:
        any of them
}

rule HackTool_Perl_Freeciv_A {
    meta:
        description = "Detects HackTool:Perl/Freeciv.A"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Freeciv"
        $string2 = "Perl script"
        $string3 = "Freeciv.pl"
    condition:
        any of them
}

rule HackTool_Perl_Mcpws_A {
    meta:
        description = "Detects HackTool:Perl/Mcpws.A"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "Mcpws"
        $string2 = "Perl script"
        $string3 = "Mcpws.pl"
    condition:
        any of them
}