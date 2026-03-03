rule Trojan_PowerShell_Agent_AKD
{
    meta:
        description = "Detects Trojan:PowerShell/Agent.AKD"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Invoke-Expression" // Common in PowerShell malware
        $s2 = "System.Net.WebClient" // Used for downloading payloads
        $s3 = "-NoProfile -NonInteractive" // Common PowerShell switches in malware

    condition:
        any of them
}

rule Trojan_PowerShell_Casur_CS_eml
{
    meta:
        description = "Detects Trojan:PowerShell/Casur.CS!eml"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Invoke-WebRequest" // Used for HTTP requests
        $s2 = "Base64" // Commonly used for obfuscation
        $s3 = "New-Object System.IO.StreamReader" // Used to read streams

    condition:
        any of them
}

rule Trojan_PowerShell_Clicker
{
    meta:
        description = "Detects Trojan:PowerShell/Clicker"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Start-Process" // Used to start new processes
        $s2 = "Get-Process" // Used to retrieve process information
        $s3 = "Set-ExecutionPolicy" // Used to change execution policy

    condition:
        any of them
}

rule Trojan_PowerShell_CredentialPhiser
{
    meta:
        description = "Detects Trojan:PowerShell/CredentialPhiser"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Get-Credential" // Used to prompt for user credentials
        $s2 = "ConvertTo-SecureString" // Used to handle secure strings
        $s3 = "Read-Host" // Used to read user input

    condition:
        any of them
}

rule Trojan_PowerShell_Macro
{
    meta:
        description = "Detects Trojan:PowerShell/Macro"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Excel.Application" // Common in macro malware
        $s2 = "Word.Application" // Common in macro malware
        $s3 = "WScript.Shell" // Used to run shell commands

    condition:
        any of them
}

rule Trojan_PowerShell_NypassUAC_MSR
{
    meta:
        description = "Detects Trojan:PowerShell/NypassUAC!MSR"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "BypassUAC" // Specific technique for bypassing UAC
        $s2 = "ElevationType" // Related to UAC elevation
        $s3 = "ShellExecute" // Used to execute commands with elevated privileges

    condition:
        any of them
}

rule Trojan_PowerShell_Obfuse_SG_MSR
{
    meta:
        description = "Detects Trojan:PowerShell/Obfuse.SG!MSR"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Obfuscation" // Commonly used in obfuscated scripts
        $s2 = "EncodedCommand" // Used to encode PowerShell commands
        $s3 = "System.Convert::FromBase64String" // Base64 decoding in PowerShell

    condition:
        any of them
}

rule Trojan_PowerShell_Pklotide_A
{
    meta:
        description = "Detects Trojan:PowerShell/Pklotide.A"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "DownloadFile" // Used to download files
        $s2 = "Invoke-Command" // Used to invoke PowerShell commands
        $s3 = "Invoke-Shellcode" // Injecting shellcode via PowerShell

    condition:
        any of them
}

rule Trojan_PowerShell_Powersploit_A
{
    meta:
        description = "Detects Trojan:PowerShell/Powersploit.A"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "PowerSploit" // Specific PowerSploit toolkit string
        $s2 = "Invoke-Mimikatz" // Used to invoke Mimikatz via PowerShell
        $s3 = "Out-EncryptedScript" // Used in PowerSploit for obfuscation

    condition:
        any of them
}

rule Trojan_PowerShell_Powersploit_B
{
    meta:
        description = "Detects Trojan:PowerShell/Powersploit.B"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "PowerSploit" // Specific PowerSploit toolkit string
        $s2 = "Invoke-Shellcode" // Injecting shellcode via PowerShell
        $s3 = "New-Object Net.WebClient" // Downloading payloads via PowerShell

    condition:
        any of them
}

rule Trojan_PowerShell_Powersploit_G
{
    meta:
        description = "Detects Trojan:PowerShell/Powersploit.G"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "PowerSploit" // Specific PowerSploit toolkit string
        $s2 = "Invoke-ReflectivePEInjection" // Used for PE injection
        $s3 = "New-Object IO.MemoryStream" // Memory stream for payloads

    condition:
        any of them
}

rule Trojan_PowerShell_Powersploit_H
{
    meta:
        description = "Detects Trojan:PowerShell/Powersploit.H"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "PowerSploit" // Specific PowerSploit toolkit string
        $s2 = "Invoke-TokenManipulation" // Token manipulation via PowerShell
        $s3 = "Invoke-DllInjection" // DLL injection via PowerShell

    condition:
        any of them
}