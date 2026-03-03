rule Trojan_PowerShell_Powersploit_I
{
    meta:
        description = "Detects Trojan:PowerShell/Powersploit.I"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "PowerSploit" // Specific PowerSploit toolkit string
        $s2 = "Invoke-ProcessInjection" // Process injection via PowerSploit
        $s3 = "New-Object System.Management.Automation.ScriptBlock" // Creating script blocks

    condition:
        any of them
}

rule Trojan_PowerShell_Powersploit_J
{
    meta:
        description = "Detects Trojan:PowerShell/Powersploit.J"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "PowerSploit" // Specific PowerSploit toolkit string
        $s2 = "Invoke-WmiCommand" // WMI commands via PowerSploit
        $s3 = "Get-WmiObject" // Retrieving WMI objects

    condition:
        any of them
}

rule Trojan_PowerShell_Powersploit_L
{
    meta:
        description = "Detects Trojan:PowerShell/Powersploit.L"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "PowerSploit" // Specific PowerSploit toolkit string
        $s2 = "Invoke-Shellcode" // Injecting shellcode via PowerSploit
        $s3 = "Get-Member" // Retrieving member information of objects

    condition:
        any of them
}

rule Trojan_PowerShell_Powersploit_M
{
    meta:
        description = "Detects Trojan:PowerShell/Powersploit.M"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "PowerSploit" // Specific PowerSploit toolkit string
        $s2 = "Invoke-CredentialPhisher" // Credential phishing via PowerSploit
        $s3 = "New-Object System.Security.SecureString" // Secure string creation

    condition:
        any of them
}

rule Trojan_PowerShell_Powersploit_N
{
    meta:
        description = "Detects Trojan:PowerShell/Powersploit.N"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "PowerSploit" // Specific PowerSploit toolkit string
        $s2 = "Invoke-Mimikatz" // Using Mimikatz via PowerSploit
        $s3 = "Add-Type" // Adding .NET types

    condition:
        any of them
}

rule Trojan_PowerShell_Powersploit_O
{
    meta:
        description = "Detects Trojan:PowerShell/Powersploit.O"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "PowerSploit" // Specific PowerSploit toolkit string
        $s2 = "Invoke-DllInjection" // DLL injection via PowerSploit
        $s3 = "New-Object System.IO.MemoryStream" // Memory stream creation

    condition:
        any of them
}

rule Trojan_PowerShell_Powersploit_P
{
    meta:
        description = "Detects Trojan:PowerShell/Powersploit.P"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "PowerSploit" // Specific PowerSploit toolkit string
        $s2 = "Invoke-TokenManipulation" // Token manipulation via PowerSploit
        $s3 = "New-Object System.Net.WebClient" // Downloading payloads

    condition:
        any of them
}

rule Trojan_PowerShell_Powersploit_Q
{
    meta:
        description = "Detects Trojan:PowerShell/Powersploit.Q"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "PowerSploit" // Specific PowerSploit toolkit string
        $s2 = "Invoke-ReflectivePEInjection" // PE injection via PowerSploit
        $s3 = "ConvertTo-SecureString" // Handling secure strings

    condition:
        any of them
}

rule Trojan_PowerShell_Powersploit_T
{
    meta:
        description = "Detects Trojan:PowerShell/Powersploit.T"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "PowerSploit" // Specific PowerSploit toolkit string
        $s2 = "Invoke-Command" // Invoking PowerShell commands
        $s3 = "New-Object System.IO.StreamReader" // Reading streams

    condition:
        any of them
}

rule Trojan_PowerShell_ReverseShell_SA
{
    meta:
        description = "Detects Trojan:PowerShell/ReverseShell.SA"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "ReverseShell" // Common string in reverse shell scripts
        $s2 = "New-Object Net.Sockets.TcpClient" // Creating TCP client
        $s3 = "StreamWriter" // Writing to streams

    condition:
        any of them
}

rule Trojan_PowerShell_ShellcodeMSIL
{
    meta:
        description = "Detects Trojan:PowerShell/ShellcodeMSIL"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Shellcode" // Common string in shellcode scripts
        $s2 = "DllImport" // Importing DLLs
        $s3 = "Marshal.Copy" // Copying memory blocks

    condition:
        any of them
}