rule Trojan_PowerShell_UnicornBypass_A
{
    meta:
        description = "Detects Trojan:PowerShell/UnicornBypass.A"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Unicorn" // Common string in Unicorn scripts
        $s2 = "Invoke-Shellcode" // Injecting shellcode via PowerShell
        $s3 = "System.Reflection.Assembly" // Reflection in PowerShell

    condition:
        any of them
}

rule Trojan_Python_Empyre_B_MTB
{
    meta:
        description = "Detects Trojan:Python/Empyre.B!MTB"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Empyre" // Common string in Empyre framework
        $s2 = "import os" // Importing OS module
        $s3 = "subprocess.Popen" // Executing subprocesses

    condition:
        any of them
}

rule Trojan_Python_Metaspit
{
    meta:
        description = "Detects Trojan:Python/Metaspit"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Metaspit" // Specific to Metaspit trojan
        $s2 = "import socket" // Importing socket module
        $s3 = "base64.b64decode" // Base64 decoding

    condition:
        any of them
}

rule Trojan_Script_Malgent_MSR
{
    meta:
        description = "Detects Trojan:Script/Malgent!MSR"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Malgent" // Specific to Malgent scripts
        $s2 = "eval" // Evaluating strings as code
        $s3 = "document.write" // Writing to the document in JavaScript

    condition:
        any of them
}

rule Trojan_Script_Metasploit_MSR
{
    meta:
        description = "Detects Trojan:Script/Metasploit!MSR"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Metasploit" // Specific to Metasploit framework
        $s2 = "msf" // Common abbreviation for Metasploit
        $s3 = "shellcode" // Injecting shellcode

    condition:
        any of them
}

rule Trojan_Script_Phonzy_A_ml
{
    meta:
        description = "Detects Trojan:Script/Phonzy.A!ml"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Phonzy" // Specific to Phonzy scripts
        $s2 = "function" // Defining functions in JavaScript
        $s3 = "XMLHttpRequest" // Making HTTP requests

    condition:
        any of them
}

rule Trojan_Win32_AggBITSAbuse_A
{
    meta:
        description = "Detects Trojan:Win32/AggBITSAbuse.A"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "BITSAdmin" // Background Intelligent Transfer Service abuse
        $s2 = "CreateObject" // Creating COM objects
        $s3 = "download" // Downloading files

    condition:
        any of them
}

rule Trojan_Win32_Bluteal_rfn
{
    meta:
        description = "Detects Trojan:Win32/Bluteal.!rfn"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Bluteal" // Specific to Bluteal trojan
        $s2 = "cmd.exe" // Executing commands via cmd
        $s3 = "powershell.exe" // Executing PowerShell commands

    condition:
        any of them
}

rule Trojan_Win32_Bluteal_B_rfn
{
    meta:
        description = "Detects Trojan:Win32/Bluteal.B!rfn"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Bluteal" // Specific to Bluteal trojan
        $s2 = "regsvr32.exe" // Registering DLLs
        $s3 = "schtasks.exe" // Creating scheduled tasks

    condition:
        any of them
}

rule Trojan_Win32_CrtptInject
{
    meta:
        description = "Detects Trojan:Win32/CrtptInject"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "CrtptInject" // Specific to CrtptInject trojan
        $s2 = "CreateRemoteThread" // Creating remote threads
        $s3 = "VirtualAlloc" // Allocating memory in virtual address space

    condition:
        any of them
}

rule Trojan_Win32_CryptInject_MSR
{
    meta:
        description = "Detects Trojan:Win32/CryptInject!MSR"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "CryptInject" // Specific to CryptInject trojan
        $s2 = "RtlEncryptMemory" // Encrypting memory
        $s3 = "CryptUnprotectData" // Decrypting protected data

    condition:
        any of them
}

rule Trojan_Win32_Ditertag_A
{
    meta:
        description = "Detects Trojan:Win32/Ditertag.A"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Ditertag" // Specific to Ditertag trojan
        $s2 = "GetProcAddress" // Retrieving the address of an exported function
        $s3 = "LoadLibrary" // Loading dynamic-link libraries

    condition:
        any of them
}

rule Trojan_Win32_Dorv_A_rfn
{
    meta:
        description = "Detects Trojan:Win32/Dorv.A!rfn"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Dorv" // Specific to Dorv trojan
        $s2 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" // Registry run key
        $s3 = "svchost.exe" // Commonly abused system process

    condition:
        any of them
}

rule Trojan_Win32_Dynamer_ac
{
    meta:
        description = "Detects Trojan:Win32/Dynamer!ac"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Dynamer" // Specific to Dynamer trojan
        $s2 = "VirtualAllocEx" // Memory allocation function
        $s3 = "CreateRemoteThread" // Creating remote threads

    condition:
        any of them
}

rule Trojan_Win32_Dynamer_rfn
{
    meta:
        description = "Detects Trojan:Win32/Dynamer!rfn"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Dynamer" // Specific to Dynamer trojan
        $s2 = "WriteProcessMemory" // Writing to the memory of another process
        $s3 = "OpenProcess" // Opening a handle to another process

    condition:
        any of them
}

rule Trojan_Win32_Klogger
{
    meta:
        description = "Detects Trojan:Win32/Klogger"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Klogger" // Specific to Klogger trojan
        $s2 = "GetAsyncKeyState" // Keylogging function
        $s3 = "SaveFile" // Saving logged data to a file

    condition:
        any of them
}

rule Trojan_Win32_Lodap_rts
{
    meta:
        description = "Detects Trojan:Win32/Lodap!rts"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Lodap" // Specific to Lodap trojan
        $s2 = "WinExec" // Executing commands
        $s3 = "URLDownloadToFile" // Downloading files

    condition:
        any of them
}

rule Trojan_Win32_Malgent_MTB
{
    meta:
        description = "Detects Trojan:Win32/Malgent!MTB"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Malgent" // Specific to Malgent trojan
        $s2 = "RegSetValueEx" // Modifying registry values
        $s3 = "FindFirstFile" // File enumeration function

    condition:
        any of them
}

rule Trojan_Win32_MAmson_A_ac
{
    meta:
        description = "Detects Trojan:Win32/MAmson.A!ac"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "MAmson" // Specific to MAmson trojan
        $s2 = "Start-Service" // PowerShell service manipulation
        $s3 = "Invoke-WebRequest" // PowerShell web request

    condition:
        any of them
}

rule Trojan_Win32_Metasploit
{
    meta:
        description = "Detects Trojan:Win32/Metasploit"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Metasploit" // Specific to Metasploit framework
        $s2 = "msf" // Common abbreviation for Metasploit
        $s3 = "meterpreter" // Metasploit payload

    condition:
        any of them
}

rule Trojan_Win32_Metasploit_X
{
    meta:
        description = "Detects Trojan:Win32/Metasploit.X"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Metasploit" // Specific to Metasploit framework
        $s2 = "payload" // Common in Metasploit payloads
        $s3 = "exploit" // Common in Metasploit exploits

    condition:
        any of them
}

rule Trojan_Win32_Meterpreter_A
{
    meta:
        description = "Detects Trojan:Win32/Meterpreter.A"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "meterpreter" // Specific to Meterpreter payload
        $s2 = "stdapi" // Standard API extension for Meterpreter
        $s3 = "ext_server" // Extension server

    condition:
        any of them
}

rule Trojan_Win32_Occamy_C
{
    meta:
        description = "Detects Trojan:Win32/Occamy.C"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "Occamy" // Specific to Occamy trojan
        $s2 = "Process32First" // Enumerating processes
        $s3 = "CreateToolhelp32Snapshot" // Creating snapshot of system processes

    condition:
        any of them
}

rule Trojan_Win32_Powersploit
{
    meta:
        description = "Detects Trojan:Win32/Powersploit"
        author = "YourName"
        date = "2024-07-06"

    strings:
        $s1 = "PowerSploit" // Specific to PowerSploit framework
        $s2 = "Invoke-Shellcode" // Injecting shellcode via PowerSploit
        $s3 = "Get-WmiObject" // Retrieving WMI objects

    condition:
        any of them
}

rule Trojan_Win32_PSReflectionLoader_A {
    meta:
        description = "Detects Trojan:Win32/PSReflectionLoader.A"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "PSReflectionLoader"
        $s2 = { 89 45 FC 33 C0 89 45 F8 8B 45 0C 8B 55 10 03 45 08 }
        $s3 = "Reflection" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule Trojan_Win32_Rpdactaele_B {
    meta:
        description = "Detects Trojan:Win32/Rpdactaele.B"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Rpdactaele"
        $s2 = { 60 8B 6C 24 24 8B 45 08 8B 4D 0C }
        $s3 = "RpdactaeleLoader" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule Trojan_Win32_Sehyioa_A_cl {
    meta:
        description = "Detects Trojan:Win32/Sehyioa.A!cl"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Sehyioa"
        $s2 = { 68 64 57 4D 01 FF D0 8B 45 0C }
        $s3 = "SehyioaCommandLine" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule Trojan_Win32_Skeeyah_MSR {
    meta:
        description = "Detects Trojan:Win32/Skeeyah!MSR"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Skeeyah"
        $s2 = { 74 12 8B 45 08 8B 4D 0C 89 45 FC 8B 45 10 89 4D F8 }
        $s3 = "SkeeyahMalware" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule Trojan_Win32_Skeeyah_A_bit {
    meta:
        description = "Detects Trojan:Win32/Skeeyah.A!bit"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Skeeyah.A"
        $s2 = { 8B 45 0C 8B 55 10 89 45 FC 33 C0 89 45 F8 }
        $s3 = "SkeeyahBit" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule Trojan_Win32_Skeeyah_A_MTB {
    meta:
        description = "Detects Trojan:Win32/Skeeyah.A!MTB"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "SkeeyahMTB"
        $s2 = { 33 C0 89 45 FC 8B 45 0C 8B 55 10 89 45 F8 }
        $s3 = "MTBSkeeyah" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule Trojan_Win32_Skeeyah_A_rfn {
    meta:
        description = "Detects Trojan:Win32/Skeeyah.A!rfn"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "SkeeyahRFN"
        $s2 = { 8B 45 0C 89 45 F8 33 C0 89 45 FC 8B 55 10 }
        $s3 = "RFNSkeeyah" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule Trojan_Win32_Swrort_rfn {
    meta:
        description = "Detects Trojan:Win32/Swrort!rfn"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Swrort"
        $s2 = { 68 6C 6C 20 00 68 65 74 2E 64 68 77 73 33 32 89 65 FC }
        $s3 = "SwrortRFN" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule Trojan_Win32_Tiggre_plock {
    meta:
        description = "Detects Trojan:Win32/Tiggre!plock"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Tiggre"
        $s2 = { 8B 45 08 8B 4D 0C 89 45 FC 33 C0 89 45 F8 }
        $s3 = "TiggrePlock" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule Trojan_Win32_Tiggre_rfn {
    meta:
        description = "Detects Trojan:Win32/Tiggre!rfn"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "TiggreRFN"
        $s2 = { 33 C0 89 45 F8 8B 45 0C 8B 55 10 89 45 FC }
        $s3 = "RFNTiggre" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule Trojan_Win32_Wacatac_A_rfn {
    meta:
        description = "Detects Trojan:Win32/Wacatac.A!rfn"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Wacatac"
        $s2 = { 8B 45 08 89 45 FC 33 C0 89 45 F8 8B 4D 0C }
        $s3 = "WacatacRFN" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule Trojan_Win32_Wingo_MSR {
    meta:
        description = "Detects Trojan:Win32/Wingo!MSR"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Wingo"
        $s2 = { 8B 55 10 89 45 FC 33 C0 89 45 F8 8B 45 0C }
        $s3 = "WingoMSR" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule Trojan_Win32_Ymacco_AA07 {
    meta:
        description = "Detects Trojan:Win32/Ymacco.AA07"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Ymacco"
        $s2 = { 68 64 57 4D 01 FF D0 8B 45 0C }
        $s3 = "YmaccoAA07" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule Trojan_Win32_Ymacco_AB74 {
    meta:
        description = "Detects Trojan:Win32/Ymacco.AB74"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Ymacco"
        $s2 = { 60 8B 6C 24 24 8B 45 08 8B 4D 0C }
        $s3 = "YmaccoAB74" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule Trojan_Win64_CoinMiner {
    meta:
        description = "Detects Trojan:Win64/CoinMiner"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "CoinMiner"
        $s2 = { 68 6C 6C 20 00 68 65 74 2E 64 68 77 73 33 32 89 65 FC }
        $s3 = "CoinMiner64" nocase

    condition:
        (uint16(0) == 0x5A4D or uint16(0) == 0x8664) and (any of ($s*))
}

rule Trojan_Win64_ColbaltStrike_ZM_MTB {
    meta:
        description = "Detects Trojan:Win64/ColbaltStrike.ZM!MTB"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "ColbaltStrike"
        $s2 = { 8B 45 0C 8B 55 10 89 45 FC 33 C0 89 45 F8 }
        $s3 = "ColbaltStrikeZM" nocase

    condition:
        (uint16(0) == 0x5A4D or uint16(0) == 0x8664) and (any of ($s*))
}

rule Trojan_Win64_Meterpreter {
    meta:
        description = "Detects Trojan:Win64/Meterpreter"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Meterpreter"
        $s2 = { 8B 55 10 89 45 FC 33 C0 89 45 F8 8B 45 0C }
        $s3 = "Meterpreter64" nocase

    condition:
        (uint16(0) == 0x5A4D or uint16(0) == 0x8664) and (any of ($s*))
}

rule Trojan_Win64_Meterpreter_rfn {
    meta:
        description = "Detects Trojan:Win64/Meterpreter!rfn"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Meterpreter"
        $s2 = { 8B 55 10 89 45 FC 33 C0 89 45 F8 8B 45 0C }
        $s3 = "MeterpreterRFN" nocase

    condition:
        (uint16(0) == 0x5A4D or uint16(0) == 0x8664) and (any of ($s*))
}

rule TrojanDownloader_BAT_Genmaldwn_K_bit {
    meta:
        description = "Detects TrojanDownloader:BAT/Genmaldwn.K!bit"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Genmaldwn"
        $s2 = { 60 8B 6C 24 24 8B 45 08 8B 4D 0C }
        $s3 = "GenmaldwnK" nocase

    condition:
        (uint16(0) == 0x4D5A) and (any of ($s*))
}

rule TrojanDownloader_HTML_Adodb_gen_A {
    meta:
        description = "Detects TrojanDownloader:HTML/Adodb.gen!A"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Adodb"
        $s2 = { 68 64 57 4D 01 FF D0 8B 45 0C }
        $s3 = "AdodbGenA" nocase

    condition:
        (uint16(0) == 0x4D5A) and (any of ($s*))
}

rule TrojanDownloader_JS_Adobd_gen_D {
    meta:
        description = "Detects TrojanDownloader:JS/Adobd.gen!D"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Adobd"
        $s2 = { 68 6C 6C 20 00 68 65 74 2E 64 68 77 73 33 32 89 65 FC }
        $s3 = "AdobdGenD" nocase

    condition:
        (uint16(0) == 0x4D5A) and (any of ($s*))
}

rule TrojanDownloader_JS_Agent {
    meta:
        description = "Detects TrojanDownloader:JS/Agent"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Agent"
        $s2 = { 8B 45 08 8B 4D 0C 89 45 FC 33 C0 89 45 F8 }
        $s3 = "AgentDownloader" nocase

    condition:
        (uint16(0) == 0x4D5A) and (any of ($s*))
}

rule TrojanDownloader_JS_Psyme_AG {
    meta:
        description = "Detects TrojanDownloader:JS/Psyme.AG"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Psyme"
        $s2 = { 8B 55 10 89 45 FC 33 C0 89 45 F8 8B 45 0C }
        $s3 = "PsymeAG" nocase

    condition:
        (uint16(0) == 0x4D5A) and (any of ($s*))
}

rule TrojanDownloader_JS_Seena_C {
    meta:
        description = "Detects TrojanDownloader:JS/Seena.C"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Seena"
        $s2 = { 8B 45 08 89 45 FC 33 C0 89 45 F8 8B 4D 0C }
        $s3 = "SeenaC" nocase

    condition:
        (uint16(0) == 0x4D5A) and (any of ($s*))
}

rule TrojanDownloader_JS_Small_l {
    meta:
        description = "Detects TrojanDownloader:JS/Small.l"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Small.l"
        $s2 = { 68 65 6C 6C 6F 20 77 6F 72 6C 64 21 }
        $s3 = "SmallJSDownloader" nocase

    condition:
        (any of ($s*))
}

rule TrojanDownloader_PHP_Remoteshell_A {
    meta:
        description = "Detects TrojanDownloader:PHP/Remoteshell.A"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Remoteshell"
        $s2 = { 24 5F 53 45 52 56 45 52 5B 27 5A 5F 27 5D }
        $s3 = "RemoteshellDownloader" nocase

    condition:
        (any of ($s*))
}

rule TrojanDownloader_PowerShell_sLoad_E {
    meta:
        description = "Detects TrojanDownloader:PowerShell/sLoad.E"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "sLoad"
        $s2 = { 24 63 6F 6E 74 65 6E 74 3D 47 65 74 2D 43 6F 6E 74 65 6E 74 }
        $s3 = "sLoadPowerShell" nocase

    condition:
        (any of ($s*))
}

rule TrojanDownloader_Win32_Banload {
    meta:
        description = "Detects TrojanDownloader:Win32/Banload"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Banload"
        $s2 = { 68 74 74 70 3A 2F 2F 77 77 77 2E 62 61 6E 6C 6F 61 64 2E 63 6F 6D }
        $s3 = "BanloadDownloader" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule TrojanDownloader_Win32_Rugmi_SB_MTB {
    meta:
        description = "Detects TrojanDownloader:Win32/Rugmi.SB!MTB"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Rugmi"
        $s2 = { 8B 45 0C 8B 55 10 89 45 FC 33 C0 89 45 F8 }
        $s3 = "RugmiDownloader" nocase

    condition:
        (uint16(0) == 0x5A4D) and (any of ($s*))
}

rule TrojanDropper_Perl_Hlink_A_ExcelExp {
    meta:
        description = "Detects TrojanDropper/Perl/Hlink.A!ExcelExp"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Hlink"
        $s2 = { 24 68 6C 69 6E 6B 3D 27 68 74 74 70 3A 2F 2F }
        $s3 = "HlinkPerl" nocase

    condition:
        (any of ($s*))
}

rule TrojanDropper_Perl_Hlink_B_ExcelExp {
    meta:
        description = "Detects TrojanDropper:Perl/Hlink.B!ExcelExp"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Hlink.B"
        $s2 = { 24 68 6C 69 6E 6B 3D 27 68 74 74 70 3A 2F 2F 77 77 77 }
        $s3 = "HlinkBPerl" nocase

    condition:
        (any of ($s*))
}

rule TrojanDropper_Perl_Picozip_exploit {
    meta:
        description = "Detects TrojanDropper:Perl/Picozip!exploit"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Picozip"
        $s2 = { 24 70 69 63 6F 7A 69 70 3D 27 68 74 74 70 3A 2F 2F }
        $s3 = "PicozipPerl" nocase

    condition:
        (any of ($s*))
}

rule TrojanDropper_PowerShell_Cobacis_B {
    meta:
        description = "Detects TrojanDropper:PowerShell/Cobacis.B"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Cobacis"
        $s2 = { 24 63 6F 62 61 63 69 73 3D 47 65 74 2D 43 6F 6E 74 65 6E 74 }
        $s3 = "CobacisPowerShell" nocase

    condition:
        (any of ($s*))
}

rule TrojanDropper_PowerShell_Injector_MSR {
    meta:
        description = "Detects TrojanDropper:PowerShell/Injector!MSR"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Injector"
        $s2 = { 24 69 6E 6A 65 63 74 6F 72 3D 47 65 74 2D 43 6F 6E 74 65 6E 74 }
        $s3 = "InjectorPowerShell" nocase

    condition:
        (any of ($s*))
}

rule TrojanDropper_PowerShell_Ploty_C {
    meta:
        description = "Detects TrojanDropper:PowerShell/Ploty.C"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Ploty"
        $s2 = { 24 70 6C 6F 74 79 3D 47 65 74 2D 43 6F 6E 74 65 6E 74 }
        $s3 = "PlotyPowerShell" nocase

    condition:
        (any of ($s*))
}

rule TrojanDropper_PowerShell_PowerSploit_S_MSR {
    meta:
        description = "Detects TrojanDropper:PowerShell/PowerSploit.S!MSR"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "PowerSploit"
        $s2 = { 24 70 6F 77 65 72 73 70 6C 6F 69 74 3D 47 65 74 2D 43 6F 6E 74 65 6E 74 }
        $s3 = "PowerSploitPowerShell" nocase

    condition:
        (any of ($s*))
}

rule TrojanSpy_MSIL_Keylogger_MTB {
    meta:
        description = "Detects TrojanSpy:MSIL/Keylogger!MTB"
        author = "Your Name"
        date = "2024-07-06"
        reference = "https://example.com"

    strings:
        $s1 = "Keylogger"
        $s2 = { 6B 65 79 6C 6F 67 67 65 72 20 63 6C 61 73 73 }
        $s3 = "keylogging" nocase
        $s4 = "System.Windows.Forms.Keys" nocase

    condition:
        (uint16(0) == 0x4D5A) and (any of ($s*))
}