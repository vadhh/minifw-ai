rule General_Malware_Detection {
    meta:
        description = "Detects common malware patterns"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "CreateRemoteThread"
        $string2 = "VirtualAlloc"
        $string3 = "GetProcAddress"
        $string4 = "LoadLibrary"
        $string5 = "RegSetValueEx"
        $string6 = "OpenProcess"
        $string7 = "WriteProcessMemory"
        $string8 = "GetModuleHandle"
        $string9 = "\\\\shell32.dll"
        $string10 = "cmd.exe /c"
    condition:
        any of them
}

rule Ransomware_Detection {
    meta:
        description = "Detects common ransomware patterns"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "ransomware"
        $string2 = "encrypt"
        $string3 = "decrypt"
        $string4 = ".locked"
        $string5 = ".encrypted"
        $string6 = "private key"
        $string7 = "public key"
        $string8 = "ransom note"
        $string9 = "decryptor"
        $string10 = "file recovery"
        $string11 = "BTC address"
        $string12 = "Bitcoin payment"
        $string13 = "Tor browser"
        $string14 = "restore files"
        $string15 = "recover your files"
    condition:
        any of them
}

rule Rootkit_Detection {
    meta:
        description = "Detects common rootkit patterns"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "rootkit"
        $string2 = "stealth"
        $string3 = "hide"
        $string4 = "hook"
        $string5 = "kernel module"
        $string6 = "ring0"
        $string7 = "root access"
        $string8 = "syscall"
        $string9 = "invisible process"
        $string10 = "bootkit"
        $string11 = "DKOM"
    condition:
        any of them
}

rule Trojan_Detection {
    meta:
        description = "Detects common Trojan patterns"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "trojan"
        $string2 = "backdoor"
        $string3 = "remote access"
        $string4 = "RAT"
        $string5 = "keylogger"
        $string6 = "credential theft"
        $string7 = "command and control"
        $string8 = "C2 server"
        $string9 = "data exfiltration"
        $string10 = "malicious payload"
        $string11 = "surveillance"
        $string12 = "persistent"
    condition:
        any of them
}

rule Backdoor_Detection {
    meta:
        description = "Detects common backdoor patterns"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "backdoor"
        $string2 = "shell"
        $string3 = "bind"
        $string4 = "reverse"
        $string5 = "connect"
        $string6 = "remote control"
        $string7 = "hidden service"
        $string8 = "C2 communication"
        $string9 = "persistent access"
        $string10 = "command execution"
        $string11 = "authentication bypass"
    condition:
        any of them
}

rule Phishing_Detection {
    meta:
        description = "Detects common phishing patterns"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "phish"
        $string2 = "credential"
        $string3 = "login"
        $string4 = "verify"
        $string5 = "account"
        $string6 = "password"
        $string7 = "security alert"
        $string8 = "click here"
        $string9 = "urgent"
        $string10 = "update your information"
        $string11 = "suspicious activity"
        $string12 = "email verification"
        $string13 = "secure your account"
    condition:
        any of them
}

rule Exploit_Detection {
    meta:
        description = "Detects common exploit patterns"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "exploit"
        $string2 = "vulnerability"
        $string3 = "shellcode"
        $string4 = "payload"
        $string5 = "buffer overflow"
        $string6 = "privilege escalation"
        $string7 = "arbitrary code execution"
        $string8 = "remote code execution"
        $string9 = "memory corruption"
        $string10 = "zero-day"
        $string11 = "ROP chain"
        $string12 = "heap spray"
        $string13 = "return-to-libc"
    condition:
        any of them
}

rule Network_Attack_Detection {
    meta:
        description = "Detects common network attack patterns"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "scan"
        $string2 = "sniff"
        $string3 = "spoof"
        $string4 = "MITM"
        $string5 = "denial of service"
        $string6 = "DDoS"
        $string7 = "packet capture"
        $string8 = "network reconnaissance"
        $string9 = "port scan"
        $string10 = "ARP poisoning"
        $string11 = "DNS spoofing"
        $string12 = "traffic interception"
        $string13 = "session hijack"
    condition:
        any of them
}

rule Fileless_Malware_Detection {
    meta:
        description = "Detects common fileless malware patterns"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "powershell"
        $string2 = "wscript"
        $string3 = "rundll32"
        $string4 = "memory injection"
        $string5 = "malicious script"
        $string6 = "regsvr32"
        $string7 = "scripting engine"
        $string8 = "reflective DLL"
        $string9 = "code injection"
        $string10 = "living off the land"
        $string11 = "scriptlet"
        $string12 = "in-memory execution"
        $string13 = "process hollowing"
    condition:
        any of them
}

rule Cryptocurrency_Miner_Detection {
    meta:
        description = "Detects common cryptocurrency miner patterns"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "miner"
        $string2 = "mining"
        $string3 = "cryptocurrency"
        $string4 = "bitcoin"
        $string5 = "monero"
        $string6 = "blockchain"
        $string7 = "hashrate"
        $string8 = "pool mining"
        $string9 = "wallet address"
        $string10 = "mining pool"
        $string11 = "cpu mining"
        $string12 = "gpu mining"
        $string13 = "crypto wallet"
    condition:
        any of them
}

rule Keylogger_Detection {
    meta:
        description = "Detects common keylogger patterns"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "keylogger"
        $string2 = "keystroke"
        $string3 = "capture"
        $string4 = "log"
        $string5 = "record"
    condition:
        any of them
}

rule Data_Exfiltration_Detection {
    meta:
        description = "Detects common data exfiltration patterns"
        author = "YourName"
        date = "2024-07-07"
    strings:
        $string1 = "exfiltrate"
        $string2 = "upload"
        $string3 = "extract"
        $string4 = "send"
        $string5 = "leak"
        $string6 = "data theft"
        $string7 = "steal data"
        $string8 = "export data"
        $string9 = "network upload"
        $string10 = "file transfer"
        $string11 = "exfil data"
        $string12 = "unauthorized access"
        $string13 = "sensitive data"
        $string14 = "confidential data"
        $string15 = "HTTP POST"
        $string16 = "FTP upload"
    condition:
        any of them
}