rule DoS_perl_Mulee_A {
    meta:
        description = "Detects DoS:perl/Mulee.A"
        author = "Your Name"
        date = "2024-07-06"
    strings:
        $perl_header = "#!/usr/bin/perl" ascii
        $pattern1 = "Mulee" ascii
        $pattern2 = "DoS attack" ascii
        $pattern3 = "target_ip" ascii
    condition:
        all of them
}

rule DoS_perl_nertt_A {
    meta:
        description = "Detects DoS:perl/nertt.A"
        author = "Your Name"
        date = "2024-07-06"
    strings:
        $perl_header = "#!/usr/bin/perl" ascii
        $pattern1 = "nertt" ascii
        $pattern2 = "flood" ascii
        $pattern3 = "attack" ascii
    condition:
        all of them
}

rule DoS_perl_Tedla_A {
    meta:
        description = "Detects DoS:perl/Tedla.A"
        author = "Your Name"
        date = "2024-07-06"
    strings:
        $perl_header = "#!/usr/bin/perl" ascii
        $pattern1 = "Tedla" ascii
        $pattern2 = "Denial of Service" ascii
        $pattern3 = "packet_size" ascii
    condition:
        all of them
}

rule DoS_Perl_Vqserver_A {
    meta:
        description = "Detects DoS:Perl/Vqserver.A"
        author = "Your Name"
        date = "2024-07-06"
    strings:
        $perl_header = "#!/usr/bin/perl" ascii
        $pattern1 = "Vqserver" ascii
        $pattern2 = "DoS script" ascii
        $pattern3 = "server_ip" ascii
    condition:
        all of them
}

rule DoS_Win32_ZipBomb_A {
    meta:
        description = "Detects DoS:Win32/ZipBomb.A"
        author = "Your Name"
        date = "2024-07-06"
    strings:
        $zip_magic = { 50 4B 03 04 } // PK header for ZIP files
        $pattern1 = "ZipBomb" ascii
        $pattern2 = "archive" ascii
        $pattern3 = "extraction" ascii
    condition:
        $zip_magic and 2 of ($pattern*)
}

rule Constructor_Perl_Machd_A {
    meta:
        description = "Detects Constructor:Perl/Machd.A"
        author = "Your Name"
        date = "2024-07-06"
    strings:
        $perl_header = "#!/usr/bin/perl" ascii
        $pattern1 = "Machd" ascii
        $pattern2 = "constructor" ascii
        $pattern3 = "create payload" ascii
    condition:
        all of them
}