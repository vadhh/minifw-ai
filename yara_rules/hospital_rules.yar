/*
  MiniFW-AI hospital sector YARA rules.

  Categories:
    medical_ransomware — Ransomware note strings and execution patterns
                         known to target healthcare environments.
    iomt_exploit       — Exploit payloads targeting medical device firmware
                         and management APIs (infusion pumps, patient monitors).
    medical_data_exfil — Unauthorized staging/exfiltration of protected health
                         information via HL7, FHIR, and DICOM protocols.

  Severity levels: critical, high, medium
*/

rule MedicalRansomware
{
    meta:
        category    = "medical_ransomware"
        severity    = "critical"
        description = "Detects ransomware note strings and execution patterns targeting hospitals"
        author      = "MiniFW-AI"

    strings:
        // Generic ransom note phrases
        $ransom_note1  = "Your network has been encrypted"       nocase
        $ransom_note2  = "All your files have been encrypted"    nocase
        $ransom_note3  = "To recover your files"                 nocase
        $ransom_note4  = "pay the ransom"                        nocase
        $ransom_note5  = "your data has been stolen"             nocase

        // Conti / Ryuk healthcare-specific strings
        $conti_ext     = ".CONTI"
        $ryuk_ext      = ".RYK"
        $ryuk_note     = "RyukReadMe"                            nocase
        $lockbit_ext   = ".lockbit"
        $alphv_ext     = ".alphv"
        $hive_note     = "HOW_TO_DECRYPT"                        nocase

        // Ransomware delivery / dropper patterns
        $vssadmin      = "vssadmin delete shadows"               nocase
        $bcdedit       = "bcdedit /set recoveryenabled no"       nocase
        $wbadmin       = "wbadmin delete catalog"                nocase

    condition:
        any of them
}

rule IoMTExploit
{
    meta:
        category    = "iomt_exploit"
        severity    = "critical"
        description = "Detects exploit payloads targeting medical device firmware and management APIs"
        author      = "MiniFW-AI"

    strings:
        // Medical device API abuse patterns
        $iomt_api1     = "/api/v1/device/config"                 nocase
        $iomt_api2     = "/infusion/rate/set"                    nocase
        $iomt_api3     = "/pump/bolus"                           nocase
        $iomt_api4     = "/monitor/alarm/disable"                nocase
        $iomt_api5     = "/ventilator/settings"                  nocase

        // Known medical device management endpoints used in exploit PoCs
        $ge_api        = "/GEHealthcare/api/"                    nocase
        $philips_api   = "/Philips/patient-monitor/"             nocase
        $baxter_api    = "/BaxterSigma/pump/"                    nocase

        // Firmware upload / remote code execution patterns
        $fw_upload     = "firmware_upgrade"                      nocase
        $rce_cmd       = "cmd.exe /c"                            nocase
        $shell_inject  = "/bin/sh -c"

    condition:
        any of them
}

rule MedicalDataExfil
{
    meta:
        category    = "medical_data_exfil"
        severity    = "high"
        description = "Detects unauthorized staging or exfiltration of protected health information"
        author      = "MiniFW-AI"

    strings:
        // HL7 message headers (unexpected in DNS/SNI payloads)
        $hl7_msh       = "MSH|^~\\&|"
        $hl7_pid       = "PID|||"

        // FHIR bulk export patterns
        $fhir_export   = "/$export"                              nocase
        $fhir_bulk     = "_outputFormat=application/fhir"        nocase
        $fhir_patient  = "/Patient/$everything"                  nocase

        // DICOM transfer / staging
        $dicom_store   = "C-STORE"
        $dicom_move    = "C-MOVE"
        $dicom_uid     = "1.2.840.10008"

        // PHI exfil staging keywords
        $phi_export    = "patient_export"                        nocase
        $phi_dump      = "medical_records_dump"                  nocase
        $phi_archive   = "phi_archive"                           nocase

    condition:
        any of them
}
