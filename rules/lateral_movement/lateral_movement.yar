/*
   Lateral movement and credential access rules
*/

rule LateralMovement_NetUse_AdminShare
{
    meta:
        description = "Net use to admin shares (C$, ADMIN$, IPC$)"
        author = "TRUDI"
        severity = "medium"

    strings:
        $net1 = "net use" ascii wide nocase
        $net2 = "net.exe" ascii wide nocase
        $adm1 = "\\c$" ascii wide nocase
        $adm2 = "\\admin$" ascii wide nocase
        $adm3 = "\\ipc$" ascii wide nocase

    condition:
        ($net1 or $net2) and ($adm1 or $adm2 or $adm3)
}

rule LateralMovement_PsExec_Artifacts
{
    meta:
        description = "PsExec / PsExecSvc artifacts in memory or filesystem"
        author = "TRUDI"
        severity = "medium"

    strings:
        $str1 = "PSEXESVC" ascii wide
        $str2 = "psexec" ascii wide nocase
        $str3 = "PsExec Service" ascii wide nocase
        $str4 = "\\\\.\\pipe\\psexecsvc" ascii wide nocase

    condition:
        any of them
}

rule LateralMovement_WMI_Exec
{
    meta:
        description = "WMI-based remote execution patterns"
        author = "TRUDI"
        severity = "medium"

    strings:
        $wmic1 = "wmic /node:" ascii wide nocase
        $wmic2 = "wmic process call create" ascii wide nocase
        $wmic3 = "Win32_Process" ascii wide
        $wmic4 = "Invoke-WmiMethod" ascii wide nocase
        $wmic5 = "Invoke-CimMethod" ascii wide nocase

    condition:
        any of them
}

rule CredentialAccess_LSASS_Dump
{
    meta:
        description = "LSASS process memory dumping tools and techniques"
        author = "TRUDI"
        severity = "critical"

    strings:
        $lsass1 = "lsass.exe" ascii wide nocase
        $dump1  = "MiniDumpWriteDump" ascii
        $dump2  = "procdump" ascii wide nocase
        $dump3  = "comsvcs.dll" ascii wide nocase
        $dump4  = "MiniDump" ascii wide nocase
        $task1  = "sekurlsa" ascii wide nocase  // mimikatz
        $task2  = "logonPasswords" ascii wide nocase

    condition:
        ($lsass1 and ($dump1 or $dump2 or $dump3 or $dump4))
        or $task1 or $task2
}

rule CredentialAccess_Mimikatz
{
    meta:
        description = "Mimikatz credential dumping tool artifacts"
        author = "TRUDI"
        severity = "critical"
        reference = "https://attack.mitre.org/software/S0002/"

    strings:
        $str1 = "mimikatz" ascii wide nocase
        $str2 = "sekurlsa::" ascii wide nocase
        $str3 = "kerberos::" ascii wide nocase
        $str4 = "lsadump::" ascii wide nocase
        $str5 = "privilege::debug" ascii wide nocase
        $str6 = "gentilkiwi" ascii wide nocase

    condition:
        any of them
}
