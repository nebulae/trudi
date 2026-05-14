/*
   Anti-forensics and defense evasion rules
*/

rule AntiForensics_SDelete_Strings
{
    meta:
        description = "SDelete secure deletion tool artifacts"
        author = "TRUDI"
        severity = "medium"

    strings:
        $str1 = "SDelete" ascii wide
        $str2 = "Sysinternals" ascii wide
        $str3 = "sdelete" ascii wide nocase
        $str4 = "secure delete" ascii wide nocase

    condition:
        any of them
}

rule AntiForensics_EventLog_Clear
{
    meta:
        description = "Windows event log clearing commands"
        author = "TRUDI"
        severity = "high"

    strings:
        $wevt1 = "wevtutil cl " ascii wide nocase
        $wevt2 = "wevtutil clear-log" ascii wide nocase
        $wevt3 = "Clear-EventLog" ascii wide nocase
        $wevt4 = "wevtutil sl" ascii wide nocase

    condition:
        any of them
}

rule AntiForensics_Timestomp
{
    meta:
        description = "Timestamp manipulation tools or PowerShell timestamp modification"
        author = "TRUDI"
        severity = "high"

    strings:
        $ts1 = "timestomp" ascii wide nocase
        $ts2 = ".CreationTime" ascii wide nocase
        $ts3 = ".LastWriteTime" ascii wide nocase
        $ts4 = ".LastAccessTime" ascii wide nocase
        $ts5 = "Touch-File" ascii wide nocase

    condition:
        $ts1 or ($ts2 and $ts3) or ($ts3 and $ts4) or $ts5
}

rule AntiForensics_USN_Deletion
{
    meta:
        description = "USN journal deletion or filesystem journal manipulation"
        author = "TRUDI"
        severity = "high"

    strings:
        $fsutil1 = "fsutil usn deletejournal" ascii wide nocase
        $fsutil2 = "fsutil journal" ascii wide nocase

    condition:
        any of them
}
