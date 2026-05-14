/*
   Persistence mechanism detection rules
*/

rule Persistence_ScheduledTask_XML_Suspicious
{
    meta:
        description = "Suspicious scheduled task XML — hidden, system-level, encoded command"
        author = "TRUDI"
        severity = "medium"

    strings:
        $hidden   = "<Hidden>true</Hidden>" ascii wide nocase
        $system   = "<UserId>S-1-5-18</UserId>" ascii wide nocase
        $highest  = "<RunLevel>HighestAvailable</RunLevel>" ascii wide nocase
        $enc      = "-EncodedCommand" ascii wide nocase
        $psh      = "powershell" ascii wide nocase
        $cmd      = "cmd.exe" ascii wide nocase

    condition:
        ($hidden or $system or $highest) and ($enc or $cmd or ($psh and $hidden))
}

rule Persistence_ServiceInstall_Cmdline
{
    meta:
        description = "Service installation via sc.exe or powershell New-Service"
        author = "TRUDI"
        severity = "medium"

    strings:
        $sc1  = "sc.exe create" ascii wide nocase
        $sc2  = "sc create " ascii wide nocase
        $sc3  = "New-Service" ascii wide nocase
        $sc4  = "sc config" ascii wide nocase
        $auto = "start= auto" ascii wide nocase
        $sys  = "type= kernel" ascii wide nocase
        $own  = "type= own" ascii wide nocase

    condition:
        ($sc1 or $sc2 or $sc3 or $sc4) and ($auto or $sys or $own)
}

rule Persistence_WMI_EventSubscription
{
    meta:
        description = "WMI event subscription persistence"
        author = "TRUDI"
        severity = "high"

    strings:
        $class1 = "__EventFilter" ascii wide
        $class2 = "__EventConsumer" ascii wide
        $class3 = "ActiveScriptEventConsumer" ascii wide
        $class4 = "CommandLineEventConsumer" ascii wide
        $class5 = "__FilterToConsumerBinding" ascii wide

    condition:
        2 of them
}

rule Persistence_Registry_Run_Key_Encoded
{
    meta:
        description = "Encoded PowerShell command in Run/RunOnce registry key"
        author = "TRUDI"
        severity = "high"

    strings:
        $run1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $run2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii wide nocase
        $enc  = "-EncodedCommand" ascii wide nocase
        $psh  = "powershell" ascii wide nocase

    condition:
        ($run1 or $run2) and ($enc or $psh)
}
