/*
   Cobalt Strike detection rules
   Covers: default named pipes, reflective loader, stager patterns, beacon config
*/

rule CobaltStrike_NamedPipe_Defaults
{
    meta:
        description = "Cobalt Strike default named pipe names"
        author = "TRUDI"
        severity = "high"
        reference = "https://blog.cobaltstrike.com/2021/01/06/cobalt-strike-hunting-named-pipe-tampering/"

    strings:
        $pipe1  = "\\\\.\\pipe\\MSSE-" ascii wide
        $pipe2  = "\\\\.\\pipe\\postex_" ascii wide
        $pipe3  = "\\\\.\\pipe\\msrpc_" ascii wide
        $pipe4  = "\\\\.\\pipe\\status_" ascii wide
        $pipe5  = "\\\\.\\pipe\\mojo." ascii wide
        $pipe6  = "\\\\.\\pipe\\interprocess_" ascii wide
        $pipe7  = "\\\\.\\pipe\\samr_" ascii wide
        $pipe8  = "\\\\.\\pipe\\wkssvc" ascii wide nocase
        $pipe9  = "\\\\.\\pipe\\ntsvcs" ascii wide nocase
        $pipe10 = "\\\\.\\pipe\\scerpc_" ascii wide
        $pipe11 = "diagsvc-" ascii wide

    condition:
        any of them
}

rule CobaltStrike_PowerShell_Stager
{
    meta:
        description = "Cobalt Strike GZIP/Base64 PowerShell stager"
        author = "TRUDI"
        severity = "high"

    strings:
        $gzip_iex  = "GzipStream" ascii wide nocase
        $from_b64  = "FromBase64String" ascii wide nocase
        $memstream = "IO.MemoryStream" ascii wide nocase
        $iex1      = "IEX(" ascii wide nocase
        $iex2      = "Invoke-Expression" ascii wide nocase
        $nop       = "-nop" ascii wide nocase
        $hidden    = "-w hidden" ascii wide nocase
        $enc       = "-encodedcommand" ascii wide nocase

    condition:
        ($gzip_iex and $from_b64 and $memstream and ($iex1 or $iex2))
        or ($nop and $hidden and $enc)
}

rule CobaltStrike_Shellcode_Injector_PowerSploit
{
    meta:
        description = "PowerSploit-derived shellcode injector used by Cobalt Strike stagers"
        author = "TRUDI"
        severity = "critical"

    strings:
        $func1   = "func_get_proc_address" ascii wide nocase
        $func2   = "func_get_delegate_type" ascii wide nocase
        $valloc  = "VirtualAlloc" ascii wide
        $rwx     = "0x40" ascii
        $commit  = "0x3000" ascii
        $runAs32 = "RunAs32" ascii wide nocase

    condition:
        ($func1 or $func2) and $valloc
        or ($valloc and $rwx and $commit and $runAs32)
}

rule CobaltStrike_ReflectiveDLL
{
    meta:
        description = "Reflective DLL loading — hallmark of CS beacon injection"
        author = "TRUDI"
        severity = "critical"

    strings:
        $reflective  = "ReflectiveLoader" ascii
        $mz_reloc    = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF }
        $cs_watermark = { FC 48 83 E4 F0 E8 }  // common CS x64 shellcode prologue

    condition:
        $reflective or $mz_reloc or $cs_watermark
}

rule CobaltStrike_BeaconConfig_Strings
{
    meta:
        description = "Cobalt Strike beacon configuration string fragments"
        author = "TRUDI"
        severity = "high"

    strings:
        $cfg1 = "BeaconHTTP" ascii
        $cfg2 = "BeaconDNS" ascii
        $cfg3 = "BeaconSMB" ascii
        $cfg4 = "%windir%\\sysnative\\" ascii
        $cfg5 = "Content-Type: application/octet-stream" ascii
        $sleep = "sleeptime" ascii nocase

    condition:
        2 of them
}
