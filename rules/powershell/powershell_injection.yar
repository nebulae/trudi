/*
   PowerShell injection and obfuscation rules
*/

rule PowerShell_EncodedCommand_Suspicious
{
    meta:
        description = "PowerShell with encoded command and evasion flags"
        author = "TRUDI"
        severity = "medium"

    strings:
        $enc1 = "-EncodedCommand" ascii wide nocase
        $enc2 = "-enc " ascii wide nocase
        $nop  = "-NonInteractive" ascii wide nocase
        $nop2 = "-NoProfile" ascii wide nocase
        $nop3 = "-NoLogo" ascii wide nocase
        $byp  = "-ExecutionPolicy Bypass" ascii wide nocase
        $byp2 = "-ep bypass" ascii wide nocase
        $win  = "-WindowStyle Hidden" ascii wide nocase
        $win2 = "-w hidden" ascii wide nocase

    condition:
        ($enc1 or $enc2) and 2 of ($nop, $nop2, $nop3, $byp, $byp2, $win, $win2)
}

rule PowerShell_AMSI_Bypass
{
    meta:
        description = "Common AMSI bypass techniques in memory"
        author = "TRUDI"
        severity = "high"

    strings:
        $amsi1 = "amsiInitFailed" ascii wide nocase
        $amsi2 = "AmsiScanBuffer" ascii wide nocase
        $amsi3 = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')" ascii wide nocase
        $amsi4 = "amsiContext" ascii wide nocase
        $patch  = { 48 31 C0 C3 }  // common AMSI patch bytes (xor rax,rax; ret)

    condition:
        any of ($amsi1, $amsi2, $amsi3, $amsi4) or $patch
}

rule PowerShell_ScriptBlock_Obfuscation
{
    meta:
        description = "Heavy PowerShell obfuscation patterns (invoke/join/char arrays)"
        author = "TRUDI"
        severity = "medium"

    strings:
        $chr   = "[char]" ascii wide nocase
        $join  = "-join" ascii wide nocase
        $split = "-split" ascii wide nocase
        $iex   = "IEX" ascii wide nocase
        $inv   = "Invoke-Expression" ascii wide nocase
        $b64   = { 22 [1-3] 41 41 41 41 [1-200] 3D 3D 22 }  // "AAAA...==" base64 blob

    condition:
        ($chr and ($join or $split) and ($iex or $inv))
        or ($b64 and ($iex or $inv))
}

rule PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell download-and-execute cradles"
        author = "TRUDI"
        severity = "high"

    strings:
        $webclient  = "Net.WebClient" ascii wide nocase
        $webreq     = "Invoke-WebRequest" ascii wide nocase
        $iwr        = "iwr " ascii wide nocase
        $downloadstr = "DownloadString" ascii wide nocase
        $downloadfile = "DownloadFile" ascii wide nocase
        $iex        = "IEX" ascii wide nocase
        $invoke     = "Invoke-Expression" ascii wide nocase

    condition:
        ($webclient or $webreq or $iwr) and ($downloadstr or $downloadfile) and ($iex or $invoke)
}
