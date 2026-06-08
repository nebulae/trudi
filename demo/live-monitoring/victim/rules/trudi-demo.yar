/*
 * trudi-demo.yar — YARA rules for Custom.TRUDI.YaraProcess.
 *
 * Used by the live-monitoring demo only. Each rule looks for a token that
 * the matching Atomic Red Team test plants in memory so the detector
 * fires deterministically. Real-world rule packs replace this file at
 * runtime by mounting over /rules/.
 */

rule TRUDI_DEMO_ProcessInjection_T1055
{
    meta:
        author = "TRUDI demo"
        description = "Matches the in-memory marker planted by T1055.001 atomic"
        atomic = "T1055.001"
        severity = "high"
    strings:
        $marker = "TRUDI_DEMO_INJECTED_MARKER_C0FFEE"
        $altmarker = "AtomicRedTeam Process Injection"
    condition:
        any of them
}

rule TRUDI_DEMO_KnownBadBinaryString
{
    meta:
        author = "TRUDI demo"
        description = "Catches the lolbas demo binary's argv signature in memory"
        severity = "medium"
    strings:
        $argv = "TRUDI_DEMO_LOLBAS_ARG"
    condition:
        $argv
}
