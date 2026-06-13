# Skill: Threat Hunting & IOC Sweeps (YARA / Velociraptor)

## Overview
Use this skill for IOC sweeps, malware identification, and threat hunting.
YARA 4.1.0 runs locally on SIFT Linux for scanning files and memory images.
Velociraptor is an endpoint agent — hunts are deployed via its web console,
not run directly from the SIFT command line.

---

## Tool Reference

| Tool | Location | Platform |
|------|----------|----------|
| `yara` | `/usr/local/bin/yara` (v4.1.0) | SIFT Linux — local file/memory scanning |
| `yarac` | `/usr/local/bin/yarac` | SIFT Linux — rule compiler |
| Velociraptor | Enterprise endpoint deployment | Web console — not a local SIFT binary |

---

## YARA Rule Structure

```yara
rule RuleName
{
    meta:
        description = "Detects X"
        author      = "Analyst Name"
        date        = "YYYY-MM-DD"
        hash        = "SHA256 of reference sample"
        reference   = "Case number or source"

    strings:
        // Hex patterns (use ?? for wildcard bytes)
        $mz     = { 4D 5A }
        $hex1   = { 48 8B ?? 48 89 ?? ?? 48 8B ?? }   // wildcarded opcodes

        // String patterns
        $str1   = "suspicious_string" nocase
        $str2   = "another_string"    wide ascii        // scan both encodings
        $str3   = "C:\\Windows\\Temp\\" wide nocase

        // Regex
        $re1    = /net\s+use\s+[A-Z]:\s+\\\\/
        $re2    = /[A-Za-z0-9+\/]{40,}={0,2}/          // base64 blob

    condition:
        uint16(0) == 0x5A4D and   // MZ header
        filesize < 5MB and
        any of them
}
```

---

## YARA Module Imports

### PE Module (Windows Executables)

```yara
import "pe"

rule Suspicious_PE
{
    meta:
        description = "PE with high section entropy and no exports"

    condition:
        pe.is_pe and
        pe.number_of_sections > 3 and
        pe.number_of_exports == 0 and
        // Check for packed/encrypted section (entropy > 7.0)
        for any section in pe.sections : (
            section.name != ".rsrc" and
            math.entropy(section.raw_offset, section.raw_size) > 7.0
        )
}
```

**Useful PE module fields:**
| Field | Description |
|-------|-------------|
| `pe.is_pe` | True if valid PE header |
| `pe.imphash()` | Import hash (pivots to related malware families) |
| `pe.number_of_imports` | Import count |
| `pe.number_of_exports` | Export count |
| `pe.number_of_sections` | Section count |
| `pe.timestamp` | Compile timestamp (can be forged) |
| `pe.imports("kernel32.dll", "VirtualAlloc")` | Specific import check |
| `pe.exports("DllEntryPoint")` | Specific export check |
| `pe.sections[i].name` | Section name (`.text`, `.data`, etc.) |
| `pe.sections[i].characteristics` | Section permissions flags |
| `pe.version_info["CompanyName"]` | Version info strings |

### Math Module (Entropy Detection)

```yara
import "math"

rule High_Entropy_File
{
    meta:
        description = "File with high overall entropy — likely packed or encrypted"

    condition:
        math.entropy(0, filesize) > 7.2
}

rule High_Entropy_Section_PE
{
    meta:
        description = "PE with a high-entropy section (packed/obfuscated)"

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_sections - 1) : (
            math.entropy(pe.sections[i].raw_offset, pe.sections[i].raw_size) > 7.0
        )
}
```

### Hash Module (Hash-Based IOC Matching)

```yara
import "hash"

rule Known_Bad_Hash
{
    meta:
        description = "Match by MD5 hash of known malware sample"

    condition:
        // hash.md5(offset, size) — use 0, filesize for whole file
        hash.md5(0, filesize) == "d41d8cd98f00b204e9800998ecf8427e" or
        hash.sha256(0, filesize) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

---

## YARA Scanning

### Scan a Single File
```bash
yara /path/to/rules.yar /path/to/file
```

### Scan a Directory Recursively
```bash
yara -r /path/to/rules.yar /mnt/windows_mount/Windows/System32/
```

### Scan a Memory Image
```bash
yara /path/to/rules.yar /path/to/memory.img
```

### Scan Exported Files from Evidence
```bash
yara -r /path/to/rules.yar ./exports/files/
```

### Scan with Match Detail (Show Matching Strings)
```bash
yara -r -s /path/to/rules.yar ./exports/files/ 2>/dev/null | tee ./exports/yara_hits/hits.txt
```

### Scan with Metadata Output
```bash
yara -r -m /path/to/rules.yar /mnt/windows_mount/ 2>/dev/null
```

### Useful Flags
| Flag | Description |
|------|-------------|
| `-r` | Recursive directory scan |
| `-s` | Print matching strings (with offset) |
| `-m` | Print rule metadata |
| `-e` / `--print-namespace` | Print rule namespace in output |
| `-n` | Print non-matching rules (invert — for testing) |
| `-f` | Fast scan mode (first match only per rule) |
| `-p N` | Use N threads for parallel scanning |
| `--timeout N` | Skip file after N seconds |
| `-t TAG` / `--tag=TAG` | Only apply rules tagged with TAG |
| `--scan-list` | Input is a text file listing paths to scan (one per line) |
| `-N` / `--no-follow-symlinks` | Do not follow symlinks (prevents loops in recursive scans) |
| `--max-rules=NUMBER` | Abort scan after NUMBER rules match |
| `-x <module>=<file>` | Load external module |
| `-d <var>=<val>` | Define external variable |

---

## Rule Compilation (Repeated Large-Scale Scanning)

```bash
# Compile rules to binary for faster re-use (avoids re-parsing .yar each run)
yarac rules.yar compiled.rules

# Scan using compiled rules
yara -C compiled.rules /target/path/
```

---

## Performance Best Practices

**Condition ordering matters — YARA evaluates left to right and short-circuits:**
```yara
condition:
    // Put cheap, specific checks FIRST to eliminate non-matches early
    uint16(0) == 0x5A4D and    // 1. Fast: 2-byte read at offset 0
    filesize < 10MB and         // 2. Fast: metadata check
    pe.is_pe and                // 3. Medium: PE structure validation
    $str1 and                   // 4. Medium: string match
    math.entropy(...) > 7.0    // 5. Expensive: full entropy scan — LAST
```

**Other tips:**
- Use `filesize < X` as the first condition to skip large files when hunting small malware
- Use `pe.is_pe` to scope rules to PE files only instead of scanning everything
- Compile rules once with `yarac` before scanning large directories
- Use `-f` (fast mode) for initial triage; rescan hits with `-s` for details
- Use `-p 4` or more threads on multi-core SIFT for directory scans

---

## IOC Sweep Workflow

1. **Build IOC list** from confirmed findings (file hashes, strings, IPs, domains, paths, mutex names)
2. **Write YARA rules** targeting each IOC type — one rule per indicator family
3. **Test rules for false positives** against a clean image or known-good file set first
4. **Scan mounted evidence** — `yara -r -s <rules> /mnt/windows_mount/`
5. **Scan memory image** — `yara <rules> /path/to/memory.img`
6. **Scan extracted files** — `yara -r <rules> ./exports/files/`
7. **Cross-reference hits** with filesystem timeline and process artifacts
8. **Export findings** to `./exports/yara_hits/ioc_sweep_<CASE_ID>_<date>.txt`

### False Positive Testing

```bash
# Test rules against a known-clean directory before sweeping evidence
yara -r rules.yar /usr/bin/ 2>/dev/null

# Use -n to see which rules did NOT match (verify scope coverage)
yara -r -n rules.yar /path/to/sample/

# Test a single rule in isolation
yara -r /path/to/single_rule.yar /path/to/target/
```

---

## Community Rulesets

```bash
# Check for community rulesets on SIFT (may be pre-installed)
ls /opt/yara-rules/ 2>/dev/null
ls /opt/signature-base/ 2>/dev/null

# Common community sources to pull manually:
# Neo23x0 / Florian Roth: https://github.com/Neo23x0/signature-base
# Elastic Security: https://github.com/elastic/protections-artifacts
# Mandiant / FireEye: Included in threat intel reports
# CISA advisories: https://www.cisa.gov/resources-tools/resources/malware-analysis-reports

# Use community rules with a filter to avoid noisy catches
yara -r /opt/signature-base/yara/ /mnt/windows_mount/ 2>/dev/null | grep -v "^$"
```

---

## Rule Storage

```
~/.claude/skills/yara-hunting/rules/    ← store reusable rules here
./exports/yara_hits/                    ← scan output for current case
./reports/                              ← finalized IOC sweep reports
```

---

## Velociraptor (Enterprise Endpoint Hunting)

Velociraptor is deployed on Windows endpoints in the environment under investigation.
Connect to the Velociraptor web console to run hunts across live or collected endpoints.
**It is NOT a local binary on the SIFT workstation.**

### Key Concepts
- **Artifact:** A named collection/query (e.g., `Windows.System.Pslist`)
- **Hunt:** Deploy an artifact across multiple endpoints simultaneously
- **VQL:** Velociraptor Query Language (SQL-like syntax for live system queries)

### Common Artifacts for Threat Hunting

| Artifact | Purpose |
|----------|---------|
| `Windows.System.Pslist` | Process listing |
| `Windows.Sysinternals.Autoruns` | Persistence / ASEPs |
| `Windows.Network.Netstat` | Active network connections |
| `Windows.System.TaskScheduler` | Scheduled tasks |
| `Windows.Forensics.Prefetch` | Execution evidence |
| `Windows.Forensics.Lnk` | Recent files / LNK files |
| `Windows.Forensics.SRUM` | SRUM resource usage |
| `Windows.Forensics.MFT` | MFT parsing |
| `Windows.EventLogs.EvtxHunter` | Search event logs by keyword |
| `Windows.Detection.Yara.Process` | YARA scan of process memory |
| `Windows.Detection.Yara.File` | YARA scan of files on disk |
| `Windows.Detection.Yara.NTFS` | YARA scan via raw NTFS access |

### Deploy a YARA Hunt (VQL reference)
```vql
SELECT * FROM Artifact.Windows.Detection.Yara.Process(
    YaraRule='''
rule ExampleRule {
  strings: $s = "indicator_string" nocase
  condition: $s
}
''')
```

### VQL — Quick Triage Queries

```vql
-- Find processes with no parent
SELECT Name, Pid, Ppid, Exe
FROM pslist()
WHERE NOT Ppid IN (SELECT Pid FROM pslist())

-- Find network connections to non-private IPs
SELECT Pid, FamilyString, RemoteAddr, RemotePort, Status
FROM netstat()
WHERE NOT RemoteAddr =~ "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1)"

-- Hunt for scheduled tasks with suspicious paths
SELECT Name, Command, Arguments
FROM scheduledtasks()
WHERE Command =~ "(temp|appdata|\\\\users\\\\)" OR
      Arguments =~ "(powershell|cmd|wscript|mshta)"
```
