# Skill: Memory Forensics (Volatility 3 / Memory Baseliner)

## Overview
Use this skill for all memory image analysis on the SIFT workstation. Always run as root
(`sudo su`) — some plugins require elevated privileges to resolve symbols.

## Tools

| Tool | Binary | Purpose |
|------|--------|---------|
| Volatility 3 | `/opt/volatility3-2.20.0/vol.py` | Process, network, registry, injection, and artifact extraction |
| Memory Baseliner | `/opt/memory-baseliner/baseline.py` | Diff suspect image against clean baseline |

> **CRITICAL:** `/usr/local/bin/vol.py` is **Volatility 2** (Python 2) — do NOT use it.
> Always use the full path: `/opt/volatility3-2.20.0/vol.py`

> **Symbol Downloads:** Volatility 3 downloads PDB symbol tables from Microsoft on first use
> per OS version. Requires internet access unless symbols are already cached locally.
> Test with `ping 8.8.8.8`. Use `--offline` to fail fast rather than hanging.

---

## Quick Setup (Recommended)

```bash
# Add alias to avoid typing full path every command
alias vol="/opt/volatility3-2.20.0/vol.py"

# Elevate once per session — required for some plugins
sudo su

# Create output dirs before starting
mkdir -p ./analysis/memory ./exports/dumpfiles ./exports/malfind ./exports/memdump
```

**Output renderers** (use `-r <renderer>` flag):
| Renderer | Description |
|----------|-------------|
| `quick` | Default: fast tab-separated output |
| `pretty` | Human-readable table with column headers (use for pstree) |
| `csv` | Comma-separated (pipe to file for spreadsheet analysis) |
| `json` | JSON output (for scripted processing) |
| `jsonl` | JSON Lines (one JSON object per line — stream-friendly) |
| `none` | Suppress output (useful for dump-only runs) |

---

## Plugin Reference by Category

### Process Enumeration

| Plugin | Method | Notes |
|--------|--------|-------|
| `windows.pslist` | EPROCESS linked list walk | Fast; misses unlinked (hidden) processes |
| `windows.psscan` | Pool tag scan (`Proc`) | **Finds hidden + exited processes** — use this |
| `windows.pstree` | EPROCESS hierarchy | Parent-child relationships |
| `windows.psdisptree` | Dispatcher objects | Alternative tree view |

```bash
# Full process enumeration — run both, compare results
vol -f <image.img> windows.psscan > ./analysis/memory/psscan.txt
vol -f <image.img> windows.pstree > ./analysis/memory/pstree.txt

# Readable pstree (trim to first 11 columns)
vol -f <image.img> -r pretty windows.pstree | cut -d '|' -f 1-11 > ./analysis/memory/pstree-cut.txt

# Filter to a specific PID and its children
vol -f <image.img> -r pretty windows.pstree --pid <PID> | cut -d '|' -f 1-11

# Identify exited processes (ExitTime is not N/A)
grep -v "N/A" ./analysis/memory/psscan.txt | grep -v "^Offset"

# Processes present in psscan but NOT in pslist = hidden
diff <(awk '{print $3}' ./analysis/memory/psscan.txt | sort) \
     <(vol -f <image.img> windows.pslist | awk '{print $2}' | sort)
```

### Process Details

```bash
# Command lines — most revealing for attacker activity
vol -f <image.img> windows.cmdline > ./analysis/memory/cmdline.txt
vol -f <image.img> windows.cmdline --pid <PID>

# Environment variables (reveals injected env, working directory)
vol -f <image.img> windows.envars > ./analysis/memory/envars.txt
vol -f <image.img> windows.envars --pid <PID>

# Security identifiers / account context
vol -f <image.img> windows.getsids --pid <PID>

# Token privileges (look for SeDebugPrivilege, SeTcbPrivilege)
vol -f <image.img> windows.privs --pid <PID>

# Loaded DLLs (check for spoofed or injected DLLs)
vol -f <image.img> windows.dlllist --pid <PID>

# Open handles (files, registry keys, mutexes, events, threads)
vol -f <image.img> windows.handles --pid <PID>
vol -f <image.img> windows.handles --pid <PID> --object-type File
vol -f <image.img> windows.handles --pid <PID> --object-type Mutant
vol -f <image.img> windows.handles --pid <PID> --object-type Key
```

### Network Connections

```bash
# Walk TCP/IP structures (active connections at capture time)
vol -f <image.img> windows.netstat  > ./analysis/memory/netstat.txt

# Pool-tag scan (finds closed/historical connections too)
vol -f <image.img> windows.netscan  > ./analysis/memory/netscan.txt

# Extract all unique remote IPs for IOC pivot
grep -v "^Offset\|127.0.0.1\|0.0.0.0" ./analysis/memory/netscan.txt | \
  awk '{print $5}' | sort -u
```

`netscan` uses pool scanning and finds historical connections; `netstat` reflects current state.

### Services

```bash
# Enumerate services (pool scan — finds hidden services)
vol -f <image.img> windows.svcscan > ./analysis/memory/svcscan.txt

# Cross-reference service SIDs against known list
vol -f <image.img> windows.getservicesids

# Look for services with unusual binary paths
grep -i "\\\\temp\\|\\\\appdata\\|\\\\users\\" ./analysis/memory/svcscan.txt
```

### Registry

```bash
# List all loaded hive virtual addresses
vol -f <image.img> windows.registry.hivelist > ./analysis/memory/hivelist.txt

# Read a specific key
vol -f <image.img> windows.registry.printkey \
  --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

vol -f <image.img> windows.registry.printkey \
  --key "SYSTEM\CurrentControlSet\Services"

# UserAssist — GUI execution evidence (programs launched via Explorer)
vol -f <image.img> windows.registry.userassist > ./analysis/memory/userassist.txt
```

### Code Injection & Anomalous Memory

```bash
# Primary injection scanner — finds RWX regions with PE headers or shellcode
vol -f <image.img> windows.malfind > ./analysis/memory/malfind.txt
vol -f <image.img> windows.malfind --dump --output-dir ./exports/malfind/

# VAD (Virtual Address Descriptor) tree — inspect all memory regions for a process
vol -f <image.img> windows.vadinfo --pid <PID> > ./analysis/memory/vadinfo_<PID>.txt

# Look for MZ-headed regions not backed by a file (classic hollowing indicator)
grep -A5 "MZ" ./analysis/memory/malfind.txt

# YARA scan of process VAD regions directly from memory
vol -f <image.img> windows.vadyarascan --yara-rules /path/to/rules.yar
vol -f <image.img> windows.vadyarascan --pid <PID> --yara-rules /path/to/rules.yar

# Kernel module enumeration
vol -f <image.img> windows.modules   > ./analysis/memory/modules.txt    # linked list
vol -f <image.img> windows.modscan   > ./analysis/memory/modscan.txt    # pool scan (hidden)

# Modules in modscan but NOT in modules = hidden/rootkit driver
```

### File & Code Extraction

```bash
# List all files cached in memory (use for finding dropped malware)
vol -f <image.img> windows.filescan > ./analysis/memory/filescan.txt

# Dump a file by virtual offset (from filescan)
vol -f <image.img> windows.dumpfiles \
  --virtaddr <0xffffff...> \
  --output-dir ./exports/dumpfiles/

# Dump a process executable to disk
vol -f <image.img> windows.pslist --dump --pid <PID>

# Dump all mapped memory pages for a process
vol -f <image.img> windows.memmap --dump --pid <PID> --output-dir ./exports/memdump/
```

### Strings Extraction from Process Memory

```bash
# Step 1: dump process memory
vol -f <image.img> windows.memmap --dump --pid <PID> --output-dir ./exports/memdump/

# Step 2: extract ASCII and Unicode strings (min 8 chars to reduce noise)
strings -a -n 8  ./exports/memdump/pid.<PID>.dmp > ./analysis/memory/strings_<PID>_ascii.txt
strings -a -el -n 8 ./exports/memdump/pid.<PID>.dmp > ./analysis/memory/strings_<PID>_unicode.txt

# Step 3: hunt for IOC patterns
grep -Ei "(https?://|ftp://|\\\\\\\\|cmd\.exe|powershell|regsvr|certutil)" \
  ./analysis/memory/strings_<PID>_ascii.txt
```

### Timeline

```bash
# Generate timeline of all memory artifacts
vol -f <image.img> timeliner --create-bodyfile > ./analysis/memory/mem_bodyfile.txt
mactime -b ./analysis/memory/mem_bodyfile.txt -z UTC > ./analysis/memory/mem_timeline.txt
```

---

## Memory Baseliner Workflow

Compares a suspect memory image against a known-good JSON baseline to surface
anomalous processes, drivers, and services without requiring a second clean image.

```bash
sudo su
cd /path/to/case/

# Process comparison (-proc)
python3 /opt/memory-baseliner/baseline.py \
  -proc \
  -i <suspect.img> \
  --loadbaseline \
  --jsonbaseline <baseline.json> \
  -o ./analysis/memory/proc_baseline.csv

# Driver comparison (-drv) — critical for rootkit detection
python3 /opt/memory-baseliner/baseline.py \
  -drv \
  -i <suspect.img> \
  --loadbaseline \
  --jsonbaseline <baseline.json> \
  -o ./analysis/memory/drv_baseline.csv

# Service comparison (-svc)
python3 /opt/memory-baseliner/baseline.py \
  -svc \
  -i <suspect.img> \
  --loadbaseline \
  --jsonbaseline <baseline.json> \
  -o ./analysis/memory/svc_baseline.csv

# Convert pipe-delimited output to true CSV
sed -i 's/|/,/g' ./analysis/memory/proc_baseline.csv
sed -i 's/|/,/g' ./analysis/memory/drv_baseline.csv
sed -i 's/|/,/g' ./analysis/memory/svc_baseline.csv
```

> **IMPORTANT:** `--loadbaseline` is a standalone boolean flag. `--jsonbaseline <path>` is the
> separate argument that specifies the JSON file path. They must both be present when loading
> an existing baseline.

**Creating a new JSON baseline from a known-good image:**
```bash
python3 /opt/memory-baseliner/baseline.py \
  -proc \
  -i <clean-baseline.img> \
  --savebaseline \
  --jsonbaseline <output_baseline.json>
```

**Comparison mode flags (what attributes to diff):**
| Flag | Description |
|------|-------------|
| `--imphash` | Compare import hashes of processes/DLLs |
| `--owner` | Compare process owner (username/SID) |
| `--cmdline` | Compare full command line of each process |
| `--state` | Compare process state (running, exited) |

**Stacking flags (show only items unique to the suspect image):**
| Flag | Description |
|------|-------------|
| `-procstack` | Stack-rank non-baseline processes |
| `-dllstack` | Stack-rank non-baseline DLLs |
| `-drvstack` | Stack-rank non-baseline drivers |
| `-svcstack` | Stack-rank non-baseline services |

**All Baseliner flags:**
| Flag | Description |
|------|-------------|
| `-proc` | Compare processes and loaded DLLs |
| `-drv` | Compare kernel drivers (rootkit detection) |
| `-svc` | Compare services |
| `--loadbaseline` | Load mode (boolean — use with `--jsonbaseline`) |
| `--jsonbaseline <file>` | Path to JSON baseline file (load or save) |
| `--savebaseline` | Save new baseline from this image |
| `--showknown` | Include baseline-matching items (verbose output) |
| `-o <file>` | Output CSV path |

---

## Six-Step Analysis Methodology

1. **Identify rogue processes** — `windows.psscan` (pool scan finds hidden/exited); compare against `windows.pslist`
2. **Analyze parent-child relationships** — `windows.pstree`; look for LOLBins spawned from unexpected parents
3. **Examine process command lines & environment** — `windows.cmdline`, `windows.envars`, `windows.privs`
4. **Review network connections** — `windows.netstat` + `windows.netscan`; extract unique external IPs
5. **Look for code injection** — `windows.malfind`, `windows.vadinfo`, `windows.vadyarascan`; dump and triage hits
6. **Baseline comparison** — Memory Baseliner `-proc`, `-drv`, `-svc`; pivot any non-baseline items

---

## Process Anomaly Indicators

| Anomaly | What to Look For |
|---------|-----------------|
| Wrong binary path | `svchost.exe` not in `System32\`; `lsass.exe` anywhere but `System32\` |
| Wrong parent | `svchost.exe` parent ≠ `services.exe`; `lsass.exe` parent ≠ `wininit.exe` |
| `taskhostw.exe` sibling | Process launched as a scheduled task |
| `conhost.exe` child | Console I/O attached — hands-on-keyboard attacker |
| LOLBin with suspicious args | `cmd.exe`, `powershell.exe`, `net.exe`, `wmic.exe`, `mshta.exe`, `certutil.exe` |
| Orphaned process | PPID not present in process list — possible hollowing or injection |
| Very short-lived processes | Exited in < 5 seconds — atomic actions or AV termination |
| Missing image path | No on-disk backing file (DLL injection / reflective loading) |
| Unsigned kernel modules | In `modscan` but absent from `modules`, or no valid signature |
| High privilege context | `SeDebugPrivilege` or `SeTcbPrivilege` in unexpected process |
| RWX VAD without file backing | Classic shellcode injection indicator from `malfind` |

---

## Error Handling

**Symbol download failure / hanging:**
```bash
# Force offline mode (fail fast on missing symbols)
vol --offline -f <image.img> windows.pslist

# Manually pre-download symbols for offline environments
# ISF files: https://downloads.volatilityfoundation.org/volatility3/symbols/
# Place in: /opt/volatility3-2.20.0/volatility3/symbols/windows/
```

**Plugin error / empty output:**
```bash
# Redirect both stdout and stderr for full diagnostic output
vol -f <image.img> windows.pslist 2>&1 | tee ./analysis/memory/plugin_errors.txt

# Check image format is recognized
file <image.img>
vol -f <image.img> windows.info
```

**Permission errors:**
```bash
# Ensure root for full plugin access
sudo /opt/volatility3-2.20.0/vol.py -f <image.img> windows.psscan
```

---

## Output Paths

| Output | Path |
|--------|------|
| Volatility text output | `./analysis/memory/` |
| Dumped files from filescan | `./exports/dumpfiles/` |
| Malfind dumps | `./exports/malfind/` |
| Process memory dumps | `./exports/memdump/` |
| Baseline comparison CSVs | `./analysis/memory/proc_baseline.csv` etc. |
| Memory bodyfile/timeline | `./analysis/memory/mem_timeline.txt` |

---

## Notes

- Always run `windows.psscan` AND `windows.pslist` — discrepancies reveal hidden processes
- `windows.malfind` produces false positives (JIT-compiled code, .NET CLR) — triage hits manually
- `windows.netscan` may show connections from before image capture time — correlate with disk timeline
- `windows.svcscan` surfaces services configured but not yet loaded, and deleted services still in memory
- Volatility 3 plugins are `windows.X` format (not `windows.X.X` as in Vol2)
