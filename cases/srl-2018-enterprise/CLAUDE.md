# Case: SRL-2018-ENTERPRISE

**Evidence integrity: Never modify evidence files. All output to `./analysis/`, `./exports/`, or `./reports/`.**

---

## Case Metadata

| Field | Value |
|-------|-------|
| **Case ID** | SRL-2018-ENTERPRISE |
| **Client** | Stark Research Labs (SRL) |
| **Domain** | SHIELDBASE (Windows Server 2022, 2022 DFL) |
| **Threat Actor** | CRIMSON OSPREY (state-level APT) |
| **Incident declared** | 2023-01-24 UTC |
| **Investigator** | Nebulae |
| **Role** | External IR consultant |
| **Initial responders** | Roger Sydow (IT Admin), Clint Barton (IT Security Analyst) |

---

## Scope

Determine the full scope of CRIMSON OSPREY's access across the SRL enterprise. Establish initial access vector, attack timeline, lateral movement path, persistence mechanisms, and data exfiltration activity across all compromised hosts. **rd-01 is the primary compromise host** per initial responder report. All hosts should be triaged; prioritize based on `reason.plan` output.

---

## Network Topology

| Network | Subnet | Key Hosts |
|---------|--------|-----------|
| **Management** | 172.16.8.0/24 | log01, assess01/02, sft01, trust01, adusa01 |
| **Services** | 172.16.4.0/24 | dc01, file01, exchange01, proxy01 (Squid), dev01, sql01 |
| **Business Line** | 172.16.7.0/24 | wksta01–wksta10 (Windows 11) |
| **R&D** | 172.16.6.0/24 | rd01–rd10 (Windows 11); lateral movement target: **172.16.6.12** |
| **DMZ** | 172.16.19.0/24 | dns01, ftp01, smtp01 |
| **VPN Client** | 172.16.30.0/24 | Remote workers |

**External attacker IP:** 172.15.1.20

---

## Domain Accounts

| Account | Role |
|---------|------|
| `rsydow-a` | Domain Admin — Roger Sydow (IT Admin) |
| `cbarton-a` | Domain Admin — Clint Barton (IT Security Analyst) |
| `srl.admin` | Emergency Domain Admin (break-glass) |
| `srladmin` | Local Admin — all workstations |

---

## Known IOCs

### Confirmed malware (from initial responder report)

| Indicator | Type | Detail |
|-----------|------|--------|
| `STUN.exe` | Malware binary | `C:\Windows\System32\STUN.exe` — PID 1912, parent svchost.exe PID 1244 |
| `msedge.exe` | Masquerading binary | 7 instances spawned from STUN.exe + explorer.exe; Trojan:Win32/PowerRunner.A |
| `pssdnsvc.exe` | Suspicious service | `C:\Windows\` — name/path mismatch for PsShutdown |
| `atmfd.dll` | Missing driver | Present in Autoruns but absent from filesystem |

### Confirmed attacker activity

| Indicator | Detail |
|-----------|--------|
| Lateral movement | `net use H: \\172.16.6.12\c$\Users` — net.exe PID 9128 |
| Execution chain | STUN.exe → svchost.exe → taskhostw.exe (scheduled task) |
| Evasion | msedge.exe masquerading; Windows Defender detected and terminated repeatedly |

### Prior findings on wkstn-01 (carried forward from earlier case folder)

- **range_admin** [RID 1003]: local admin, zero logins, password reset 2018-08-29 — likely backdoor account
- **Administrator**: password reset same day (2018-08-29) as range_admin — coordinated credential activity
- **AppCompatCache**: `C:\Users\mhill\AppData\Local\SquirrelTemp\Update.exe` with timestomped timestamp (1985-10-26)
- Host is domain-joined; SIDs from two separate domains present
- No offensive tools in installed programs list; attacker likely lived off the land

---

## Incident Timeline (UTC)

| Timestamp (UTC) | Event |
|-----------------|-------|
| 2023-01-24 | Incident declared; F-Response agents deployed |
| 2023-01-25 14:52:04 | Lateral movement — `net use H: \\172.16.6.12\c$\Users` |
| 2023-01-25 14:56:42–15:04:43 | msedge.exe PIDs spawned |
| 2023-01-25 15:00:56 | msedge.exe PID 2524 active at memory capture time |
| 2023-01-29 12:23:16 | Kansa post-intrusion collection (Autorunsc timestamp) |

---

## Evidence

All evidence is in `~/cases/srl-2018-enterprise/evidence/`. Disk images are **not currently mounted** — use `ewf.mount_full_image` before accessing hives or filesystem tools. Every `.img` has a sibling `.md5` — use `hash.verify_evidence_hash` at case open, once per file per case.

### Hosts with disk + memory

| System | Role | Disk Image | Memory Image | EWF Mount | FS Mount |
|--------|------|------------|--------------|-----------|----------|
| **rd-01** | **Primary compromise** (R&D RDS, 172.16.6.11) | `base-rd-01-cdrive.E01` (17 GB) | `base-rd01-memory.img` (3 GB) | `/mnt/ewf_rd01` | `/mnt/rd01` |
| dc | Domain Controller | `base-dc-cdrive.E01` (12 GB) | `base-dc-memory.img` (5 GB) | `/mnt/ewf_dc` | `/mnt/dc` |
| file-server | File server | `base-file-cdrive.E01` (16 GB) | `base-file-memory.img` (2 GB) | `/mnt/ewf_file` | `/mnt/fileserver` |
| wkstn-01 | Business line workstation | `base-wkstn-01-c-drive.E01` (16 GB) | `base-wkstn-01-memory.img` (3 GB) | `/mnt/ewf_wkstn01` | `/mnt/wkstn01` |

### Hosts with disk only

| System | Role | Disk Image | EWF Mount | FS Mount | Mount Dirs |
|--------|------|------------|-----------|----------|------------|
| rd-02 | R&D RDS | `base-rd-02-cdrive.E01` (17 GB) | `/mnt/ewf_rd02` | `/mnt/rd02` | **sudo mkdir needed** |
| wkstn-05 | Business line workstation | `base-wkstn-05-cdrive.E01` (14 GB) | `/mnt/ewf_wkstn05` | `/mnt/wkstn05` | **sudo mkdir needed** |
| dmz-ftp | DMZ FTP server | `dmz-ftp-cdrive.E01` (12 GB) | `/mnt/ewf_dmz` | `/mnt/dmz` | pre-created |

### Hosts with memory only

Useful as pivot/triage targets and for cross-host correlation. No disk → no `ez.*`/`tsk.*` work, but full `vol.*` coverage available.

| System | Likely role | Memory Image |
|--------|-------------|--------------|
| admin | IT admin workstation (rsydow-a / cbarton-a) | `base-admin-memory.img` (5 GB) |
| av | McAfee ePO server (172.16.5.20) | `base-av-memory.img` (9 GB) |
| elf | Linux host (name suggests ELF binary platform) | `base-elf-memory.img` (5 GB) |
| hunt | Threat hunting / EDR collection box | `base-hunt-memory.img` (5 GB) |
| mail | Exchange / mail server | `base-mail-memory.img` (17 GB) |
| sp | SharePoint server (likely) | `base-sp-memory.img` (9 GB) |
| file-snapshot5 | VSS snapshot capture of file-server | `base-file-snapshot5.img` (2 GB) |
| wkstn-02 / -03 / -04 / -06 | Business line workstations | `base-wkstn-0{2,3,4,6}-memory.img` (3 GB each, wkstn-06 is 2 GB) |
| rd-03 / -04 / -05 / -06 | R&D RDS hosts | `base-rd-0{3,4,5,6}-memory.img` (3 GB each) |

Memory-only host roles above are inferred from hostname conventions — confirm via `vol_vol_symbol_check` + SOFTWARE/SYSTEM hive extraction from the memory image (`vol.registry_printkey`) before treating the role as established.

### Registry hive paths (once mounted)

| System | SOFTWARE | SYSTEM | SAM |
|--------|----------|--------|-----|
| rd-01 | `/mnt/rd01/Windows/System32/config/SOFTWARE` | `/mnt/rd01/Windows/System32/config/SYSTEM` | `/mnt/rd01/Windows/System32/config/SAM` |
| dc | `/mnt/dc/Windows/System32/config/SOFTWARE` | `/mnt/dc/Windows/System32/config/SYSTEM` | `/mnt/dc/Windows/System32/config/SAM` |
| wkstn-01 | `/mnt/wkstn01/Windows/System32/config/SOFTWARE` | `/mnt/wkstn01/Windows/System32/config/SYSTEM` | `/mnt/wkstn01/Windows/System32/config/SAM` |
| file-server | `/mnt/fileserver/Windows/System32/config/SOFTWARE` | `/mnt/fileserver/Windows/System32/config/SYSTEM` | `/mnt/fileserver/Windows/System32/config/SAM` |

---

## Output Directories

```
~/cases/srl-2018-enterprise/analysis/    — intermediate work, parsed artifacts
~/cases/srl-2018-enterprise/exports/     — tool output (CSV, JSON, bodyfiles)
~/cases/srl-2018-enterprise/reports/     — final investigator reports
```

---

## Known Context

- **Primary user on rd-01 (172.16.6.11):** `tdungan` — logged in at time of memory capture
- **Primary user on wkstn-01:** `mhill`
- **Endpoint AV:** McAfee VirusScan 8800, managed by ePO at **172.16.5.20:443**
- **F-Response Subject agent** (`subject_srv.exe`) listens on **TCP/3262** on collection targets. Inbound connections TO port 3262 are FROM the IR team examiner workstation — NOT attacker infrastructure. Do not flag as pivot host or reverse shell.

---

## Tool Notes

- **Volatility 3 binary:** `/usr/local/bin/vol` — do NOT use `/usr/local/bin/vol.py` (that is Volatility 2). Always route via `vol_*` MCP wrappers.
- **MemProcFS / VSCMount / Memory Baseliner:** not installed on this SIFT instance
- **YARA rules:** bundled TTP ruleset at `~/trudi/rules/` (cobalt_strike, persistence, lateral_movement, powershell, anti_forensics)
- **Kansa Autorunsc CSVs** (post-intrusion collection 2023-01-29): not on this SIFT instance
- All timestamps in UTC
