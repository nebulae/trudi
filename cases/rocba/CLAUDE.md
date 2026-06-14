# Case: ROCBA

**Evidence integrity: Never modify evidence files. All output to `./analysis/`, `./exports/`, or `./reports/`.**

---

## Case Metadata

| Field | Value |
|-------|-------|
| **Case ID** | ROCBA |
| **Client** | Stark Research Labs (SRL) |
| **Victim** | Fred Rocba — engineering hire (start date 2020-10-26) |
| **System** | Microsoft Surface, single-user, shipped by Microsoft to Fred's home |
| **Incident** | Physical break-in to Fred's home; theft appears to have targeted the SRL Surface |
| **Incident date** | 2020-11-13 (while Fred was on planned vacation) |
| **Your role** | External DFIR consultant — Windows endpoint forensics |
| **Dataset** | SANS FOR500 Windows Forensic Analysis — Fred Rocba case |

---

## Scope

Determine **what SRL intellectual property the actor accessed or exfiltrated** from Fred's Surface during the 2020-11-13 break-in window, **how** the data was moved off the system (USB, cloud sync, email, RDP, web upload), **where** it went, and **when** the activity occurred. Fred is the victim, not the suspect — but his account activity is the baseline against which intruder activity must be distinguished.

It is unknown at case open what IP was taken or by what mechanism. The 5 key investigative questions (FOR500 framing):

1. What key SRL projects did Fred have access to?
2. What was stolen?
3. Where was it transferred to?
4. How was it stolen?
5. When did the activity occur?

---

## Case Background

| Date (local, EST) | Event |
|-------------------|-------|
| 2020-10-24 | Fred interviewed and accepted offer at SRL |
| 2020-10-24 | New Microsoft Surface shipped from MS to Fred's home for remote work |
| 2020-10-26 | Fred begins work at SRL |
| 2020-11-10 | Fred departs on planned vacation (Disney, FL) |
| 2020-11-13 | Home break-in; SRL Surface targeted |
| — | Unknown what IP was taken or how |

Fred's normal work pattern is **RDP into SRL infrastructure + cloud applications**, using a personal Microsoft account on a system installed with the same SaaS app set he used previously. Any access that does not match Fred's vacation-period absence (2020-11-10 → return) is presumptive intruder activity.

---

## Victim Profile (frocba)

| Attribute | Value |
|-----------|-------|
| Email | `frocba@stark-research-labs.com` (Office 365 Exchange) |
| Microsoft account | Personal MS account also signed into the device |
| Primary apps | Office 365, SharePoint, OneDrive (Personal AND Business), Exchange Online via Local Outlook, Microsoft Portal Online, RDP |
| OS | Windows, fully patched and updated |
| Single-user | Yes — only Fred's profile expected |
| System time zone | **EST5EDT** (Eastern, UTC-5 / UTC-4 DST) — convert all artifact timestamps to UTC for reporting |

The dual cloud-identity setup (personal MS account + Office 365 work account, both with OneDrive) is forensically significant: **two independent cloud sync paths exist**, either of which could be the exfiltration channel.

---

## SRL Projects (potential targets of theft)

SRL specializes in metals/alloys and biotech R&D for defensive and offensive applications, contracting with DoAP / AARP-OLD and Harbinger Corporation. Publicly disclosed research projects Fred may have had access to:

| Project | Domain |
|---------|--------|
| Metal Alloy Bicycle Helmet | Lightweight protective alloys |
| High-Entropy Alloys (HEAs) | Military / LEO body protection |
| Copper Alloy Research | Antimicrobial healthcare surfaces |
| Bulletproof Cotton | Flexible blast/ballistic fabrics |

Treat references to these project names — and their associated file names, document codes, CAD/CAM files, or chemistry data — as **first-priority artifacts** in browser history, OneDrive sync logs, Recent Items, Jump Lists, Shellbags, LNK files, Outlook, and `$MFT` searches.

---

## Investigation Foci (FOR500 — single-host endpoint)

This is **not** an enterprise APT case. There is no confirmed malware, no known threat actor, no enterprise lateral-movement question. Prioritize Windows user-activity artifacts:

| Category | Artifacts |
|----------|-----------|
| **Account & logon** | SAM hive (local accounts, last login), Security event log (4624/4625/4634/4647, type 7=unlock, type 10=RemoteInteractive), Profile creation timestamps in SOFTWARE\Microsoft\Windows NT\ProfileList |
| **Time-of-activity anchoring** | System event log (6005/6006/6013/1/42), SYSTEM\ControlSet\Control\Windows\ShutdownTime, last-write times on user hive keys, UserAssist GUID timestamps |
| **File access & opening** | ShellBags (BCD/NTUSER.DAT), RecentDocs, OpenSavePidlMRU, LastVisitedPidlMRU, JumpLists (`AutomaticDestinations`/`CustomDestinations`), LNK files in `Recent\` |
| **Program execution** | Prefetch, Amcache (`Amcache.hve`), ShimCache (AppCompatCache), UserAssist, BAM/DAM, SRUM (`SRUDB.dat`) |
| **External devices** | SYSTEM\MountedDevices, USBSTOR, SetupAPI.log, EMDMgmt, Volume Shadow — **critical for "USB exfil" hypothesis** |
| **Browser activity** | Edge/Chrome `History`, `Cookies`, `Login Data`, `Web Data`, `Downloads`, cache; IE/Edge typed URLs in NTUSER; sync to MS account |
| **Cloud sync (OneDrive)** | `%LOCALAPPDATA%\Microsoft\OneDrive\logs\Personal\` AND `\Business1\`; `SyncDiagnostics.log`, `SyncEngine.log`, `<ID>.dat`/`.odl` files (parse with `OneDriveExplorer` / odl tools); Recycle Bin in OneDrive folder |
| **Email** | Local Outlook OST/PST under `%LOCALAPPDATA%\Microsoft\Outlook\` — parse with `misc.readpst_extract` or `misc.pff_export` |
| **Remote access** | RDP outbound from Fred's Surface: Microsoft-Windows-TerminalServices-Client/Operational (event 1024/1102); `Default.rdp`; bitmap cache (`bcache*.bmc`, `Cache0000.bin`) — bitmap cache may reveal what was viewed on the remote SRL system |
| **Data transfer volume** | SRUM `Application Resource Usage` / `Network Usage` — bytes-sent per process per hour. Correlate spikes with the break-in window |
| **Persistence / anti-forensics** | Autoruns, Scheduled Tasks, USN journal for deletion bursts, $LogFile, deleted Prefetch, RecentFileCache, Windows Search index (`Windows.edb`) for content traces |
| **Photos sync (vacation alibi)** | Disney photos auto-syncing to the system during the vacation window confirm device was online while Fred was away — distinguishes Fred's continued cloud activity from intruder physical access |

---

## Evidence

Images are **in place but not yet mounted**. Hash and verify before any analysis (`hash.verify_evidence_hash` once per file per case — no companion `.md5` files exist, so compute baseline hashes at case open and record them in the trace).

| System | Type | Path | Size | File mtime | EWF mount | FS mount |
|--------|------|------|------|------------|-----------|----------|
| Fred's Surface | C: drive (E01) | `~/cases/rocba/evidence/rocba-cdrive.e01` | 23.7 GB | 2022-05-23 (file copy time — original acquisition predates) | `/mnt/ewf_rocba` | `/mnt/rocba` |
| Fred's Surface | Memory (raw) | `~/cases/rocba/evidence/Rocba-Memory.raw` | 19.0 GB | 2020-11-19 (≈6 days after break-in — likely acquisition date) | — | — |

**Memory image IS present** — revise expectations from the "post-incident, disk-only" assumption: someone acquired live memory ≈6 days after the break-in. Volatility 3 is in scope; run `vol.symbol_check` at case open. The 19 GB size implies a high-RAM Surface device, so allow extra time on Volatility plugin runs.

Mount directories are **not pre-created** — `sudo mkdir /mnt/ewf_rocba /mnt/rocba` then `ewf.mount_full_image` for the E01. The memory raw is read directly by Volatility; no mount needed.

### Registry hive paths (once disk is mounted at `/mnt/rocba/`)

| Hive | Path |
|------|------|
| SOFTWARE | `/mnt/rocba/Windows/System32/config/SOFTWARE` |
| SYSTEM | `/mnt/rocba/Windows/System32/config/SYSTEM` |
| SAM | `/mnt/rocba/Windows/System32/config/SAM` |
| SECURITY | `/mnt/rocba/Windows/System32/config/SECURITY` |
| Fred's NTUSER | `/mnt/rocba/Users/<profile>/NTUSER.DAT` — enumerate `/mnt/rocba/Users/` and cross-check `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` SIDs to pick the right one |
| Fred's USRCLASS | `/mnt/rocba/Users/<profile>/AppData/Local/Microsoft/Windows/UsrClass.dat` |

---

## Output Directories

```
~/cases/rocba/analysis/    — intermediate work, parsed artifacts
~/cases/rocba/exports/     — tool output (CSV, JSON, bodyfiles)
~/cases/rocba/reports/     — final investigator reports
```

---

## Tool Notes

- **Volatility 3 binary:** `/usr/local/bin/vol` — memory image is present; run `vol.symbol_check` first to confirm symbols are cached for this build
- **VSCMount:** Windows-only — do not use
- **MemProcFS / Memory Baseliner:** not installed on this SIFT instance
- **YARA rules:** bundled TTP ruleset at `~/trudi/rules/` (cobalt_strike, persistence, lateral_movement, powershell, anti_forensics) — lower priority for this case profile but run against any unsigned/suspicious binaries discovered
- **OneDrive log parsing:** `OneDriveExplorer` (if installed) or manual `.odl` parsing — both Personal and Business log roots must be processed
- **Outlook OST/PST:** route through `misc.readpst_extract` (PST) or `misc.pff_export` (OST/PST via libpff)
- **Browser:** Hindsight (`misc.hindsight_chrome`) for Chromium-family Edge; SQLECmd for the History/WebCacheV01.dat sqlite-and-ESE files
- **All timestamps in UTC** in findings and reports — convert from EST5EDT system time

---

## Pivot Hostname Prefixes

Single-host case — pivot detection is not the primary concern. If any internal SRL hostnames appear in browser history, RDP `Default.rdp`, mapped drives, or `\\HOST\` UNC paths in Jump Lists/LNK, surface them as `recommended_actions` (not phase-stack pivots) since we don't have evidence images for them.
