# Case: CFREDS-LEAK

**Evidence integrity: Never modify evidence files. All output to `./analysis/`, `./exports/`, or `./reports/`.**

---

## Case Metadata

| Field | Value |
|-------|-------|
| **Case ID** | CFREDS-LEAK |
| **Subject** | "Iaman Informant" — Manager, Technology Development Division, **OOO** (the company) |
| **Co-actor** | "Spy Conspirator" — employee of a rival company; solicited the leak via email |
| **Crime** | Theft of confidential IP belonging to OOO and exfiltration to a rival via multiple channels |
| **Subject username** | `informant` (Windows user profile on PC) |
| **Subject sophistication** | "Sufficient authority to bypass DRM/DLP" + "slight knowledge of digital forensics" — applied anti-forensics |
| **Incident window** | 2015-03-22 → 2015-03-25 (per hint dates in NIST questions); last anti-forensic actions on PC: 2015-03-25 |
| **Dataset** | NIST CFReDS Data Leakage Case (public training set) |
| **Your role** | Internal DFIR investigator / corporate counsel |

---

## CASE_QUESTION: What confidential information did Iaman Informant exfiltrate from OOO to Spy Conspirator, via which channels (email, Google Drive, RM#1 USB, RM#2 USB, RM#3 CD-R), what anti-forensic techniques did he apply on each device, and what is the complete timeline of his leakage activity between 2015-03-22 and 2015-03-25?

Decomposes into:
1. **What was taken** — specific filenames + content categories + source paths on PC / network share / RM#1.
2. **To whom** — Spy Conspirator's email address and (if recoverable) any other identifiers.
3. **By which channel, per artifact** — email (Outlook OST), Google Drive (sync DB + VSS snapshot.db cloud_entry table), RM#1 USB (authorized), RM#2 USB (unauthorized — staged at security checkpoint), RM#3 CD-R (UDF burn).
4. **Anti-forensics** — applied separately on PC, on RM#2, and on RM#3 (per Q47, Q53, Q56). Identify the method + the residual artifact that revealed it.
5. **Timeline** — solicitation → planning → staging → exfiltration → cover-up, in system-local time AND UTC.

---

## Scenario (verbatim relevant excerpts)

> "'Iaman Informant' was working as a manager of the technology development division at a famous international company OOO that developed state-of-the-art technologies and gadgets. … 'Mr. Informant' received an offer from 'Spy Conspirator' to leak sensitive information related to the newest technology. 'Mr. Conspirator' was an employee of a rival company, and 'Mr. Informant' decided to accept the offer for large amounts of money, and began establishing a detailed leakage plan."

Channels used by the subject:
- **Email** — discussed the plan "like a business relationship" (Outlook).
- **Personal cloud storage** — sent sample data (Google Drive).
- **Storage devices** — attempted to physically remove a USB stick and a CD; both intercepted at the company's Security Checkpoint and sent to forensics.

Company policies (treat as constraints the subject knew about):
- Confidential files only on authorized external storage and secured network drives.
- Confidential file access only **10:00–16:00** local time.
- Non-authorized devices forbidden on premises.
- All employees pass the Security Checkpoint.
- All storage devices (HDD/SSD/USB/CD/DVD) forbidden under Security Checkpoint rules.
- DRM + DLP solutions in place — subject had auth to bypass them.

---

## Target Systems (from NIST)

| | Type | OS / FS | Size | Identifier |
|---|------|---------|------|------------|
| **PC** | Virtual System (VMware → converted) | Windows 7 Ultimate SP1, NTFS | 20 GB HDD, 2 GB RAM, 1 CPU/2 cores | IP `10.11.11.129` |
| **RM#1** | USB removable storage (**AUTHORIZED** for confidential files) | exFAT | 4 GB | Serial `4C530012450531101593` |
| **RM#2** | USB removable storage (unauthorized — intercepted) | FAT32 | 4 GB | Serial `4C530012550531106501` |
| **RM#3** | CD-R (UDF) — intercepted | UDF | 700 MB | — |

The two USB serials are key knowns — feed them to `misc.knowns_pattern_generate(derivation_type='exact')` and hunt their occurrence in `SYSTEM\MountedDevices`, `USBSTOR`, `SetupAPI.dev.log`, and `EMDMgmt` registry/log artifacts.

---

## Evidence Inventory (on disk)

All files in [evidence/](evidence/). Hash baselines preserved in [evidence/_chain_of_custody_source_hashes.sha256](evidence/_chain_of_custody_source_hashes.sha256) (pre-move) and [evidence/_chain_of_custody_evidence_hashes.sha256](evidence/_chain_of_custody_evidence_hashes.sha256) (post-move). All moved files verified byte-perfect via SHA-256 against source manifest.

| Source | Format | File(s) | Size | NIST acquisition tool |
|--------|--------|---------|------|-----------------------|
| **PC** | E01 (EnCase, segmented) | `cfreds_2015_data_leakage_pc.E01` → `E04` | 2.0G + 2.0G + 2.0G + 1.3G = 7.4G | EnCase Imager 7.10.00.103, converted from VMDK |
| **RM#1** | E01 (EnCase) | `cfreds_2015_data_leakage_rm#1.E01` | 75M | FTK Imager 3.3.0.5 + Tableau USB Bridge T8-R2 write blocker |
| **RM#2** | E01 (EnCase) | `cfreds_2015_data_leakage_rm#2.E01` | 244M | EnCase Imager 7.09.00.111 + Tableau USB Bridge T8-R2 |
| **RM#2** | DD | `cfreds_2015_data_leakage_rm#2.dd` | 4.0G | FTK Imager 3.3.0.5 + Tableau USB Bridge T8-R2 |
| **RM#3 type1** | RAW ISO + CUE | `cfreds_2015_data_leakage_rm#3_type1.iso` + `.cue` + `.txt` | 118M + 361B + 738B | FTK Imager 3.3.0.5 |
| **RM#3 type2** | DD | `cfreds_2015_data_leakage_rm#3_type2.dd` | 103M | FTK Imager 3.3.0.5 + bchunk (raw ISO/CUE → DD) |
| **RM#3 type3** | E01 (EnCase) | `cfreds_2015_data_leakage_rm#3_type3.E01` | 91M | EnCase Imager 7.09.00.111 |

**Format redundancy notes:**
- The three **RM#3 types are the same CD-R in three acquisition forms** — pick the EnCase (`.E01`) by default for mounting via `ewfmount`; the raw `.iso` is useful when a tool wants the literal CD sector image (UDF tools may prefer it); the `.dd` is the bchunk-converted contiguous raw.
- The **RM#2 has two forms** (`.E01`, `.dd`) — same disk; default to `.E01`. (NIST also ships a `.7z` containing the same `.dd` — we removed it from `evidence/` as redundant since the raw `.dd` is already extracted.)
- The **PC** is one logical disk split across `.E01`-`.E04`. Mount via `ewfmount` pointed at any segment; auto-discovers the rest.

**Image hashes** are published by NIST at `https://cfreds-archive.nist.gov/data_leakage_case/hash_values.html` — confirm against NIST's MD5/SHA-1 once `hash.verify_evidence_hash` runs at Triage.

**Seed files reference** — NIST also publishes a `cfreds_2015_data_leakage_seed_files.7z` (150 MB) with the source documents that were planted in RM#1 + company network drive as the confidential IP. NOT in our evidence/ — the case is solvable without them, but downloading them later would enable file-content matching (sha256 the recovered candidates against the seed manifest at `seed_file_hash_values.tsv`).

---

## Subject Profile (`informant`)

| Attribute | Value |
|-----------|-------|
| Windows username | `informant` (Desktop path: `\Users\informant\Desktop\`) |
| Real name | Iaman Informant |
| Role | Technology Development Manager, OOO |
| Email | Used Outlook for plan discussion — account TBD from OST parse (Q19) |
| Cloud storage | Google Drive (Q28–29 + Q44–45) — sync logs + VSS snapshot.db |
| Authorized storage | RM#1 (4C530012450531101593) only |
| Unauthorized storage staged at checkpoint | RM#2 + RM#3 |
| Skill | Authority to bypass DRM/DLP; **basic digital forensics knowledge** → expects AF techniques |
| Resignation file | A DOCX on `\Users\informant\Desktop\` (Q35) — printed (Q36) |

Generate username variants via `misc.knowns_pattern_generate(reference_set=['Iaman Informant'], derivation_type='person_username')` — expect `iaman`, `informant`, `iinformant`, `iaman.informant`, etc.

---

## Investigation Foci (NIST's stated Practice Points)

| Practice Point | Specific Artifacts |
|----------------|---------------------|
| **Windows forensics** | Event logs (Security/System/App), Outlook, app execution history, **CD burning records (IMAPI)**, external device traces (USBSTOR/MountedDevices/SetupAPI/EMDMgmt), network drive mappings, **system caches (Thumbcache 256 — Q37, Sticky Notes — Q40, Windows Search index — Q41), Volume Shadow Copies (Q43)** |
| **File system** | NTFS (PC) + FAT32 (RM#2) + exFAT (RM#1) + UDF (RM#3). MFT, FAT directory entries, $LogFile, $UsnJrnl, FAT slack |
| **Web browser** | History, cache, cookies, **URLs + search keywords** (Q15) |
| **Email** | **Outlook OST** (Q17–20) — bodies + attachments + deleted items |
| **Databases** | ESE (Windows Search `Windows.edb`) + SQLite (Google Drive `snapshot.db` `cloud_entry` table — Q45 hint includes DDL) |
| **Recovery & carving** | Recycle Bin, metadata recovery, signature carving, unused area |
| **User behaviour** | Forensic timeline + visual diagram |

Knowns-driven hunt patterns (run before generic enumeration):
- USB serials → `misc.knowns_pattern_generate(derivation_type='exact')`
- Subject names ("Iaman Informant", "Spy Conspirator") → `misc.knowns_pattern_generate(derivation_type='person_username')`
- Company name "OOO" — too generic to grep usefully; ignore as a pattern
- IP `10.11.11.129` (PC's own IP) — useful for finding outbound RDP/SMB references TO this host elsewhere

---

## Anti-Forensics Watchlist

The NIST questions explicitly state AF was applied on three devices. Treat each finding category as a positive search:

| Locus | NIST signal | Likely technique | Residual artifact (what to look for) |
|-------|-------------|------------------|--------------------------------------|
| **PC** | Q47: "What actions were performed for anti-forensics on PC at the last day 2015-03-25?" | Likely a combination: Recycle Bin emptying (Q46), file renaming (Q21 — parent dirs deleted, MFT entries overwritten), browser-history wiping, possibly tool-assisted (CCleaner/SDelete) | `$UsnJrnl` deletion bursts, `$LogFile` transactions, ShimCache/Amcache/UserAssist entries for the AF tool, Windows Search index `Windows.edb` (Q42–44) preserves text content of deleted items, **Volume Shadow Copies preserve pre-wipe state (Q43–44)** |
| **RM#2** (USB) | Q53: "What actions were performed for anti-forensics on USB drive RM#2?" + hint from Q52 (recover deleted files) | File deletion / FAT directory clearing | FAT directory entry remnants, file slack, allocated/unallocated cluster comparison |
| **RM#3** (CD-R) | Q56: "What actions were performed for anti-forensics on CD-R RM#3?" + Q55 hint "recover hidden files… determine proper filenames prior to renaming" | File renaming on UDF + likely hidden-attribute flags | UDF filesystem record comparison, file content fingerprinting to match originals |

**Critical AF-preservation artifact: Volume Shadow Copies** — Q43–45 explicitly direct you to VSS for Google Drive history. List VSCs (`img.vshadow_list`), mount the pre-2015-03-25 snapshot, diff against current system image. Subject probably didn't know to wipe VSS.

**Windows Search index (`Windows.edb`) is the second key AF defeat** — Q42–44 explicitly cover IE history, email communication, and Desktop directory content STORED IN the search database. The subject likely wiped sources but `Windows.edb` retains indexed text. Parse via `ez.sqlecmd` (no, that's SQLite — `Windows.edb` is ESE, use `misc.regripper_hive`-style ESE parsers or specific Windows Search tools; falls back to `strings.strings_grep` if no structured tool).

---

## Investigation Roadmap — 62 NIST Questions

The NIST page lists 62 specific questions grouped by phase. They are the authoritative answer-key roadmap. Treat them as **the work order for Collect/Analyze phases** after Triage produces the initial plan. Brief categorization (Q numbers from the NIST page order):

| Group | NIST Questions | Phase |
|-------|----------------|-------|
| **System characterization** | Q1–10 (hashes, partitions, OS, timezone, hostname, accounts, last logon, last shutdown, NIC/DHCP, installed apps) | Triage |
| **System + user activity** | Q11–13 (app execution, system on/off + logon/logoff between 09:00–18:00, web browsers used) | Triage |
| **Browser** | Q14–16 (history paths, websites visited + timestamps, search keywords) | Collect/Analyze |
| **Windows Explorer search** | Q17 (search-bar keywords) | Collect/Analyze |
| **Email (Outlook OST)** | Q18–21 (app, file path, account, all emails incl. deleted) | Collect/Analyze |
| **External devices + file ops** | Q22 (USB devices attached to PC), Q23 (renaming traces on Desktop 2015-03-23 → 24, MFT entries overwritten), Q24 (network share IP) | Collect/Analyze |
| **RM#2 (USB)** | Q25–26 (directories traversed + files opened) | Collect/Analyze |
| **Network drive** | Q27–28 (directories traversed + files opened) | Collect/Analyze |
| **Cloud (Google Drive)** | Q29–31 (traces on PC, deleted files, account info) | Collect/Analyze |
| **CD-R burn** | Q32–34 (method/software, when burned, files copied PC→CD-R, files opened from CD-R) | Collect/Analyze |
| **Resignation file** | Q35–36 (DOCX on Desktop — timestamps, print history) | Collect/Analyze |
| **Thumbcache** | Q37–38 (location, confidential file traces — 256-size only) | Collect/Analyze |
| **Sticky Notes** | Q39–40 (location, content) | Collect/Analyze |
| **Windows Search index** | Q41–44 (enabled? path, contents, IE history 2015-03-22→23, email comms 2015-03-23→24, Desktop files) | Collect/Analyze |
| **VSS** | Q45–47 (location/created dates, Google Drive cloud_entry deletions, why Outlook absent from VSS) | Collect/Analyze |
| **Recycle Bin + AF** | Q48 (Recycle Bin examination), Q49 (PC AF on 2015-03-25) | Analyze |
| **RM#2 recovery + AF** | Q50 (recover deleted), Q51 (AF on RM#2), Q52 (files copied PC→RM#2) | Analyze |
| **RM#3 recovery + AF** | Q53 (recover hidden files + determine original filenames), Q54 (AF on RM#3) | Analyze |
| **Synthesis** | Q55–57 (timeline, methodologies list, visual diagram) | Report |

(Numbering above is my regrouping for phase planning; the NIST page lists the same questions sequentially without explicit Q#s. Quote them by description when recording findings.)

---

## Mount Plan (once Triage starts)

Mount directories are NOT pre-created — `sudo mkdir` first.

| Image | Mount commands |
|-------|----------------|
| PC (E01-E04) | `sudo mkdir /mnt/ewf_pc /mnt/pc` → `ewf.mount_full_image` on `cfreds_2015_data_leakage_pc.E01` |
| RM#1 | `sudo mkdir /mnt/ewf_rm1 /mnt/rm1` → `ewf.mount_full_image` on `cfreds_2015_data_leakage_rm#1.E01` |
| RM#2 | `sudo mkdir /mnt/ewf_rm2 /mnt/rm2` → `ewf.mount_full_image` on `cfreds_2015_data_leakage_rm#2.E01` |
| RM#3 | `sudo mkdir /mnt/ewf_rm3 /mnt/rm3` → `ewf.mount_full_image` on `cfreds_2015_data_leakage_rm#3_type3.E01`; or use the `.iso` + `.cue` via `cdemu`/loopback for UDF fidelity |

### Registry hive paths (once PC mounted at `/mnt/pc/`)

| Hive | Path |
|------|------|
| SOFTWARE | `/mnt/pc/Windows/System32/config/SOFTWARE` |
| SYSTEM | `/mnt/pc/Windows/System32/config/SYSTEM` |
| SAM | `/mnt/pc/Windows/System32/config/SAM` |
| SECURITY | `/mnt/pc/Windows/System32/config/SECURITY` |
| `informant` NTUSER | `/mnt/pc/Users/informant/NTUSER.DAT` |
| `informant` USRCLASS | `/mnt/pc/Users/informant/AppData/Local/Microsoft/Windows/UsrClass.dat` |

---

## Output Directories

```
~/cases/cfreds-leak/analysis/    — intermediate work, parsed artifacts
~/cases/cfreds-leak/exports/     — tool output (CSV, JSON, bodyfiles)
~/cases/cfreds-leak/reports/     — final investigator reports
~/cases/cfreds-leak/evidence/    — read-only evidence images (+ chain-of-custody hash manifests)
```

---

## Tool Notes

- **Outlook OST** → `misc.pff_export` (libpff). Q20 hint: "just examine the OST file only" — bodies + attachments + deleted items recoverable from OST without server access.
- **Google Drive snapshot.db** → SQLite, `ez.sqlecmd`. Q45 provides the exact DDL of `cloud_entry` table — query for `removed=1` records. The VSS copy of `snapshot.db` is the gold artifact (Q44–45).
- **Windows Search `Windows.edb`** → ESE database. No native MCP tool — use `strings.strings_grep` against the file as a confirmation pass, OR run `libesedb`-based extraction via Bash (allowed). `ez.sqlecmd` won't parse ESE.
- **VSS** → `img.vshadow_list` first to enumerate snapshots; `img.vshadow_mount` to mount a specific snapshot for parallel analysis of historical state.
- **UDF (CD-R)** → use the `.iso` mounted via Linux UDF loop (`mount -t udf -o loop`); the EWF form may not preserve UDF specifics. Try EWF first, fall back to raw `.iso` if questions about UDF metadata require it.
- **All timestamps in UTC** — note PC timezone from SYSTEM hive (Q4) and convert all reported times. NIST hints reference Q4's timezone explicitly.
- **`ez.evtxecmd`** for Windows event logs (Q12: system on/off + logon/logoff, but **filter to 09:00–18:00 local time only**).

---

## Pivot Hostname Prefixes

Single-host investigation with subject's PC as primary. The company's network share has an IP (Q24) that may reveal an internal hostname — if a SMB hostname appears in `\\HOST\share` UNC references, surface it as `recommended_actions` rather than a phase-stack pivot (we don't have an image for it). Google Drive endpoints, Outlook server addresses, and Spy Conspirator's email host are exfil channels — record in findings, not as pivot hosts.

---

## Don't-Peek Discipline

**Answer key exists**. Do NOT fetch or read it before recording findings. Reserve for the `accuracy.*` Report-phase evaluation — `accuracy.accuracy_compare` against the NIST ground truth gives precision/recall/F1 for the final accuracy report. Looking at answers first would invalidate the autonomy demonstration and the accuracy metric.
