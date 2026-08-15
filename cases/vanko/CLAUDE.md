# Case: VANKO-2016

**Evidence integrity: Never modify evidence files. All output to `./analysis/`, `./exports/`, or `./reports/`.**

---

## Case Metadata

| Field | Value |
|-------|-------|
| **Case ID** | VANKO-2016 |
| **Subject** | Anthony Vanko — lead biochemical engineer, Stark Enterprises DC Research and Development Facility |
| **Associates** | Kylie Normandy (scientist, Stark LA research lab); unidentified female acquaintance (chemical-engineering doctoral student, met Vanko ~third week of June 2016) |
| **Incident** | Stark internal research documents (cell regrowth calculations, rapid cell regeneration research, ZF DNA splice test notes) posted to a Chinese university file share 2016-06-22/23; JARVIS detected a large-volume copy from the StarkResearch server to Vanko's workstation on 2016-06-30 (`\StarkResearch\Level 5–8 Classified\`), then suspended his account and emailed him |
| **Dataset** | SANS FOR500 "Case of the Abducted Zebrafish" student scenario |
| **Your role** | Digital investigative analyst for Stark Enterprises |

---

## CASE_QUESTION: Was Anthony Vanko involved in the dissemination of classified Stark research to the Chinese university server (2016-06-22/23), did he copy the large volume of classified data from the StarkResearch server on 2016-06-30, and what was done with that data?

The three questions from the scenario tasking:
1. Was Vanko involved with the dissemination of classified information? Of not, then who was? And how was it done?
2. Validate whether Vanko copied a large volume from the StarkResearch server.
3. What was done with the data?

---

## Scenario Key Facts

- Subject device: **Surface 3, Windows 10 Professional** (Stark-issued). Connects to `StarkLabs` Wi-Fi and `StarkSat` satellite 802.11; also uses travel wireless networks.
- Vanko carries an **iPhone 5c** (low cell usage; may have been synced to the Surface).
- Known comms methods: **email, Skype, WhatsApp**.
- Motive context: no annual bonus, lab funding cut; 2016-06-25 CEO Tony Stark email announcing 25% budget cuts to non-weapon research.
- Kylie Normandy's acquaintance left the bar with Vanko ~third week of June 2016 — shortly before the 06-22/23 posting.
- Timeline anchors: documents posted 2016-06-22/23 → CEO email 06-25 → JARVIS bulk-copy detection 06-30 → account suspended → image acquired 2016-11-04 (≈4-month gap between incident and acquisition).

---

## Evidence Inventory (on disk, `evidence/`)

| Item | Files | Notes |
|------|-------|-------|
| **Full physical image** (Surface 3) | `surface_physical.E01`–`.E21` (~42 GB, EnCase segmented) | FTK Imager 2.9.0.1385 live physical acquisition, 2016-11-04, examiner Ovie Carroll. 119,276 MB source, 244,277,248 sectors. **MD5 `4032d556cc866c23f1e797410e95603c` / SHA1 `e0e72dfcef167dd358813726e82f6c235bc85ce7`** (verified in `surface_physical.E01.txt`) — use for `hash.verify_evidence_hash` |
| Acquisition sidecars | `surface_physical.E01.txt`, `.E01.adcf`, `.d01` | FTK acquisition log + AccessData metadata |
| **Logical C-drive copy** (CyLR-style) | `vanko-c-drive.CYLR/vanko-c-drive.CYLR/G/` | `$MFT`, `$LogFile`, registry hives (`Windows/System32/config/`: SAM, SECURITY, SOFTWARE, SYSTEM + RegBack), SRUM (`Windows/System32/sru/SRUDB.dat`), Prefetch (243 files), single user profile **`PC User`** (NTUSER.DAT, Recent LNKs, Chrome `History`/`Cookies`/`Login Data`, Skype `live:anthony.vanko` incl. `main.db`, WhatsApp desktop data, **two personal OSTs**: `anthony.vanko@gmail.com (1).ost`, `anthony.vanko@icloud.com.ost`) |


The scenario handout PDF sits inside the CyLR dir (`FOR500HANDOUT_Vanko Student Scenario.pdf`) — reference material, not evidence.

---

## Mount Plan

`sudo mkdir /mnt/ewf_vanko /mnt/vanko` → `ewf.mount_full_image` on `evidence/surface_physical.E01` (auto-discovers segments E02–E21). Registry hives are also directly readable from the CyLR copy for the Triage pre-plan batch without mounting.

---

## Output Directories

```
~/cases/vanko/analysis/    — intermediate work, parsed artifacts
~/cases/vanko/exports/     — tool output (CSV, JSON, bodyfiles)
~/cases/vanko/reports/     — final investigator reports
~/cases/vanko/evidence/    — read-only evidence (E01 + CyLR copy)
```

---

## Pivot Hostname Prefixes

`STARK` (StarkResearch server, StarkLabs/StarkSat SSIDs). Single-workstation case — no images for other hosts; record server-side references as findings, not phase-stack pivots.
