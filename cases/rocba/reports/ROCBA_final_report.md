# ROCBA — DFIR Final Report
## Stark Research Labs IP Theft via Stolen Microsoft Surface (SRL-FORGE)

**Prepared by:** External DFIR Consultant (TRUDI / SANS SIFT)
**Case ID:** ROCBA · **Host:** SRL-FORGE (Microsoft Surface) · **Victim:** Fred Rocba (`fredr`)
**Evidence:** `rocba-cdrive.e01` (C:, 23.7 GB) + `Rocba-Memory.raw` (19 GB, acquired 2020-11-19)
**Timezone:** all times **UTC** (host TZ Eastern, UTC-5).

---

## 1. Executive Summary

Fred Rocba's SRL-issued Surface (SRL-FORGE) was exposed to the Internet with remote access enabled and was under continuous credential attack from **2020-11-01**. Two consumer Microsoft accounts gained interactive (RDP) access to the device and, during the **2020-11-13 break-in window while Fred was on vacation**, an actor collected and exfiltrated SRL intellectual property through **multiple channels** and then ran anti-forensic tooling.

- **WHO** — Two principals, bound to local accounts via the **SAM `InternetName`** value:
  - `srl-h` (RID 1001, local admin) ⇄ **`srl-helpdesk@outlook.com`** — RDP'd in **2020-11-10** from Verizon IP **174.196.200.9** (recon/persistence; ran SDelete).
  - `fredr` (RID 1002, the victim) ⇄ **`fred.rocba@outlook.com`** — Fred's *own* account, **taken over** by the attacker, who authenticated **2020-11-14** from Azure IP **52.249.198.56**.
- **HOW (initial access)** — Internet-facing NTLM network-logon **brute-force** (548,244 failed `4625` events, Type 3, from 332 external IPs). The successful Nov-14 logons came from **52.249.198.56 — an IP also present in the brute-force set**, tying credential access to the account takeover.
- **WHAT** — SRL research projects (codenamed **Gunstar, Airwolf/Wolf Air, Blue Thunder, Megaforce, KITT, Vibrainium, Adamantium**), alloy/metallurgy research, `RareEarthDeposits_Confidential`, and Fred's **entire Outlook mailbox**.
- **HOW (exfil)** — ranked by evidence strength:
  1. **USB removable media (CONFIRMED)** — Lexar Flash Drive `F:` "CRIMSON2"; SRL files written to the volume 2020-11-14 03:45–04:30 UTC.
  2. **Google Drive (SUSPECTED)** — files + exported mailbox staged into the `G:` Drive File Stream sync root 03:59–14:00 UTC.
  3. **Outlook mailbox export (LIKELY)** — `backup.pst` / `SRL-EMAIL-EXPORT.pst`.
- **Lateral movement** — outbound RDP from the Surface into SRL's internal jump host **`base-rd-08.shieldbase.lan` (172.16.6.18)** on 2020-11-14 05:00 & 05:05 UTC.
- **Anti-forensics** — **SDelete** downloaded and executed (no Security log clearing detected).

**Bottom line:** This is a remote intrusion enabled by Internet-exposed remote access and credential brute-force, culminating in multi-channel theft of SRL IP and Fred's mailbox under Fred's hijacked account, with a pre-positioned secondary admin identity (`srl-helpdesk@outlook.com`).

---

## 2. Findings (with confidence tiers)

| # | Finding | Tier | ATT&CK |
|---|---------|------|--------|
| 1 | `srl-h` (RID1001) bound to `srl-helpdesk@outlook.com` (SAM InternetName); RDP Type10 from 174.196.200.9 (Verizon) 2020-11-10 13:26 UTC; provisioned at imaging (pwd 2020-10-20) | **CONFIRMED** | T1078, T1021.001 |
| 2 | Internet NTLM brute-force: 548,244 `4625` Type-3 from 332 external IPs from 2020-11-01 22:15 UTC | LIKELY | T1110 |
| 3 | Outbound RDP under `fredr` to internal `base-rd-08.shieldbase.lan` (172.16.6.18) 2020-11-14 05:00 & 05:05 UTC | **CONFIRMED** | T1021.001 |
| 4 | `fred.rocba@outlook.com` (=`fredr`) RDP Type10 from Azure 52.249.198.56 2020-11-14 12:31 & 12:52 UTC (post-theft) | LIKELY | T1078, T1021.001 |
| 5 | **USB exfil** — Lexar `F:` "CRIMSON2" (S/N AAZ62W7KENRSJLHY); SRL files written to volume 2020-11-14 03:45–04:30 UTC, removed 04:34 | **CONFIRMED** | T1052.001 |
| 6 | **Google Drive** staging of SRL projects + exported mailbox into `G:\My Drive\STARK-RESEARCH-LABS FOLDER` 03:59–14:00 UTC (cloud upload not independently confirmed) | SUSPECTED | T1567.002 |
| 7 | **Outlook mailbox export** — `backup.pst` 13:39 UTC; `SRL-EMAIL-EXPORT.pst` to Google Drive 14:00:54 UTC | LIKELY | T1114 |
| 8 | **IP scope** — SRL-Projects (Gunstar/Airwolf/Blue Thunder/Megaforce), Maria Hill-KITT, Vibrainium, Adamantium, alloy research, RareEarthDeposits_Confidential, full mailbox | LIKELY | T1005 |
| 9 | **SDelete** anti-forensics executed (download 13:37 UTC, EULA both profiles, SDELETE.EXE prefetch); no `1102` Security clear | LIKELY | T1070.004 |
| 10 | **Exclusion** — `D:` "SRL IRT" (serial FC3EE602, 2020-11-16) = IR acquisition drive (`ROCBA-SYSTEM\Rocba-Memory.raw`), **not** exfil | SUSPECTED | — |
| 11 | Account-takeover linkage — all Nov-14 `fredr`/`fred.rocba` successes from 52.249.198.56, an IP in the brute-force set; no other brute-force IP succeeded | LIKELY | T1110→T1078 |
| 12 | Identity attribution — `fred.rocba@outlook.com` = victim Fred Rocba (hijacked); `srl-helpdesk@outlook.com` = consumer account, no SRL match, controller **parked unknown pending legal process** | LIKELY | — |
| 13 | Brute-force outcome — enumerated targets (Administrator[disabled]/ADMIN/USER/FORGE/TEST) had **zero** `4624` success; only `fredr`/`fred.rocba` compromised | LIKELY | — |

*Tier key: CONFIRMED = direct corroborated artifact; LIKELY = strong multi-artifact inference; SUSPECTED = single-vector / mechanism not fully proven.*

---

## 3. Timeline (UTC)

| Date/Time | Event |
|-----------|-------|
| 2020-10-20 | `srl-h` / `srl-helpdesk@outlook.com` password set — account provisioned during imaging (pre-ship) |
| 2020-11-01 22:15 | OS (re)installed/upgraded; **brute-force flood begins** (548k `4625`, Type 3, 332 external IPs) |
| 2020-11-10 13:26 | **`srl-helpdesk@outlook.com` RDP logon** (Type 10) from **174.196.200.9** (Verizon) — recon |
| 2020-11-10 | Fred departs on vacation (Disney, FL) |
| 2020-11-13 | Home break-in; Surface targeted |
| 2020-11-14 03:42 | `fredr` brute-force **succeeds** (Type 3 NTLM) from **52.249.198.56** (Azure) |
| 2020-11-14 03:45–04:30 | **SRL files copied to USB** Lexar `F:` "CRIMSON2" (Megaforce, Blue Thunder, KITT, Wolves_Lair) |
| 2020-11-14 04:34 | Lexar USB removed |
| 2020-11-14 05:00 & 05:05 | **Outbound RDP to `base-rd-08.shieldbase.lan` (172.16.6.18)** — lateral movement into SRL |
| 2020-11-14 03:59–04:30 | SRL project files staged into **Google Drive** `G:\My Drive\STARK-RESEARCH-LABS FOLDER` |
| 2020-11-14 12:31 & 12:52 | **`fred.rocba@outlook.com` RDP logon** (Type 10) from 52.249.198.56 |
| 2020-11-14 13:37 | **SDelete.zip** downloaded |
| 2020-11-14 13:39 | Outlook `backup.pst` created |
| 2020-11-14 14:00:54 | **`SRL-EMAIL-EXPORT.pst` staged to Google Drive** |
| 2020-11-16 02:31 | `D:` "SRL IRT" responder drive — memory image acquisition (IR, excluded) |
| 2020-11-19 | Memory image file timestamp |

---

## 4. Distinct-Principal Disposition

- **`srl-h` ⇄ `srl-helpdesk@outlook.com`** — bound by SAM `InternetName` + `4624` Type-10 logon from 174.196.200.9. Consumer account masquerading as SRL helpdesk; pre-positioned during imaging; ran SDelete. **Controller of the outlook.com account is unknown from host evidence — parked pending legal process** (Microsoft account + Verizon subscriber records).
- **`fredr` ⇄ `fred.rocba@outlook.com`** — bound by SAM `InternetName` (Full Name "Fred Rocba"). This is the **victim's own account, taken over** by the attacker via brute-force from 52.249.198.56 (Finding 11). Nov-14 activity is attacker activity, not Fred (who was on vacation).

Both principals are dispositioned; no third interactive principal surfaced.

---

## 5. Evidence Integrity & Methodology

- C: E01 hashed at case open (MD5 `9059412a9c74e1d0f0b3079f1bdc5433`); memory raw MD5 `3101dbf2e3e500bd2f82871c5e8836f6`. Evidence mounted **read-only**.
- **Self-correction (mount):** the E01 is a bare NTFS volume whose acquired image is 7 sectors short of the declared size (missing backup VBR); `ntfs-3g` aborted. Resolved without modifying evidence via a **device-mapper `linear` + `zero`-pad overlay**, mounted read-only.
- **Self-correction (hive recovery):** `fredr` NTUSER.DAT was dirty and RECmd could not find its lowercase logs on the case-sensitive mount; resolved by copying the hive + transaction logs with matching case and replaying.
- **Self-correction (brute-force protocol):** initially characterized as RDP; corrected to **Type-3 NTLM** network logon after parsing the `LogonType` field.
- Tooling routed through typed MCP wrappers (RECmd, EvtxECmd, LECmd, RegRipper, AmcacheParser, Volatility 3). Every finding carries a `linked_call_id` to its source execution (see exported trace).

### Limitations
- `vol.netscan` timed out (1800 s) on the 19 GB image; memory was acquired ~5 days after the exfil, so live sockets/processes from the Nov-14 session had already exited — **disk artifacts are authoritative** for the exfil window. `vol.pslist` confirmed GoogleDriveFS/OneDrive/iCloud sync clients resident.
- Google Drive **cloud upload** not independently confirmed (DriveFS `sync_log` not parsed) — channel held at SUSPECTED.
- SDelete **deletion targets** not enumerated (no USN-gap analysis) — held at LIKELY.

---

## 6. Recommended Actions (advisory)

**Containment / Response**
1. Disable `srl-h`/`srl-helpdesk@outlook.com` access; force password reset + token revocation for `fredr`/`fred.rocba@outlook.com`.
2. Isolate and image **`base-rd-08.shieldbase.lan` (172.16.6.18)**; hunt for the same identities elsewhere in `shieldbase.lan`.
3. Legal-process requests: Microsoft (both outlook.com accounts), Verizon (174.196.200.9 @ 2020-11-10), Microsoft/Azure (52.249.198.56 @ 2020-11-14); Google preservation for the Drive contents and `SRL-EMAIL-EXPORT.pst`.
4. If physically recoverable, seize the **Lexar "CRIMSON2"** USB (S/N AAZ62W7KENRSJLHY) as primary exfil evidence.
5. Notify owners of the affected SRL projects (Gunstar, Airwolf, Blue Thunder, Megaforce, KITT, Vibrainium, Adamantium) of confirmed IP loss.

**Hardening / Improve**
6. Remove Internet exposure of RDP/remote access; require VPN + MFA; restrict RDP to jump hosts.
7. Enforce USB device-control allowlisting; block consumer cloud-sync clients (Google Drive consumer) via app-control + DLP.
8. Disable Outlook PST export by GPO; audit mailbox export in M365.
9. Block Sysinternals SDelete (and similar) via WDAC/AppLocker; alert on its prefetch creation. Deploy Sysmon + PowerShell logging to SIEM.
10. Prohibit consumer Microsoft accounts as local admins on engineering endpoints; segregate helpdesk-tier accounts from IP-bearing hosts.

---

*All conclusions are grounded in the cited tool executions; the complete, timestamped execution trace with per-finding `linked_call_id` provenance is exported alongside this report.*
