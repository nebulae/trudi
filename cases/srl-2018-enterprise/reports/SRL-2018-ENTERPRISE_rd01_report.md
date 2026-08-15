# Incident Report — SRL-2018-ENTERPRISE (CRIMSON OSPREY)

**Scope:** full enterprise sweep — **all available Windows memory images malfind-examined** + disk triage on rd-01/rd-02/DC/file-server/dmz-ftp.
**Domain:** SHIELDBASE | **Threat actor (case-designated label):** CRIMSON OSPREY
**Investigator:** Nebulae (TRUDI orchestrator) | **Report date:** 2026-06-13
**Audit log:** `reports/SRL-2018-ENTERPRISE_trace.{json,md}` (457 trace entries, 183 tool calls, 51 findings, 12 CONFIRMED)

> Evidence is **Aug–Sep 2018**. **CRIMSON OSPREY** is the case label, not a corroborated group. Malware *family* (Cobalt Strike) held SUSPECTED; **PowerShell Empire** cradle CONFIRMED / family LIKELY.

---

## Case Question
> *Full scope of CRIMSON OSPREY's compromise of SRL — initial access, timeline, lateral movement, persistence, exfiltration.*

---

## Executive Summary

A PowerShell Empire + Cobalt-Strike-family intrusion (C2 `squirreldirectory.com`) with **three hosts carrying resident in-memory implants — rd-01, rd-04, and wkstn-04** — spread by **valid-account abuse**: the `spsql` service account was reused (pass-the-ticket) across ≥8 hosts, **Domain Admin `rsydow-a` was compromised** and used for **repeated account takeovers** (`narciso.ward`, `tyler.oslund`). **DCSync / Golden Ticket / krbtgt compromise are REFUTED** across the full DC log window. **Data exfiltration is CONFIRMED via the DMZ FTP server**: ~1 GB of archives (`examples.ps1.rar` 823 MB, `M&A Targets.zip` 194 MB) were downloaded (FTP RETR, status 226) to **external DigitalOcean/Azure IPs** (165.227.50.129, 40.121.0.91). Sensitive R&D data (**Project Mayhem**) sits on the file-server share and is the likely collection source.

**Scope of theft (archives recovered & enumerated on the DMZ FTP server):** `examples.ps1.rar` (1 GB, 352 files) is a wholesale copy of the file-server shares (R&D incl Project Mayhem / P.E.G.A.S.U.S / MH_Eyes_Only, HR, Management, Case Files) **and — critically — a system-state backup containing `ntds.dit` (64 MB) + `SYSTEM` + `SECURITY` hives: a full domain credential-database theft (T1003.003)** that hands the attacker offline recovery of every SHIELDBASE credential and is the **likely credential-acquisition mechanism** behind the spsql/rsydow-a abuse. `M&A Targets.zip` holds Orocobre (lithium) + Tronox (TiO₂) M&A due-diligence. A **`range_admin` dormant local-admin backdoor** was also confirmed on **both** wkstn-01 (RID 1003) and wkstn-05 (RID 1006) with coordinated `Administrator`/`range_admin` password resets on 2018-08-29 (attacker-persistence vs cyber-range provisioning is held SUSPECTED — the dataset is a range and the other workstations are memory-only).

**Deep-dive update (origin & exfil pivot):** rd-01's *first* foothold (2018-08-28 15:42:38) ran **as `spsql`, fileless** (Empire cradle → MSF/Empire reverse-HTTP shellcode, MSIE "MATP" UA, no dropper) — so rd-01 was entered with a **valid credential, not a local phish**, and patient-zero is upstream. The FTP-exfil **staging pivot is SUSPECTED `sql01` (172.16.4.5)** — `rsydow-f` opened `\\srl-ftp` from 172.16.4.5 (and the 10.10.4.5 mirror) ~17 min before the `examples.ps1.rar` egress, and rd-04/wkstn-04 hold live SMB sessions to 172.16.4.5 (`vol.netstat`, so the **SMB-convergence role is artifact-grounded**); but sql01 is **un-imaged**, so archive-assembly *on* sql01 is inference, not a resident artifact. The **`rsydow` identity family (`rsydow` / `rsydow-a` DA / `rsydow-f`)** is the through-line, and **everything converges on the un-imaged `sql01`** as the #1 remaining collection target. `file-snapshot5.img` proved to be a clean file-server memory capture (no implant).

**C2-config extraction (rd-04 / wkstn-04 injected regions):** the embedded external callback IP is **not host-recoverable**. `vol.netstat` shows rd-04 (172.16.6.14) egress terminating at the **corporate Squid proxy 172.16.4.10:8080**, so the host-side socket points at the proxy and `squirreldirectory.com` resolves *proxy-side* — outside host evidence. (The in-memory Empire/.NET config is UTF-16/wide-encoded; this Vol3 build exposes only `windows.vadyarascan`, which rejects the `--yara-rules` flag, so inline-rule memory-YARA was unavailable — a tool-limitation self-correction, logged.) Net: `squirreldirectory.com` stays the **confirmed C2 host**; its resolved IP would require **proxy/DNS logs** not in evidence. The same netstat pass independently **corroborated `sql01` (172.16.4.5) as the SMB convergence hub** — rd-04 and the dual-homed wkstn-04 (172.16.7.14 / 10.10.150.181) both hold ESTABLISHED SMB to it.

**Two accuracy corrections during this investigation (both surfaced by challenge/re-check):**
1. The case-file IOCs (`STUN.exe` etc.) were **refuted** — the real chain is WMI→Empire→`p.exe`.
2. The bundled **YARA TTP rules fire on every F-Response-collected image (baseline noise — the collection agent + AV + .NET)** and are **not** a per-host compromise discriminator. **`malfind` (injected code) is the discriminator** — and applying it across the full image set is what uncovered **wkstn-04** (which a YARA-only pass would have buried among baseline hits) and cleared the others.

---

## Host disposition (complete examined set)

| Host | Status | Basis |
|---|---|---|
| **rd-01** (172.16.6.11) | **CONFIRMED implant** | `p.exe` reflective loader (VT 60/76) + WMI persistence + Empire cradle |
| **rd-04** (172.16.6.14) | **CONFIRMED implant** | injected Empire PowerShell + Run-key `Sophos` |
| **wkstn-04** (172.16.7.x) | **CONFIRMED injected shellcode** (host-scope LIKELY) | powershell PID 1288 PEB-walk shellcode (malfind) |
| **dmz-ftp** (172.16.10.12) | **CONFIRMED exfil channel** | IIS FTP RETR 226 of ~1 GB to external IPs |
| rd-02 (172.16.6.12) | lateral target — **AV-quarantined payload**, no resident implant | McAfee quarantined `C:\WINDOWS\5B1B72B.EXE` (GenericRXAO-VJ, 08-31 00:09 UTC); memory malfind-clean; no on-disk toolkit |
| rd-06 (172.16.6.16) | lateral touch, **no resident implant** | DC-authenticated (spsql/tyler.oslund); malfind-clean |
| DC, file-server | targeted (creds / collection), **not implanted** | malfind empty; file-server disk: Mayhem collection burst 09-06, no implant |
| **wkstn-01** (mhill) | memory-clean; **disk: `range_admin` backdoor + timestomped `Update.exe`** | SAM RID 1003 dormant admin; ShimCache `SquirrelTemp\Update.exe` ts 1985-10-26 |
| **wkstn-05** | memory-clean; **disk: `range_admin` backdoor** (same pattern) | SAM RID 1006 dormant admin; coordinated 08-29 resets |
| admin, av, hunt, sp, mail, rd-03, rd-05, wkstn-02/03/06 | **examined — clean** | malfind benign (AV/.NET/F-Response only) |
| **elf** (Linux) | **not analyzable** | image = raw "data", no kernel banner, no Vol3 ISF — tooling boundary |

---

## Attack timeline (UTC, 2018)

| Time | Host | Event |
|---|---|---|
| 08-28 15:42:38 | rd-01 | First Empire stager → `squirreldirectory.com/a` — ran **as `spsql`, fileless** (MSF/Empire reverse-HTTP shellcode, MSIE "MATP" UA, no dropper) ⇒ entered with a **valid credential**, patient-zero upstream |
| 08-28 22:30 | DC | DA `rsydow-a` resets `narciso.ward` (takeover #1) |
| 08-30 16:43:36 | rd-01 | `spsql` Kerberos == WmiPrvSE→PowerShell (remote-WMI) |
| 08-30 18:31 | rd-01 | Empire `Install-Persistence` → WMI sub `SystemPerformanceMonitor` |
| 08-30 22:14 | rd-01 | `p.exe` dropped/run in `Temp\Perfmon\` |
| 08-29 02:56–03:06 | wkstn-01, wkstn-05 | Coordinated `Administrator` + `range_admin` password resets (~30 s apart) on both workstations — dormant local-admin backdoor pattern |
| 08-31 00:09 | rd-02 | McAfee quarantined `C:\WINDOWS\5B1B72B.EXE` (GenericRXAO-VJ; 15 KB MinGW injector PE, not in VT) on the lateral target |
| 09-05 05:27 | (AD backup) | `ntds.dit` (64 MB) + `SYSTEM`/`SECURITY` hives packed into `examples.ps1.rar` → full domain credential-DB capture |
| 08-10 / 09-04 | dmz-ftp | `M&A Targets.zip` (194 MB) RETR'd to 40.121.0.91 / 165.227.50.129 |
| 09-05 18:40 | sql01 (172.16.4.5) | `rsydow-f` opens `\\srl-ftp` from 172.16.4.5 (+10.10.4.5 mirror) — **SUSPECTED FTP-exfil staging pivot** (SMB-hub role artifact-grounded; sql01 un-imaged), ~17 min pre-egress |
| 09-05 18:57 | dmz-ftp | `examples.ps1.rar` (823 MB) RETR'd to 165.227.50.129 (rsydow-f) |
| 09-06 01:37 | DC | DA `rsydow-a` resets `tyler.oslund` (takeover #2) → ops from 172.16.6.16 |
| 09-06 18:08–18:16 | file-server | **R&D\Mayhem collection burst** — `Project Mayhem.pptx` + 2 R&D docs freshly created (`$MFT`); data marshalling in the share |

---

## Findings (tiered)

**CONFIRMED**
- rd-01 `p.exe` reflective-loader implant (SHA256 `7fa4f6cc…2892c`, VT 60/76); PowerShell cradle → C2 `squirreldirectory.com`; WMI event-subscription persistence (`SystemPerformanceMonitor`, CreatorSID spsql).
- rd-04 host compromise — injected Empire PowerShell (PID 2664/4520/4896) + Run-key `Sophos`.
- **wkstn-04 injected shellcode** — PID 1288 PEB-walk stager (host-scope LIKELY, memory-only).
- **Exfiltration over FTP (T1048.003)** — DMZ FTP RETR 226: `examples.ps1.rar` 862,864,145 B → 165.227.50.129 (`rsydow-f`); `M&A Targets.zip` 203,196,252 B → 165.227.50.129 & 40.121.0.91 (`dblake`).
- Project Mayhem + R&D IP present on file-server `shieldbase-share\R&D\Mayhem`.
- **rd-02 (lateral target 172.16.6.12) AV-quarantined payload** — McAfee detected/quarantined `C:\WINDOWS\5B1B72B.EXE` (GenericRXAO-VJ!1F3258EBEF41) on 2018-08-31 00:09 UTC; recovered 15,360-byte MinGW injector PE (SHA256 `455636b9…e4c673`, VirtualAllocEx/rundll32), absent from VirusTotal. *(Detection/quarantine = CONFIRMED; campaign attribution held SUSPECTED — generic signature, no execution/delivery evidence survives.)*
- **Domain credential-database exfiltration (T1003.003)** — the recovered DMZ-FTP archive `examples.ps1.rar` (SHA256 `719103eb…09ba`) contains `…\WindowsServerBackup\4.04\Active Directory\ntds.dit` (64 MB) + `registry\SYSTEM` (16 MB) + `registry\SECURITY` — the full AD database plus the boot key/LSA secrets to decrypt it → offline recovery of **every** SHIELDBASE domain credential. **This is the likely credential-acquisition mechanism** behind the spsql/rsydow-a abuse (ntds.dit dated 09-05, the rar's egress day).
- **Exfil archive contents enumerated** — `examples.ps1.rar` (1,002,723,527 B, 352 files) = wholesale file-server shares (R&D incl Project Mayhem / P.E.G.A.S.U.S / MH_Eyes_Only / Metal Alloys, HR, Management, Case Files); `M&A Targets.zip` (SHA256 `c6333cd2…d111d`, 32 files, 218 MB) = Orocobre (lithium) + Tronox (TiO₂) M&A due-diligence. Both recovered on the DMZ FTP server (dirs `rsydow-f`, `nfury`).
- **`range_admin` dormant local-admin backdoor on wkstn-01 (RID 1003) AND wkstn-05 (RID 1006)** — zero logins, never-expires, Administrators member; on each host the `range_admin` + built-in `Administrator` passwords were reset ~30 s apart on 2018-08-29 (wkstn-01 02:56:03/02:57:29; wkstn-05 03:06:01/03:06:27). *(Account facts CONFIRMED; attacker-persistence-vs-range-provisioning held SUSPECTED.)*
- **Anti-forensic timestomp (T1070.006)** — wkstn-01 ShimCache: `C:\Users\mhill\AppData\Local\SquirrelTemp\Update.exe` backdated to 1985-10-26 12:15:00.

**LIKELY**
- `spsql` remote-WMI + pass-the-ticket to ≥8 hosts incl. 172.16.6.12; **`rsydow-a` DA compromised + repeated account-takeover** (narciso.ward, tyler.oslund); rd-02/rd-06 lateral touch; nromanoff compromised; file-server = collection source; **DCSync/Golden-Ticket/krbtgt REFUTED**; tdungan unwitting (credential reused).
- **rd-01 first foothold ran as `spsql`, fileless** (2018-08-28 15:42:38 — MSF/Empire reverse-HTTP shellcode, MSIE "MATP" UA, no dropper) ⇒ valid-credential entry, patient-zero upstream of rd-01.
- **`sql01` (172.16.4.5) is the SMB convergence hub** — rd-04 and wkstn-04 hold ESTABLISHED SMB to it (`vol.netstat`, artifact-grounded), and `rsydow-f` opened `\\srl-ftp` from 172.16.4.5 (+10.10.4.5 mirror) ~17 min pre-egress; #1 remaining collection target. *(Its role as FTP-exfil staging/archive-assembly host is **SUSPECTED** only — sql01 is un-imaged.)*

**SUSPECTED**
- Credential access: ProcDump (rd-01 Dashlane dir) + Mimikatz/LSASS YARA (rd-04) — exact dump step not confirmed; RC4 Kerberoasting (14× TGS); `cbarton-a` 2nd DA (10.10.x).
- **C2 egress is proxied** — rd-04 (172.16.6.14) outbound terminates at Squid proxy 172.16.4.10:8080 (`vol.netstat`); external C2 IP for `squirreldirectory.com` resolves proxy-side and is not host-recoverable. sql01 (172.16.4.5) corroborated as SMB convergence hub (rd-04 + wkstn-04 ESTABLISHED SMB).
- **5B1B72B.EXE = CRIMSON OSPREY tooling (SUSPECTED)** — mid-intrusion timing, random C:\WINDOWS name, MinGW injector, not in VT; generic signature precludes CONFIRMED.
- **Exfil archives not staged on the file-server** — `examples.ps1.rar`/`M&A Targets.zip` absent from file-server `$MFT` (124,492 records) → assembled on another host (→ sql01 lead). File-server R&D\Mayhem shows a collection burst 09-06 18:08–18:16 UTC.
- **`range_admin` = attacker persistence (vs benign cyber-range provisioning) — undetermined**: dataset is a range; wkstn-02/03/04/06 are memory-only (fleet-vs-targeted untestable); 4724/4738 reset-source events unavailable.
- **Squirrel delivery lead (wkstn-01 / mhill)** — timestomped `Update.exe` sits in `SquirrelTemp\` (Squirrel app-installer updater) and the C2 is `squirreldirectory.com`; shared "squirrel" naming hints at a malicious Squirrel-packaged app as initial access, but no executing sample recovered.

**Negatives / corrections**
- No DCSync/krbtgt/rogue-account/log-clear (full DC window). YARA = F-Response baseline noise (not a discriminator). Identities cross-referenced (jpallen/kellee.espinoza/dayla.watson/tdungan not takeover victims).
- **Exfil-IP TI enrichment = dead-end**: 165.227.50.129 (DigitalOcean) and 40.121.0.91 (Azure) are clean (0 malicious) on VT + AbuseIPDB in 2026 — uninformative for 2018 infra (reassigned); malicious classification rests on the contemporaneous FTP behavior. *(Self-corrected: the rd-02 quarantine was first overclaimed as "lateral delivery / AV-neutralized / LIKELY CRIMSON OSPREY"; adversarial review CHALLENGED it → narrowed to the quarantine fact + SUSPECTED attribution.)*

---

## Principals

| Account | Disposition |
|---|---|
| `spsql` | Primary lateral credential (pass-the-ticket, WMI-persistence creator) |
| `rsydow-a` (DA) | **Compromised** — account-takeover actions; **`rsydow-f`** used for FTP exfil (same identity family) |
| `cbarton-a` (DA) | **Suspected compromised** (10.10.x) |
| `nromanoff` | Compromised account (NTLM lateral from rd-04) |
| `narciso.ward`, `tyler.oslund` | Takeover victims (4724/4738) |
| `dblake` | FTP egress account (M&A Targets.zip) — attacker-used |
| `tdungan` | Unwitting data owner (credential reused) |

---

## IOCs
- **C2 / stager:** `squirreldirectory.com`; egress proxy 172.16.4.10:8080
- **Exfil destinations:** `165.227.50.129` (DigitalOcean), `40.121.0.91` (Azure) — via DMZ FTP 172.16.10.12
- **Exfiltrated archives:** `examples.ps1.rar` (862,864,067 B, SHA256 `719103ebc3f5903172736b005f7c6d51c7b072ac02b7305086e04988d7cd09ba`; staged `srl-ftp/Users/rsydow-f/PowerShell/`); `M&A Targets.zip` (203,196,174 B, SHA256 `c6333cd2a4c6088e4540d7aa66c34898bcaa8fa297430fe4c80a283e975d111d`; staged `srl-ftp/Users/nfury/Asgard/`)
- **Stolen-data scope:** full file-server shares (R&D/HR/Mgmt/Case Files) + **`ntds.dit` + `SYSTEM` + `SECURITY` (domain credential DB)**; Orocobre/Tronox M&A due-diligence
- **Backdoor account:** `range_admin` (wkstn-01 RID 1003, wkstn-05 RID 1006); **timestomp:** `mhill\…\SquirrelTemp\Update.exe` → 1985-10-26
- **Implant:** `C:\Windows\Temp\Perfmon\p.exe` — SHA256 `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c`
- **rd-02 quarantined payload:** `C:\WINDOWS\5B1B72B.EXE` — SHA256 `455636b96add4397f02fc706c1509512ba72d74bec1e6cf7792dcbd474e4c673` (McAfee GenericRXAO-VJ!1F3258EBEF41; 15 KB MinGW injector; not in VT)
- **Toolkit dir:** `\Windows\Temp\Perfmon\`; **persistence:** rd-01 WMI `SystemPerformanceMonitor`, rd-04 HKCU `…\Run\Sophos`
- **Confirmed-implant hosts:** rd-01, rd-04, wkstn-04; **exfil host:** dmz-ftp

---

## Residual / follow-on (documented gaps — not implied complete)
- **Linux `elf` host — NOT ANALYZABLE** (evidence boundary): image is raw "data", no kernel banner, no Vol3 ISF, and **zero recoverable ASCII strings** (no `/bin/bash`, `root:`, sshd, IPs) — i.e. compressed/encrypted/zeroed, nothing extractable by Volatility *or* strings. Needs a clean re-acquisition.
- **`sql01` (172.16.4.5) un-imaged** — #1 acquisition target; SMB-convergence-hub role artifact-grounded but archive-assembly role only SUSPECTED. (172.16.4.6, the **10.10.x** subnet also un-imaged.)
- **Squid proxy access logs + DMZ DNS (`dns01`) not in evidence** → the only path to resolve `squirreldirectory.com`'s callback IP (egress is proxied via 172.16.4.10:8080).
- **DMZ FTP host disk** not imaged (only IIS logs) — but the staged archives themselves were recovered from the live FTP volume.
- **Cloud:** M365 UAL (OneDrive) for the Project Mayhem side.
- **Resolved this round:** archive contents enumerated; wkstn-01/05 disks parsed; and the **credential-acquisition gap is now explained** — the attacker exfiltrated `ntds.dit`+`SYSTEM`+`SECURITY` (offline hash recovery of the whole domain), superseding the earlier "spsql credential-acquisition unevidenced" note. The exact host that ran the AD backup (likely the DC, via `wbadmin`/`ntdsutil`) remains to be pinned.

## Recommendations
**Contain:** **treat the entire SHIELDBASE domain as credential-compromised** — `ntds.dit`+`SYSTEM` were exfiltrated, so force-reset **all** domain passwords incl. `krbtgt` (twice) and every service/computer account; isolate/reimage rd-01, rd-04, wkstn-04 and **remove the `range_admin` account on wkstn-01/wkstn-05 (and audit the rest of the fleet)**; block outbound FTP to non-corporate IPs (specifically 165.227.50.129 / 40.121.0.91); disable/reset `rsydow-a`, `cbarton-a`, `spsql`, `rsydow-f`, `dblake`, `nromanoff`, `nfury`, takeover victims; remove rd-01 WMI sub + rd-04 `Run\Sophos`; sinkhole `squirreldirectory.com`; legal/compliance hold on the M&A + ntds.dit exfiltration.
**Improve:** EDR/Sysmon in-memory shellcode detection (the malfind PEB-walk pattern was the discriminator); PowerShell ScriptBlock+AMSI logging; LSA Protection/Credential Guard; restrict remote-WMI + DMZ egress; enable `4663` on crown-jewel shares; **tune YARA to suppress the F-Response agent baseline**; image the residual hosts above.

---
*Generated by TRUDI (Claude Opus 4.8 + Foundation-Sec-8B-Reasoning) on SANS SIFT. Every finding traces to a tool execution via `linked_call_id`; CONFIRMED/LIKELY findings passed adversarial `reason.evaluate_finding`; the Golden-Ticket/DCSync hypothesis was driven to REFUTED; the YARA-baseline misclassification was caught by the malfind cross-check and self-corrected; all named identities were cross-referenced. Confidence tiers and residual gaps are stated explicitly.*
