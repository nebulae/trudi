# SCHARDT-2002 — Forensic Investigation Report

**Case ID:** SCHARDT-2002
**Subject:** Greg Schardt (alias "Mr. Evil")
**Evidence:** Single-host disk image — abandoned Dell Latitude CPi notebook (serial VLQLW), IBM-DBCA-204860 drive (~4.5 GB), acquired as EnCase E01 (`4Dell Latitude CPi.E01`/`.E02`) and as a raw `dd` split (`SCHARDT.001`–`.008`).
**Scope:** Disk-only (no memory image, no live network capture).
**Disposition:** **CASE RESOLVED** — all 31 NIST sub-questions answered. The laptop is conclusively tied to Greg Schardt; the alternate-operator hypothesis is refuted.
**Confidence summary:** 19 CONFIRMED, 0 unresolved. All timestamps UTC.

> ⚖️ **TRUDI architectural note:** every finding below is traceable to the specific tool execution that produced it via `linked_call_id` in the audit log (`reports/SCHARDT-2002_trace.{json,md}`). Forensic tools are exposed only as typed MCP functions — the agent physically cannot run a destructive or evidence-mutating command. Evidence was treated strict read-only throughout.

---

## 1. Case Question

> Find hacking software, evidence of its use, and any captured data on the abandoned Dell CPi laptop, and produce evidence tying the laptop to Greg Schardt (alias "Mr. Evil").

**Answer (all four prongs):**
1. **Hacking software** — Cain & Abel, Ethereal + WinPcap, Network Stumbler, Look@LAN, 123 Write All Stored Passwords, Anonymizer.
2. **Evidence of use** — the `Mr. Evil` account ran Ethereal, Cain, NetStumbler, LookAtLan and mIRC (UserAssist + Prefetch + AppCompatCache).
3. **Captured data** — the `interception` libpcap holds a third-party victim's plaintext Hotmail/MSN session.
4. **Tie to Greg Schardt** — two independent artifact classes bind the sole administrator account `Mr. Evil` to the real name **Greg Schardt**.

---

## 2. Evidence Integrity & Chain of Custody (Q1)

| Item | Value |
|---|---|
| Acquisition tool | Forensic MD5 imager v1.77 (S/N 50527) |
| Source drive | IBM-DBCA-204860, S/N HQ0RQQF7429, 4.5 GB, 9,514,260 sectors |
| Stored acquisition MD5 (media) | `aee4fcd9301c03b3b054623ca261959a` |
| E01 SHA-256 | `96bebe80f00541bf28fbc2ef0b02b580082ee6ad58837e991852ae66f077ec31` |
| E02 SHA-256 | `46bd09821dbb64675e5877d0ad7ec544a571fad5a3fd7fc3f0c3a162788887db5` |

**CONFIRMED.** `ewfinfo` reports the stored acquisition MD5; both E01/E02 segments' **full SHA-256** match the vendor-published `HackingCase_E01_hashes.html`. (The HTML's MD5 column is truncated to 31 hex characters, so the **full SHA-256** — not a prefix — was the verification basis.) Acquisition and verification hashes match; chain of custody intact.

---

## 3. System Profile (Q2–Q11)

| # | Question | Answer |
|---|---|---|
| Q2 | Operating system | Microsoft Windows XP (build 2600) |
| Q3 | Install date | **2004-08-19 22:48:27 UTC** |
| Q4 | Timezone | **Central Standard Time** (ActiveTimeBias 300) |
| Q5 | Registered owner | **Greg Schardt** |
| Q6 | Computer account name | **N-1A9ODN6ZXK4LQ** |
| Q7 | Primary domain | None — workgroup (TCP/IP Domain blank) |
| Q8 | Last shutdown | **2004-08-27 15:46:33 UTC** (ControlSet001) |
| Q9 | Total accounts | **5** (Administrator, Guest, HelpAssistant, SUPPORT_388945a0, Mr. Evil) |
| Q10 | Main user | **Mr. Evil** (RID 1003) |
| Q11 | Last user to log on | **Mr. Evil** (last login 2004-08-27 15:08:23 UTC) |

**CONFIRMED** via RECmd over SOFTWARE / SYSTEM / SAM hives. The four built-in/service accounts are dormant (no interactive login); **Mr. Evil is the sole operator profile**.

---

## 4. Identity Linkage — Schardt = Mr. Evil = Administrator (Q12)

**CONFIRMED.** `Program Files\Look@LAN\irunin.ini` is the single file proving the equivalence: it records **RegisteredOwner "Greg Schardt"** on host N-1A9ODN6ZXK4LQ for the administrator account **Mr. Evil**. The file belongs to **Look@LAN 2.50**. MFT `$SI` (2004-08-25 15:56:09 UTC) corroborates the file's self-recorded date.

---

## 5. Network Identity (Q13–Q15)

- **Q13 — NICs:** two cards — a **Xircom CardBus Ethernet 100 + Modem 56** (wired) and a **Compaq WL110 Wireless LAN PC Card** (the PCMCIA wireless card from the scenario).
- **Q14 — IP / MAC (from the same Look@LAN file):** IP **192.168.1.111**, MAC **00:10:A4:93:3E:09**.
- **Q15 — Vendor from first 3 MAC bytes:** OUI **00:10:A4 = Xircom**. The Xircom NIC is the interface recorded during the **Look@LAN** install/setup.

**CONFIRMED.** The Xircom (wired) is the *identity-binding* NIC; the Compaq WL110 (wireless) is the *capture* interface — it associated with the **SpeedStream** access point (BSSID 00-C0-02-B9-00-78) per WZCSVC. Keeping these two NICs distinct explains the IP/subnet divergence between the host (192.168.1.111) and the captured traffic (192.168.254.x) — the expected wardriving pattern.

---

## 6. Hacking Software (Q16)

**CONFIRMED — six+ tools installed and present on disk under `Program Files`:**

| Tool | Version | Purpose |
|---|---|---|
| Cain & Abel | v2.5 beta45 | Password cracking / credential sniffing |
| Ethereal + WinPcap | 0.10.6 / 3.01a | Packet sniffing |
| Network Stumbler | 0.4.0 | Wardriving / wireless AP discovery |
| Look@LAN | 2.50 | Network host scanning |
| 123 Write All Stored Passwords | — | Stored-credential dumping |
| Anonymizer Bar | 2.0 | Traffic anonymization |

---

## 7. Evidence of Use — Execution

**CONFIRMED across three independent channels:**
- **Prefetch:** `CAIN.EXE`, `ETHEREAL.EXE`, `LOOKATLAN.EXE`, `LOOKATHOST.EXE`, `MIRC.EXE`, `AGENT.EXE`, plus installers `123WASP_SETUP.EXE`, `ETHEREAL-SETUP-0.10.6.EXE`, `LALSETUP250.EXE` — proving the tools were **run**, not merely installed.
- **AppCompatCache (ShimCache)** from the SYSTEM hive corroborates execution.
- **Per-user attribution (UserAssist, `Mr. Evil` NTUSER.DAT):** GUI launches of `ethereal.exe`, `Cain.exe`, `NetStumbler.exe`, `LookAtLan.exe`, `mirc.exe`, `agent.exe` with non-zero run counts — tying USE specifically to the **Mr. Evil** profile (= Greg Schardt), not merely to the host.

---

## 8. Email & News Identity (Q17–Q20)

**CONFIRMED.** Two programs hold this information (**Q19 = Forte Agent + Outlook Express**):
- **Q17 — SMTP email (Mr. Evil):** `whoknowsme@sbcglobal.net` (Forte Agent `AGENT.INI`, FullName "Mr Evil", SMTP `smtp.sbcglobal.net`).
- **Q18 — NNTP news server:** `news.dallas.sbcglobal.net` (NNTPPort 119).
- **Q20 — Five+ subscribed newsgroups** (Outlook Express `.dbx`): `alt.2600`, `alt.2600.cardz`, `alt.2600.crackz`, `alt.2600.phreakz`, `alt.binaries.hacking.beginner`, `alt.binaries.hacking.utilities`.

---

## 9. IRC / mIRC (Q21–Q22)

**CONFIRMED** (`Program Files\mIRC\mirc.ini`):
- **Q21 — online user settings:** ident `userid=Mrevil`, `nick=Mr`, `anick=mrevilrulez`, `user='Mini Me'`, `email=none@of.ya`, server **Undernet** (`losangeles.ca.us.undernet.org:6660`).
- **Q22 — IRC channels accessed (3+):** `#AllNiteCafe`, `#Chataholics`, `#CyberCafe` (chanfolder lists 80+ joined channels including `#mIRC`, `#Beginner`).

---

## 10. Captured Data — Packet Sniffing (Q23–Q25)

**CONFIRMED.** `Documents and Settings\Mr. Evil\interception` is an **Ethereal/libpcap** capture, created on-host (MFT `$SI` 2004-08-27 15:41:00 UTC), inside Mr. Evil's logon session.
- **Q23 — file name:** `interception` (in `\My Documents`, the Ethereal default save directory).
- **Q24 — victim's computer type:** a **Windows CE / Pocket PC handheld** — User-Agent `Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; PPC; 240x320)` at IP 192.168.254.2.
- **Q25 — websites the victim accessed:** `mobile.msn.com` and Hotmail / MSN Passport; captured login cookie `MSPPre=findme69@hotmail.com`.

**Mechanism — passive wireless sniffing (CONFIRMED).** Full MAC enumeration of the pcap shows only the victim iPAQ (00:0f:20:80:47:17 @ 192.168.254.2), the SpeedStream AP/gateway (00:c0:02:b9:00:78 @ 192.168.254.254) and one stray broadcast. The laptop's own IP (192.168.1.111) appears in **zero** frames and no ARP-poison/karma artifacts are present — consistent with passive interception of a third party (wardriving theory).

---

## 11. Web Mail (Q26–Q27)

**CONFIRMED.**
- **Q26 — main user's web-based email:** a **Yahoo** account, `mrevil2000` — IE History shows `us.f613.mail.yahoo.com` sessions (login, ShowFolder, ShowLetter, Logout); the Cookies folder holds `mr. evil@yahoo[1].txt`.
- **Q27 — Yahoo save filename:** opened messages are saved as **`ShowLetter[N].htm`** in Temporary Internet Files.

---

## 12. Personal Attribution — Second Independent Binding

**CONFIRMED.** Independent of `irunin.ini`, the IE History records a Yahoo registration form submission:

```
edit.yahoo.com/config/id_check?.fn=Greg&.ln=Schardt&.id=mrevil2000
```

The operator self-entered real name **Greg Schardt** while registering the `mrevil2000` persona from the sole Mr. Evil profile. Combined with the `irunin.ini` RegisteredOwner and convergent persona identifiers (mIRC `Mrevil`/`mrevilrulez`, Forte "Mr Evil"), the **Schardt ↔ Mr. Evil ↔ this-laptop** identity is firmly established. **This refutes the alternate-operator hypothesis (H2).**

---

## 13. Deleted Files / Recycle Bin (Q28–Q30)

**CONFIRMED** (Mr. Evil `RECYCLER\S-1-5-21-…-1003`):
- **Q28 — executables in recycle bin:** **4** — `lalsetup250.exe`, `netstumblerinstaller_0_4_0.exe`, `WinPcap_3_01_a.exe`, `ethereal-setup-0.10.6.exe`.
- **Q29 — really deleted?** **No.** The `Dc1`–`Dc4.exe` payloads and the `INFO2` index persist as fully-recoverable PE32 binaries; the bin was never emptied.
- **Q30 — files reported deleted by the filesystem:** **3** unallocated MFT entries.

---

## 14. Anti-Virus Check (Q31)

**CONFIRMED (negative).** A ClamAV physical scan of `Program Files` returned no detections (every file `OK`). The laptop holds **no conventional viruses**; the offensive capability here is the **legitimate-but-dual-use toolset itself**, not signatured malware.

---

## 15. Victim ≠ Subject (Exhaustion Check)

**CONFIRMED.** The interception pcap was exhaustively parsed: `net.http_session_inventory` enumerated **all 9 HTTP sessions and 22 unique cookie names** (the full MSN/Passport set), and `net.pcap_identity_timeline` extracted **25 identity artifacts** across cookie/email/auth fields. A knowns-driven roster sweep (person_username variants of *Greg Schardt* / *Mr. Evil* / *mrevil2000* / *whoknowsme*) returned **0 matches**. Every captured identity (`findme69@hotmail.com`, `rudy@hotmail.com`, the MSPAuth/MSPProf Passport tokens, `inet@microsoft.com`) maps to the **victim** at 192.168.254.2 or to Microsoft Passport servers — none to the suspect. Schardt/Mr. Evil are bound to the laptop entirely from **on-disk** artifacts, so the capture evidences interception of *others*.

---

## 16. Improve & Response Recommendations (advisory only)

> TRUDI never performs containment or eradication — these are recommendations for the human IR / legal team.

**RESPONSE**
- Preserve the original EnCase E01 image and verified hash manifest in the evidence locker under SCHARDT-2002 chain-of-custody; restrict access to lead investigator and prosecuting counsel.
- Package this report, the 19 CONFIRMED findings, and the full TRUDI execution log (causal-DAG export) as the prosecutor disclosure bundle; include the two identity-linkage artifacts (Look@LAN `irunin.ini` RegisteredOwner and the IE Yahoo `id_check` URL) as primary exhibits.
- Notify the third-party Windows-CE victim (Hotmail `findme69@hotmail.com`, capture 2004-08-27) so they can rotate credentials; share capture metadata with the Microsoft/Hotmail abuse desk for victim-side correlation.

**IMPROVE**
- Add the six observed tools to the enterprise unauthorized-software detection / application-allowlist rules so equivalent installs trigger immediately in modern estates.
- Codify the **dual-artifact identity-linkage standard** demonstrated here (require two independent artifact classes before recording a real-world identity as CONFIRMED) as a DAIR Analyze-phase rule.
- Add wireless-interception detection (promiscuous-mode capture tools + libpcap files containing third-party session data) to the network-monitoring use-case catalog.

---

## 17. Methodology & Audit Trail

Single-host disk-only EnCase E01 (verified by full SHA-256). DAIR loop Triage → Collect → Analyze → Scan → Report. Tools run (all via typed MCP wrappers, evidence read-only): `ewf.ewf_info` / `hash.verify_evidence_hash`; `ez.recmd_hive` (SOFTWARE/SYSTEM/SAM, Mr. Evil NTUSER); `ez.appcompatcacheparser`; UserAssist; `ez.pecmd` (Prefetch); `ez.mftecmd`; `ez.rbcmd` (recycle bin); `tsk.fls`/`tsk.icat` (deleted-file recovery); `strings.strings_grep`; `net.http_session_inventory` + `net.pcap_identity_timeline` + `net.ngrep_search`; `misc.knowns_pattern_generate`; ClamAV. Adversarial review via `reason.hypothesize` / `reason.evaluate_finding` / `reason.synthesize` / `reason.pre_report_check`. Competing hypothesis (alternate operator) raised at Triage and **refuted** by two independent identity bindings. Every finding carries a `linked_call_id` to its source tool execution in `reports/SCHARDT-2002_trace.{json,md}`.

**END OF REPORT — SCHARDT-2002**
