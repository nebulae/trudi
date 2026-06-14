## M57-JEAN Case Context

**Case ID:** M57-JEAN
**Source:** M57.biz scenario ("The case of M57.biz — Investigating corporate exfiltration"), Garfinkel/NPS scenario family
**Evidence type:** Single-host disk image (no memory, no network capture)
**Evidence root:** `/home/trin/cases/m57-jean/evidence/`
**Opened:** 2026-06-02
**Status:** Evidence acquisition in progress (downloading) — investigation not yet started.

---

### Scenario

**M57.biz** is a hip web start-up developing a body art catalog.

- $3M in seed funding; closing a $10M round at time of incident
- 2 founder/owners, 10 first-year employees
- **Virtual corporation**: programmers WFH (daily online chat, weekly in-person at office park); marketing & BizDev on the road (hotels, Starbucks; in-person every two weeks). **Most documents exchanged by email.**

**The incident:** A spreadsheet (`m57plan.xlsx`) containing the full employee roster — names, positions, salaries, and Social Security Numbers — was posted as an attachment in the "technical support" forum of a competitor's website. The spreadsheet came from CFO Jean's computer.

**Conflicting statements:**
- **Alison Smith (President):** "I don't know what Jean is talking about. I never asked Jean for the spreadsheet. I never received the spreadsheet by email."
- **Jean Jones (CFO):** "Alison asked me to prepare the spreadsheet as part of the new funding round. Alison asked me to send the spreadsheet to her by email. That's all I know."

---

### Case Question

**CASE_QUESTION:** How did `m57plan.xlsx` (containing employee names, salaries, and SSNs) get from CFO Jean's M57.biz workstation to the "technical support" forum of a competitor's website, and who within M57.biz was involved?

Sub-questions from the client (first-round funder):
1. When did Jean create this spreadsheet?
2. How did it get from her computer to the competitor's website?
3. Who else from the company is involved?

---

### Roster (knowns for identifier cross-reference)

| Name | Position | Salary | SSN |
|---|---|---|---|
| Alison Smith | President | $140,000 | 103-44-3134 |
| Jean Jones | CFO | $120,000 | 432-34-6432 |
| Bob Blackman | Programmer (Apps 1) | $90,000 | 493-46-3329 |
| Carol Canfred | Programmer (Apps 2) | $110,000 | 894-33-4560 |
| Dave Daubert | Programmer (Q&A) | $67,000 | 331-95-1020 |
| Emmy Arlington | Programmer (Entry Level) | $57,000 | 404-98-4079 |
| Gina Tangers | Marketing (Creative 1) | $80,000 | 980-97-3311 |
| Harris Jenkins | Marketing (G&C) | $105,000 | 887-33-5532 |
| Indy Counterching | BizDev (Outreach) | $240,000 | 123-45-6789 |

**Annual Salaries:** $1,009,000 · **Benefits (30%):** $302,700

**Mandatory at first Triage batch:**
- `misc.knowns_pattern_generate(reference_set=[<first last>, ...], derivation_type="person_username")` → grep against MFT, mailbox, browser history, $UsnJrnl
- `misc.knowns_pattern_generate(reference_set=[<SSN>, ...], derivation_type="exact")` → strings/grep sweep for any SSN in unallocated, pagefile, browser cache, email store
- Identifier normalization (case fold, separator equivalence, `first.last`/`first_last`/`firstlast`/`flast`/`firstl`, email-prefix extraction) before declaring any non-match

---

### Known electronic identities

- `alison@m57.biz` — password `"ab=8989` (literal leading double-quote)
- `jean@m57.biz` — password `gick*1212`

(Credentials recorded for context only; never used against live systems. Evidence is read-only.)

---

### Evidence Inventory

| File | Format | Size | Notes |
|------|--------|------|-------|
| `nps-2008-jean.E01` | EnCase E01 segment 1 | 1.5 GB | Primary image of Jean's workstation (NPS-2008-Jean dataset) |
| `nps-2008-jean.E02` | EnCase E01 segment 2 | 1.4 GB | Continuation |

**Reference (not in evidence/):** the case briefing PDF (`M57-Jean.pdf`) ships separately; `m57plan.xlsx` was not provided with the image set.
**Not provided:** memory image, network capture, co-worker workstations, AFF format (briefing mentioned an `.aff` but only the E01 set was delivered).
**Implication:** Attribution beyond Jean's machine must come from artifacts on Jean's disk — email headers (Received chain, Message-ID, Return-Path), MAPI/PST stores, webmail browser cache, sent items, contacts, IM logs, $Recycle.Bin, VSS snapshots, USN journal, LNK/Jump Lists.

---

### Investigative Threads (a priori, before evidence)

1. **Spreadsheet origin & timing** — `m57plan.xlsx` OOXML internal metadata (`docProps/core.xml`, `app.xml`): `dc:creator`, `cp:lastModifiedBy`, `dcterms:created`, `dcterms:modified`, `Application`, `AppVersion`, total edit time. Cross-check against MFT $SI/$FN on Jean's disk and any LNK / Office MRU / Jump List entries.
2. **Outbound email path** — full mailbox enumeration via `misc.pff_export` (PST/OST) or `misc.readpst_extract`; verify SMTP `Received:` chain, `Return-Path`, `Message-ID` domain, and recipient address on every send of `m57plan.xlsx`. **Do not trust the From: header alone** — header spoofing / look-alike domain is the classic move in this scenario family.
3. **Webmail / browser path** — Hindsight on all browser profiles; cookies, autofill, form data, history for any webmail (Gmail/Yahoo/Hotmail) and for the competitor's forum URL.
4. **Recipient identity vs. roster** — every recipient address found must be cross-referenced against the M57 roster with full normalization. A `From:` that *looks like* Alison but isn't `alison@m57.biz` is the kind of detail this case is built around — flag explicitly.
5. **Local handling** — recent docs, $Recycle.Bin, USN journal entries, VSS snapshots showing earlier copies of the spreadsheet, Prefetch for Excel and any archiver / mail client / browser launches around the create/send window.
6. **Other involved parties** — Alison's denial + Jean's claim is a direct conflict. Resolving it requires either (a) an email actually delivered to `alison@m57.biz`, or (b) evidence the delivery target was someone else (look-alike domain, spoofed address, attacker-controlled inbox).

---

### Phase entry checklist

Before the **initial Triage** batch (per global `CLAUDE.md`):
- `misc.start_execution_log(case_id="M57-JEAN", output_path="./analysis/M57-JEAN_trace.json")` — announce dashboard URL
- `hash.verify_evidence_hash` on `nps-2008-jean.E01` and `nps-2008-jean.E02` (once per file per case)
- `ewf.ewf_info` on `nps-2008-jean.E01` (acquisition metadata is allowed here even though normally suppressed — this is the only system-identity source absent memory)
- `strings.stat_file` on each evidence file
- Parallel pre-plan reads of SOFTWARE / SYSTEM / SAM via `ez.recmd_hive` once the image is mounted (ewf → ro loop → ntfs-3g via `ewf.mount_full_image`)
- `reason.hypothesize` on CASE_QUESTION (capture each `hypothesis_id` — route findings via `tested_hypothesis_id`)
- `reason.plan` with combined pre-plan output as `evidence_available`

---

### Output routing

- Scripts, CSVs, JSON: `/home/trin/cases/m57-jean/analysis/`
- Tool-grade exports (mailbox, registry CSV, timeline CSV): `/home/trin/cases/m57-jean/exports/`
- Trace + final report: `/home/trin/cases/m57-jean/reports/` (`M57-JEAN_trace.json` / `.md`, `M57-JEAN_report.md`)
- Mount points: `/home/trin/cases/m57-jean/mnt/`

All timestamps UTC. Evidence directory is strict read-only.

---

### Hackathon submission

Add to Find Evil! submission artifacts. Strong demo-video candidate IF a self-correction surfaces (e.g. early "Jean sent to Alison" hypothesis revised when `Received:` headers don't terminate at `m57.biz`). Per global hackathon notes, route the final report + trace into the submission bundle on completion.
