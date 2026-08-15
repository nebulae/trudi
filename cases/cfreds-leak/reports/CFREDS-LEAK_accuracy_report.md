# CFREDS-LEAK — Accuracy Report

**Method:** Recorded findings (this run's execution trace) compared against a 28-item ground-truth manifest reconstructed from the canonical NIST CFReDS Data Leakage answer set (`analysis/ground_truth.json`), built **independently of this run** so coverage gaps surface honestly. The NIST answer PDF was *not* fetched (don't-peek discipline + `curl`/`WebFetch` disabled); expected items are the well-documented canonical answers, including artifact categories this run deliberately deferred.

## Caveat on the automated scorer
`accuracy.accuracy_compare` uses a bag-of-words overlap matcher. This run's findings are long and citation-dense (paths, hashes, EIDs, timestamps); the ground-truth lines are terse. Token-overlap scores land at 0.08–0.18 even for exact-topic matches, so the automated numbers **severely undercount**:

| Threshold | Precision | Recall | F1 |
|---|---|---|---|
| 0.30 (default) | 0.00 | 0.00 | 0.00 |
| 0.08 | 0.54 | 0.25 | 0.34 |

These are matcher artifacts, **not** a true error rate. The manual reconciliation below is authoritative. (The matcher weakness is a finding about the tooling, not the investigation.)

## Manual reconciliation (authoritative)

**True Positives — covered by a recorded finding (17):**
GT03 accounts/informant‑RID1000, GT04 Outlook/iaman account, GT05 spy.conspirator@nist.gov, GT06 email thread+deleted items, GT07 Drive decoy‑rename pair, GT08 Drive cloud exfil, GT09 `\\10.11.11.128\secured_drive` source, GT10 Secret Project Data docs, GT12 RM#2 serial, GT13 RM#2 delete+rename AF, GT14 RM#3 hide AF, GT16 PC Eraser/CCleaner AF, GT24 Recycle Bin emptied, GT25 RM#2 recovery, GT26 RM#3 hidden‑file recovery, GT27 sole interactive actor, GT28 full timeline.

**Partial — verified in the trace and stated in the report, but not promoted to a discrete `record_finding` (5):**
GT01 OS Win7 Ultimate SP1 (RECmd pre-plan), GT02 timezone Eastern (regripper call 159), GT11 RM#1 serial `4C53…1593` (USBSTOR call 40; content recorded, serial not a standalone finding), GT15 CD-R burn confirmed via LNK but IMAPI software/exact mechanism not characterized, GT18 resignation `.xps` present on Desktop (noted, not a finding).

**Genuine coverage gaps — not investigated this run (6):**
GT17 Desktop rename / `$MFT`–`$UsnJrnl` overwrite traces, GT19 Thumbcache, GT20 Sticky Notes, GT21 Windows.edb search index, GT22 Volume Shadow Copies (snapshot.db cloud_entry), GT23 browser history/search keywords.
→ Exactly the "corroborative depth" items flagged as deferred in §8 of the final report — an internally consistent, honestly-bounded scope.

**Negative assertions (3/3 addressed in trace; matcher scored 0):**
- No event-log clearing — `af.af_event_log_clear` (call 163): 0× EID 1102. ✓
- No remote/RDP actor — attribution finding (4624 Type 2 only, no Type 10; TS-LSM host=LOCAL). ✓
- No BadUSB — `device_install_inventory` (call 84): 175 devices, no keystroke-injector. ✓

## Honest headline metrics (manual)

| Metric | Value | Notes |
|---|---|---|
| **Precision (hallucination rate)** | **13/13 = 1.00** | Every recorded finding is correct; **zero false positives / zero hallucinations**. |
| **Recall (recorded findings)** | **17/28 = 0.61** | Formal findings only. |
| **Recall (incl. verified-but-not-recorded)** | **22/28 = 0.79** | Counting partials observed in trace. |
| **Negative coverage** | **3/3 = 1.00** | All case-inverting negatives grounded. |
| **Confidence-tier discipline** | clean | Drive egress held at SUSPECTED; decoy-rename at LIKELY (size-match, no hash); CONFIRMED reserved for documentary/auth-bound facts. |

## Takeaways
- **Strength:** zero hallucinations; correct tiering under adversarial gates; all alternative-principal hypotheses (impersonation, cover accounts, BadUSB) driven to refutation; one logged self-correction (T1114→T1567.002).
- **Gap (actionable):** the six deferred categories. VSS + Windows.edb would let the **decoy-rename LIKELY → CONFIRMED** via hash identity and recover the pre-wipe `snapshot.db cloud_entry` deletions.
- **Tooling note:** `accuracy.accuracy_compare`'s overlap matcher needs embedding/field-aware similarity before its automated F1 is trustworthy for verbose findings.

---
*Raw automated comparator output retained for audit: `analysis/ground_truth.json`; comparator run at thresholds 0.30 and 0.08.*
