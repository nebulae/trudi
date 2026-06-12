# Case: <CASE_ID>

**Evidence integrity: Never modify evidence files. All output to `./analysis/`, `./exports/`, or `./reports/`.**

---

## Case Metadata

| Field | Value |
|-------|-------|
| **Case ID** | <CASE_ID> |
| **Client** | <CLIENT_NAME> |
| **Evidence received** | <YYYY-MM-DD> UTC |
| **Investigator** | <INVESTIGATOR_HANDLE> |

---

## Evidence Files

| Path | System | Description |
|------|--------|-------------|
| `~/cases/<CASE_ID>/evidence/<DISK_IMAGE>.E01` | <HOSTNAME> | C: drive image |
| `~/cases/<CASE_ID>/evidence/<MEMORY_IMAGE>.img` | <HOSTNAME> | RAM capture |

**Mounted:**
- EWF: `/mnt/ewf_<HOSTNAME>/ewf1`
- Filesystem: `/mnt/<HOSTNAME>` (read-only NTFS)

---

## Output Directories

```
~/cases/<CASE_ID>/analysis/    — intermediate work, parsed artifacts
~/cases/<CASE_ID>/exports/     — tool output (CSV, JSON, bodyfiles)
~/cases/<CASE_ID>/reports/     — final investigator reports
```

---

## Scope

<Describe what you're trying to determine — compromise, timeline, attacker activity, etc.>

---

## Investigation discipline (inherited)

The global contract in `~/.claude/CLAUDE.md` governs every case. In particular, observe the **Distinct-Principal & Competing-Hypothesis Discipline**, **Authentication-Session Inventory before attribution**, **Per-Principal / Recipient-Correspondent Exhaustion**, and **Exfil-Channel Enumeration & Ranking** rules — a new account/identity is a separate principal whose controller must be established before its actions are attributed, and an exfil channel claim needs a transfer artifact, not tool/folder presence. These are backed by the broad `attribution` and `transfer` record_finding gates; DAIR may surface host/account leads as `candidate_pivots`, but those candidates are advisory and do not automatically change phases.
