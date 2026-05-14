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
