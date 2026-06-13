# Skill: Timeline Generation (Plaso / log2timeline)

> **Installation:** Plaso 20240308 installed from the GIFT PPA (`ppa:gift/stable`).
> Packages: `python3-plaso`, `plaso-tools`, `python3-pytsk3`.
> The standard Ubuntu jammy universe package conflicts with SIFT's libyal libraries —
> always install from GIFT PPA:
> ```bash
> sudo add-apt-repository ppa:gift/stable
> sudo apt install python3-plaso plaso-tools python3-pytsk3
> ```

## Overview
Use this skill for all super-timeline creation, filtering, and analysis tasks using the
Plaso suite on the SANS SIFT workstation. Plaso parses hundreds of artifact types from
disk images, mounted filesystems, and individual files into a unified timeline.

## Tools

| Tool | Purpose |
|------|---------|
| `log2timeline.py` | Parse evidence sources into a Plaso storage file (.plaso) |
| `psort.py` | Filter, sort, and export Plaso storage to CSV/JSON/other formats |
| `pinfo.py` | Inspect Plaso storage file metadata and parser hit statistics |
| `psteal.py` | One-step: parse + export without creating an intermediate .plaso file |
| `image_export.py` | Extract specific files from disk images for targeted analysis |

---

## Workflow

### 1. Verify Evidence (Read-Only)

```bash
# Inspect an existing .plaso file
pinfo.py /path/to/existing.plaso

# Confirm image type before ingestion
file /mnt/ewf/ewf1
```

### 2a. Create Super-Timeline (Full Ingest)

```bash
log2timeline.py \
  --storage-file ./analysis/<CASE_ID>.plaso \
  --parsers win10 \
  --hashers md5,sha256 \
  --timezone UTC \
  /mnt/ewf/ewf1

# With Volume Shadow Copy (VSS) support — enumerates all shadow copies
log2timeline.py \
  --storage-file ./analysis/<CASE_ID>.plaso \
  --parsers win10 \
  --hashers md5 \
  --vss-stores all \
  --timezone UTC \
  /mnt/ewf/ewf1
```

**Common parser presets:**
| Parser Set | Use For |
|------------|---------|
| `win10` | Windows 10/11 / Server 2016–2022 (**preferred for modern Windows**) |
| `win7` | Windows 7/8/8.1 — may work for Win10 but `win10` is more complete |
| `win_gen` | Generic Windows artifacts (lighter than win10) |
| `linux` | Linux system artifacts |
| `webhist` | Browser history (all browsers) |
| `android` | Android device artifacts |

**To list all available parsers:**
```bash
log2timeline.py --parsers list
```

### 2b. One-Step Ingest + Export (psteal — No .plaso File)

Use when you need a quick CSV and don't need the persistent .plaso storage:

```bash
psteal.py \
  --source /mnt/ewf/ewf1 \
  --output-format l2tcsv \
  --write ./exports/<CASE_ID>_timeline.csv \
  --parsers win10 \
  --timezone UTC
```

### 2c. Targeted Ingest (Faster — Specific Paths or Artifact Types)

Parse only specific directories or artifact types to reduce processing time:

```bash
# Parse only a mounted filesystem path (not raw image)
log2timeline.py \
  --storage-file ./analysis/<CASE_ID>.plaso \
  --parsers win10 \
  --timezone UTC \
  /mnt/windows_mount/Windows/

# Parse only event logs (winevtx parser)
log2timeline.py \
  --storage-file ./analysis/<CASE_ID>_evtx.plaso \
  --parsers winevtx \
  --timezone UTC \
  ./exports/evtx/

# Parse only registry hives
log2timeline.py \
  --storage-file ./analysis/<CASE_ID>_reg.plaso \
  --parsers winreg \
  --timezone UTC \
  ./exports/registry/

# Parse a bodyfile output from fls (filesystem MAC times)
log2timeline.py \
  --storage-file ./analysis/<CASE_ID>_fls.plaso \
  --parsers mactime \
  --timezone UTC \
  ./analysis/bodyfile.txt
```

### 3. Inspect Storage

```bash
# Show parser statistics, source info, and event count
pinfo.py ./analysis/<CASE_ID>.plaso

# Verbose — show all parsers and their individual event counts
pinfo.py -v ./analysis/<CASE_ID>.plaso
```

Always run `pinfo.py` after `log2timeline.py` to confirm parser hit counts.
Zero hits from expected parsers indicates wrong parser set or a mount problem.

### 4. Filter & Export

```bash
# Export all events to CSV (l2tcsv — compatible with Timeline Explorer)
psort.py -o l2tcsv \
  -w ./exports/<CASE_ID>_timeline.csv \
  ./analysis/<CASE_ID>.plaso

# Export to dynamic CSV (more columns, better for script-based pivoting)
psort.py -o dynamic \
  -w ./exports/<CASE_ID>_dynamic.csv \
  ./analysis/<CASE_ID>.plaso

# Export to JSON (for scripted processing)
psort.py -o json \
  -w ./exports/<CASE_ID>_timeline.json \
  ./analysis/<CASE_ID>.plaso

# Filter by date/time range (UTC)
psort.py -o l2tcsv \
  -w ./exports/<CASE_ID>_filtered.csv \
  ./analysis/<CASE_ID>.plaso \
  "date > '2023-01-01 00:00:00' AND date < '2023-02-01 00:00:00'"

# Filter by keyword in the message/description field
psort.py -o l2tcsv \
  -w ./exports/<CASE_ID>_powershell.csv \
  ./analysis/<CASE_ID>.plaso \
  "message contains 'powershell'"

# Combined filter: time range AND keyword
psort.py -o l2tcsv \
  -w ./exports/<CASE_ID>_combined.csv \
  ./analysis/<CASE_ID>.plaso \
  "date > '2023-01-24 00:00:00' AND date < '2023-01-26 00:00:00' AND message contains 'cmd.exe'"

# Filter by parser/data source type
psort.py -o l2tcsv \
  -w ./exports/<CASE_ID>_evtx.csv \
  ./analysis/<CASE_ID>.plaso \
  "parser contains 'winevtx'"

# Quick pivot: events within 5 minutes of a known timestamp
psort.py -o l2tcsv \
  -w ./exports/<CASE_ID>_slice.csv \
  --slice '2023-01-25 14:52:00' \
  ./analysis/<CASE_ID>.plaso
```

### 5. Merging Multiple .plaso Files

When you've run separate ingest jobs (e.g., disk + evtx directory + memory bodyfile):

```bash
psort.py \
  -o l2tcsv \
  -w ./exports/<CASE_ID>_merged.csv \
  ./analysis/<CASE_ID>_disk.plaso \
  ./analysis/<CASE_ID>_evtx.plaso \
  ./analysis/<CASE_ID>_fls.plaso
```

`psort.py` accepts multiple `.plaso` files and outputs them in a single chronological export.

---

## Extract Files from Image (image_export.py)

Extract specific files from a disk image without mounting it:

```bash
# Export files matching a name pattern
image_export.py \
  --write ./exports/files/ \
  --name "*.evtx" \
  /mnt/ewf/ewf1

# Export files by extension
image_export.py \
  --write ./exports/files/ \
  --extension "pf,lnk" \
  /mnt/ewf/ewf1

# Export files using a filter file (one path pattern per line)
# Example filter.txt contents:
#   /Windows/System32/winevt/Logs/
#   /Windows/Prefetch/
#   /Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat
image_export.py \
  --write ./exports/files/ \
  --filter /path/to/filter.txt \
  /mnt/ewf/ewf1
```

---

## Key Flags Reference

**log2timeline.py:**
| Flag | Description |
|------|-------------|
| `--storage-file <file>` | Output .plaso storage file path |
| `--parsers <set>` | Parser preset or comma-separated list |
| `--hashers md5,sha256` | Hash all processed files |
| `--timezone UTC` | Always use UTC |
| `--vss-stores all` | Process all Volume Shadow Copies |
| `--vss-stores 1,2` | Process specific VSS store numbers |
| `--single-process` | Debug mode — slower, better error messages |
| `-q` | Quiet mode (suppress progress bar) |
| `--worker-memory-limit N` | Limit per-worker RAM in MB (default: 3072) |

**psort.py:**
| Flag | Description |
|------|-------------|
| `-o <format>` | Output format: `l2tcsv`, `dynamic`, `json` |
| `-w <file>` | Write output to file |
| `--slice <datetime>` | Events within 5 min of this timestamp (quick pivot) |
| `-z UTC` | Force UTC output timezone |

---

## Filtering in Timeline Explorer (GUI)

After exporting to CSV, open in Timeline Explorer (`wine` or Windows VM):

```bash
wine /opt/zimmermantools/TimelineExplorer/TimelineExplorer.exe
```

Key filtering strategy in Timeline Explorer:
- **Source** column — filter to artifact type (EVT, FILE, REG, WEBHIST, etc.)
- **Type** column — narrow to event sub-type (e.g., `Last Written Time`)
- **Message** column — primary search target; use Ctrl+F for keyword search
- **Tag** column — mark events of interest; export tagged-only subset

---

## Output Paths

| Output | Path |
|--------|------|
| Plaso storage | `./analysis/<CASE_ID>.plaso` |
| CSV timelines | `./exports/<CASE_ID>_timeline.csv` |
| Filtered CSVs | `./exports/<CASE_ID>_filtered.csv` |
| Extracted files | `./exports/files/` |

---

## Notes

- `win10` parser preset is the correct choice for Windows 10/11 and Windows Server 2016+
- `win7` parser still works on modern Windows images but may miss newer artifact types
- `--vss-stores all` is essential for intrusion cases — attackers often delete files VSS preserves
- NEVER write .plaso or CSV output to `/mnt/` or `/media/` — always use `./analysis/` or `./exports/`
- `pinfo.py` after ingest is mandatory — zero parser hits means configuration error, not a clean system
- Large images (>100 GB) can take hours; use targeted `--parsers` or path-scoped ingest to reduce time
- `psort.py` accepts multiple .plaso files — merge disk + memory bodyfile + log timelines into one export
- `--slice` in psort is invaluable for quick pivots around a known event timestamp
