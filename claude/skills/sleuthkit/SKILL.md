# Skill: File System & Carving (The Sleuth Kit / EWF Tools)

## Overview
Use this skill for disk image analysis, filesystem navigation, file extraction, and
file carving on the SIFT workstation. Evidence images are commonly in E01 (Expert Witness
Format). Always mount read-only to preserve evidence integrity.

---

## Tool Reference

| Tool | Purpose |
|------|---------|
| `ewfinfo` | Display E01 image metadata and embedded hash values |
| `ewfverify` | Verify E01 image integrity against stored hashes |
| `ewfmount` | Mount E01/EWF images as a raw disk device |
| `img_stat` | Display image format and sector size |
| `mmls` | Display partition table (MBR and GPT) |
| `fsstat` | Filesystem metadata (cluster size, MFT location, etc.) |
| `fls` | List files and directories (includes deleted entries) |
| `icat` | Extract file content by inode/MFT number |
| `istat` | Display inode metadata (MAC times, size, allocated blocks) |
| `ffind` | Find filename for an inode |
| `ils` | List inodes (including orphan/deleted) |
| `blkls` | Extract unallocated disk blocks (for carving) |
| `tsk_recover` | Bulk extract all allocated and/or unallocated files |
| `mactime` | Generate timeline from bodyfile |
| `blkcat` | Extract raw data unit content |
| `bulk_extractor` | Carve email addresses, URLs, domains, credit cards, etc. |
| `photorec` | File carving by file signature |

---

## Workflow

### 1. Verify the Image

```bash
# Display E01 metadata (acquisition hash, timestamps, notes)
ewfinfo /cases/<casename>/<image>.E01

# Verify integrity — compare computed vs stored hash
ewfverify /cases/<casename>/<image>.E01
```

Record the MD5/SHA1 from `ewfinfo` output in your case notes. `ewfverify` must complete
without errors before any analysis proceeds.

### 2. Mount E01 Image (Read-Only)

```bash
# Create mount points
sudo mkdir -p /mnt/ewf /mnt/windows_mount

# Mount the E01 via ewfmount (exposes as /mnt/ewf/ewf1)
# For multi-segment images (E01, E02, ... or .e01, .e02, ...), point to the first segment only
sudo ewfmount /cases/<casename>/<image>.E01 /mnt/ewf/

# Confirm the raw device is present
ls /mnt/ewf/
# Expected: ewf1
```

**Multi-segment E01:** `ewfmount` automatically detects and joins all segments when you
specify the first segment. No glob or special syntax needed.

### 3. Check Sector Size

```bash
# Default is 512 bytes; some modern drives use 4096 (4K) sector size
img_stat /mnt/ewf/ewf1

# Look for "Sector Size" in output — use this value in offset calculations
# If 4096: OFFSET = Start_sector * 4096
```

### 4. Inspect Partition Table

```bash
sudo mmls /mnt/ewf/ewf1
# Note the Start sector and sector size for the target partition (usually the largest NTFS)
```

Example output (512-byte sectors):
```
     Slot    Start        End          Length       Description
00:  Meta    0000000000   0000000000   0000000001   Primary Table (#0)
01:  -----   0000000000   0000002047   0000002048   Unallocated
02:  000:00  0000002048   0000534527   0000532480   NTFS / exFAT (0x07)
03:  000:01  0000534528   ...          ...          Recovery
```

**GPT disks:** `mmls` handles GPT automatically — look for partition type GUIDs.

### 5. Mount Filesystem (Read-Only)

```bash
# Byte offset = Start_sector * sector_size (usually 512)
OFFSET=$(( 2048 * 512 ))   # adjust sector start and size from mmls output

sudo mount -o ro,loop,offset=${OFFSET} /mnt/ewf/ewf1 /mnt/windows_mount

# Verify
ls /mnt/windows_mount/
```

**If mount fails (filesystem dirty / hibernation):**
```bash
# Add norecovery for NTFS (no journal replay — preserves evidence state)
sudo mount -o ro,loop,norecovery,offset=${OFFSET} /mnt/ewf/ewf1 /mnt/windows_mount
```

### 6. Filesystem Metadata

```bash
# Filesystem statistics (NTFS version, cluster size, MFT offset, volume ID)
sudo fsstat /mnt/ewf/ewf1

# With partition offset (if fsstat is run against the raw image directly)
sudo fsstat -o 2048 /mnt/ewf/ewf1
```

### 7. Filesystem Navigation with TSK

```bash
# List all files recursively (includes deleted entries — marked with *)
sudo fls -r -p /mnt/ewf/ewf1 > ./analysis/fls_output.txt

# List with MAC times in bodyfile format (for timeline creation)
sudo fls -r -m / /mnt/ewf/ewf1 > ./analysis/bodyfile.txt

# List a specific directory by inode
sudo fls /mnt/ewf/ewf1 <inode_number>

# List root directory (inode 5 on NTFS; inode 2 on ext)
sudo fls /mnt/ewf/ewf1 5

# Show only deleted entries
sudo fls -r -p /mnt/ewf/ewf1 | grep "^\*"

# With partition offset (bypass filesystem mount)
sudo fls -r -o 2048 /mnt/ewf/ewf1
```

**fls flags:**
| Flag | Description |
|------|-------------|
| `-r` | Recursive |
| `-p` | Full path (vs relative) |
| `-m /` | Bodyfile format (prefix `/` = mount point) |
| `-o <sectors>` | Partition offset in sectors |
| `-f <type>` | Force filesystem type (`ntfs`, `fat32`, `ext4`) |
| `-l` | Long format (include all timestamps) |
| `-d` | Show only deleted entries |
| `-D` | Show only directories |
| `-F` | Show only files (non-dirs) |
| `-h` | Hash file contents (MD5, for use with mactime) |
| `-z ZONE` | Display timestamps in specified timezone (e.g., `UTC`) |

### 8. Extract Files by Inode

```bash
# Get inode metadata (MAC times, allocated blocks, file size)
sudo istat /mnt/ewf/ewf1 <inode_number>

# Extract file content to local path
sudo icat /mnt/ewf/ewf1 <inode_number> > ./exports/files/<filename>

# Extract a deleted file (recover from unallocated blocks)
sudo icat -r /mnt/ewf/ewf1 <inode_number> > ./exports/files/<filename>

# Extract file slack space (data after EOF in last cluster)
sudo icat -s /mnt/ewf/ewf1 <inode_number> > ./exports/files/<filename>_slack

# Find filename for a known inode
sudo ffind /mnt/ewf/ewf1 <inode_number>

# With partition offset
sudo icat -o 2048 /mnt/ewf/ewf1 <inode_number> > ./exports/files/<filename>
```

### 9. Inode and Block-Level Analysis

```bash
# List all inodes (orphan entries = deleted with no directory entry)
sudo ils /mnt/ewf/ewf1 > ./analysis/ils_output.txt

# List only orphan (unlinked) inodes — deleted files with no directory entry
sudo ils -p /mnt/ewf/ewf1 > ./analysis/ils_orphan.txt

# List all inodes (allocated + unallocated)
sudo ils -e /mnt/ewf/ewf1 > ./analysis/ils_all.txt

# List only allocated inodes
sudo ils -a /mnt/ewf/ewf1 > ./analysis/ils_allocated.txt

# List only unallocated inodes
sudo ils -A /mnt/ewf/ewf1 > ./analysis/ils_unallocated.txt

# Mactime bodyfile format (combine with fls bodyfile for timeline)
sudo ils -m /mnt/ewf/ewf1 > ./analysis/ils_bodyfile.txt

# Extract raw unallocated blocks (for carving on tight storage budgets)
sudo blkls /mnt/ewf/ewf1 > ./analysis/unallocated.raw
# or targeted:
sudo blkls -a /mnt/ewf/ewf1 > ./analysis/allocated.raw     # allocated blocks only
sudo blkls -A /mnt/ewf/ewf1 > ./analysis/unallocated.raw   # unallocated blocks only
sudo blkls -s /mnt/ewf/ewf1 > ./analysis/slack.raw         # file slack space only
sudo blkls -e /mnt/ewf/ewf1 > ./analysis/every.raw         # every block (all types)
```

### 10. Bulk File Recovery

```bash
# Recover all allocated files, preserving directory structure (default)
sudo tsk_recover /mnt/ewf/ewf1 ./exports/tsk_recover/

# Recover allocated files only (explicit)
sudo tsk_recover -a /mnt/ewf/ewf1 ./exports/tsk_recover_alloc/

# Recover ALL files including unallocated/deleted
sudo tsk_recover -e /mnt/ewf/ewf1 ./exports/tsk_recover_all/

# Recover from a specific directory inode only
sudo tsk_recover -d <dir_inode> /mnt/ewf/ewf1 ./exports/tsk_recover_subdir/
```

### 11. Generate Filesystem Timeline

```bash
# Step 1: Create bodyfile
sudo fls -r -m / /mnt/ewf/ewf1 > ./analysis/bodyfile.txt

# Step 2: Convert to sorted timeline (UTC, default tab-separated)
mactime -b ./analysis/bodyfile.txt -z UTC > ./exports/fs_timeline.txt

# Step 2 (alt): CSV output (easier to open in Timeline Explorer)
mactime -b ./analysis/bodyfile.txt -z UTC -d > ./exports/fs_timeline.csv

# Step 2 (alt): ISO 8601 timestamps (sortable, unambiguous)
mactime -b ./analysis/bodyfile.txt -z UTC -y > ./exports/fs_timeline_iso.txt

# Step 3 (optional): Filter by date range
mactime -b ./analysis/bodyfile.txt -z UTC -d 2023-01-01 2023-12-31 > ./exports/fs_timeline_filtered.txt

# Step 4 (optional): Generate hourly/daily index for large timelines
mactime -b ./analysis/bodyfile.txt -z UTC -i hour ./analysis/timeline_index.txt > ./exports/fs_timeline.txt

# Step 5 (optional): Export as bodyfile for use with log2timeline
# The bodyfile.txt IS the output — pass directly to log2timeline.py as a source
```

**mactime flags:**
| Flag | Description |
|------|-------------|
| `-b <file>` | Input bodyfile |
| `-z ZONE` | Timezone (always use `UTC`) |
| `-d` | CSV output (comma-separated, easier for spreadsheet tools) |
| `-y` | ISO 8601 date format (YYYY-MM-DD) instead of US format |
| `-h` | Add session header with metadata and column names |
| `-i [day\|hour] <file>` | Write hourly/daily index file for navigation |

### 12. Targeted Artifact Extraction

```bash
# Windows event logs
sudo find /mnt/windows_mount/Windows/System32/winevt/Logs/ -name "*.evtx" \
  -exec cp {} ./exports/evtx/ \;

# Registry hives
for hive in SYSTEM SOFTWARE SECURITY SAM; do
  sudo cp /mnt/windows_mount/Windows/System32/config/$hive ./exports/registry/
done

# User NTUSER.DAT hives (all users)
sudo find /mnt/windows_mount/Users/ -name "NTUSER.DAT" \
  -exec cp --parents {} ./exports/registry/ \;

# UsrClass.dat (shellbags, file associations — in each user's Local profile)
sudo find /mnt/windows_mount/Users/ -name "UsrClass.dat" \
  -exec cp --parents {} ./exports/registry/ \;

# Prefetch files
sudo mkdir -p ./exports/prefetch/
sudo cp -r /mnt/windows_mount/Windows/Prefetch/ ./exports/prefetch/

# MFT (inode 0 on NTFS)
sudo icat /mnt/ewf/ewf1 0 > ./exports/mft/\$MFT

# UsnJrnl (inode 11 on NTFS) — $J data stream contains the change journal
sudo icat /mnt/ewf/ewf1 11-128-4 > ./exports/mft/\$J 2>/dev/null || \
sudo icat /mnt/ewf/ewf1 11 > ./exports/mft/\$J

# Amcache
sudo cp /mnt/windows_mount/Windows/AppCompat/Programs/Amcache.hve ./exports/registry/

# SRUM database
sudo mkdir -p ./exports/srum/
sudo cp /mnt/windows_mount/Windows/System32/sru/SRUDB.dat ./exports/srum/

# Browser profiles (Chrome/Edge)
sudo find /mnt/windows_mount/Users/ \
  -path "*/Google/Chrome/User Data/Default/History" \
  -exec cp --parents {} ./exports/browser/ \;
sudo find /mnt/windows_mount/Users/ \
  -path "*/Microsoft/Edge/User Data/Default/History" \
  -exec cp --parents {} ./exports/browser/ \;

# Recycle Bin
sudo cp -r "/mnt/windows_mount/\$Recycle.Bin/" ./exports/recyclebin/

# Scheduled tasks (XML definitions)
sudo cp -r /mnt/windows_mount/Windows/System32/Tasks/ ./exports/tasks/

# PowerShell transcript logs (if enabled)
sudo find /mnt/windows_mount/Users/ -name "PowerShell_transcript*.txt" \
  -exec cp --parents {} ./exports/pslogs/ \;
```

---

## File Carving

### bulk_extractor

```bash
# Full carve from raw image (default: 4 threads in v2.0+)
sudo bulk_extractor -o ./exports/carved/ /mnt/ewf/ewf1

# Targeted feature types only (faster for specific IOC hunting)
sudo bulk_extractor -o ./exports/carved/ -e email -e url -e domain /mnt/ewf/ewf1

# Increase thread count for speed on multi-core SIFT
sudo bulk_extractor -j 8 -o ./exports/carved/ /mnt/ewf/ewf1

# Carve from unallocated space only
sudo blkls -u /mnt/ewf/ewf1 > /tmp/unalloc.raw
sudo bulk_extractor -o ./exports/carved_unalloc/ /tmp/unalloc.raw
```

Output: feature files for email addresses, URLs, domains, credit cards, BTC addresses,
telephone numbers, and more — each with byte offset back to image.

### PhotoRec (Signature-Based File Recovery)

```bash
sudo photorec /mnt/ewf/ewf1
# Interactive: select partition → file types → output directory
# Use ./exports/photorec/ as output directory
```

---

## Hash Verification and Known-File Filtering

```bash
# Compute MD5 hash of an extracted file
md5sum ./exports/files/<filename>

# Generate MD5 hashes of all extracted files for case documentation
find ./exports/files/ -type f -exec md5sum {} \; > ./exports/files/md5_manifest.txt

# Filter against NSRL (known-good software) with hashdeep
# (hashdeep must be installed: apt install hashdeep)
hashdeep -r /mnt/windows_mount/Windows/ -l > ./analysis/windows_hashes.txt
```

---

## Unmounting

```bash
# Always unmount in reverse order (filesystem first, then EWF)
sudo umount /mnt/windows_mount
sudo umount /mnt/ewf
```

---

## Output Paths

| Output | Path |
|--------|------|
| Bodyfile | `./analysis/` |
| FLS output | `./analysis/fls_output.txt` |
| Filesystem timeline | `./exports/fs_timeline.txt` |
| Extracted files | `./exports/files/` |
| Registry hives | `./exports/registry/` |
| Event logs | `./exports/evtx/` |
| MFT + UsnJrnl | `./exports/mft/` |
| SRUM | `./exports/srum/` |
| Prefetch | `./exports/prefetch/` |
| Carved files | `./exports/carved/` |
| Recovered files (tsk) | `./exports/tsk_recover/` |

---

## Notes

- Never write to `/mnt/` paths — read-only mounts only
- `fls -p` flag shows full paths (more readable than relative paths)
- Deleted files appear with a `*` prefix in `fls` output
- Use `-o <sectors>` flag with all TSK tools when bypassing mount (more reliable than loopback)
- `img_stat` before `mmls` catches 4K sector drives — wrong sector size = wrong byte offset
- `norecovery` mount option prevents NTFS journal replay that could alter analysis
- `icat` is preferred over `cp` for extracting files — bypasses OS file locking and VSS
- The bodyfile from `fls` can be fed directly to `log2timeline.py` as an input source
- VSS (Volume Shadow Copies) can be mounted: use `mmls` on VSS metadata and `icat` with offsets
