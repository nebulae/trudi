"""EWF / Expert Witness Format tools — mount and verify E01 images."""
import subprocess
import os
import re
from typing import Optional
from fastmcp import FastMCP
from core import run, DEFAULT_TIMEOUT, VOL_TIMEOUT, PLASO_TIMEOUT

mcp = FastMCP("ewf")


@mcp.tool()
def ewf_info(image: str) -> dict:
    """Display E01 image metadata: acquisition hash, timestamps, notes, examiner info."""
    return run(["ewfinfo", image])


@mcp.tool()
def ewf_verify(image: str) -> dict:
    """
    Verify E01 image integrity by recomputing and comparing MD5/SHA1 hashes.
    Must complete without errors before analysis proceeds.
    """
    return run(["ewfverify", image], timeout=VOL_TIMEOUT*6)


@mcp.tool()
def ewf_mount(image: str, mount_point: str) -> dict:
    """
    Mount an E01/EWF image as a raw device at mount_point.
    For multi-segment images (E01/E02/...) specify the first segment only.
    After mounting, run tsk_mmls against mount_point/ewf1 to get partition offsets.
    """
    os.makedirs(mount_point, exist_ok=True)
    return run(["ewfmount", image, mount_point], needs_sudo=True)


@mcp.tool()
def ewf_umount(mount_point: str) -> dict:
    """Unmount an EWF mount point."""
    return run(["umount", mount_point], needs_sudo=True)


_LOWNTFS = "/usr/bin/lowntfs-3g"


def _lowntfs_available() -> bool:
    return os.path.exists(_LOWNTFS)


def _mount_ntfs_ro(ewf_device: str, mount_point: str, offset_bytes: int) -> dict:
    """Read-only NTFS mount, robust to hosts with no in-kernel NTFS driver.

    ntfs-3g spells the journal-safety option ``norecover`` (NOT ``norecovery``);
    the misspelling is rejected by the helper and surfaces as
    "wrong fs type, bad option, bad superblock". Also, on hosts whose kernel has
    no NTFS module (e.g. WSL2), ``mount`` without ``-t`` cannot auto-detect and
    fails the same way — so we retry with an explicit ``-t ntfs-3g``.

    Windows paths are case-insensitive but ntfs-3g is not: a lookup of
    Windows/AppCompat/Programs/Amcache.hve misses the on-disk
    ``Windows/appcompat`` and reads as "Amcache absent". lowntfs-3g with
    ``ignore_case`` is tried first when installed; the case-sensitive chain
    below remains the fallback.
    """
    options = f"ro,loop,norecover,offset={offset_bytes}"
    low = None
    if _lowntfs_available():
        low = run(["mount", "-t", "lowntfs-3g", "-o", options + ",ignore_case",
                   ewf_device, mount_point], needs_sudo=True)
        if low["success"]:
            low["case_insensitive"] = True
            return low
    first = run(["mount", "-o", options, ewf_device, mount_point], needs_sudo=True)
    if first["success"]:
        return _case_sensitive(first, low)
    second = run(
        ["mount", "-t", "ntfs-3g", "-o", options, ewf_device, mount_point],
        needs_sudo=True,
    )
    if second["success"]:
        return _case_sensitive(second, low)
    second["first_attempt_stderr"] = first.get("stderr", "")
    return _case_sensitive(second, low)


def _case_sensitive(result: dict, low: Optional[dict]) -> dict:
    """Mark a fallback mount case-sensitive so a path miss is not read as absence."""
    result["case_insensitive"] = False
    if low is not None:
        result["lowntfs_attempt_stderr"] = low.get("stderr", "")
    if result.get("success"):
        result["path_case_note"] = ("Mounted case-SENSITIVE: a Windows path that is not "
                                    "found may exist with different case (e.g. "
                                    "Windows/appcompat) — list the parent directory "
                                    "before concluding it is absent.")
    return result


@mcp.tool()
def mount_ntfs(
    ewf_device: str,
    mount_point: str,
    offset_bytes: int,
    read_only: bool = True,
) -> dict:
    """
    Mount an NTFS partition from a raw EWF device.
    offset_bytes: byte offset = sector_start * sector_size (from mmls output).
    Always mounts read-only, with norecover to prevent NTFS journal replay.
    Falls back to an explicit ntfs-3g filesystem type when the kernel has no
    in-built NTFS driver.
    """
    os.makedirs(mount_point, exist_ok=True)
    if not read_only:
        return {"success": False, "stderr": "Read-only mount is required for evidence integrity."}
    return _mount_ntfs_ro(ewf_device, mount_point, offset_bytes)


@mcp.tool()
def umount_filesystem(mount_point: str) -> dict:
    """Unmount a mounted filesystem."""
    return run(["umount", mount_point], needs_sudo=True)


_MMLS_ROW_RE = re.compile(r"^\d{3}:\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s*(.*)$")


def _mmls_sector_size(stdout: str) -> int:
    """mmls prints its unit ("Units are in 512-byte sectors"); 4Kn media differ."""
    m = re.search(r"Units are in (\d+)-byte sectors", stdout or "")
    return int(m.group(1)) if m else 512


def _mmls_partitions(stdout: str) -> list[dict]:
    """Real partitions from an mmls table, largest first.

    Skips the Meta and Unallocated rows and keeps every data partition whatever
    its description: a GPT table calls them "Basic data partition", so matching
    the word NTFS in the description finds nothing at all.
    """
    out = []
    for line in (stdout or "").splitlines():
        m = _MMLS_ROW_RE.match(line.strip())
        if not m:
            continue
        slot, start, end, length, desc = m.groups()
        if not slot[0].isdigit():      # Meta / ------- rows carry no partition
            continue
        out.append({"slot": slot, "start": int(start), "end": int(end),
                    "length": int(length), "description": desc.strip()})
    # A description that names the filesystem is the strongest hint; size breaks ties.
    return sorted(out, key=lambda p: ("ntfs" in p["description"].lower(), p["length"]),
                  reverse=True)


@mcp.tool()
def mount_full_image(image_e01: str, ewf_mount_point: str, fs_mount_point: str) -> dict:
    """
    Convenience: mount an E01 image end-to-end.
    1. ewfmount the E01 to ewf_mount_point (exposes ewf1)
    2. Read partition table via mmls
    3. Probe candidate partitions with fsstat and mount the NTFS one

    Returns the mount result and the detected NTFS offset in bytes.
    """

    os.makedirs(ewf_mount_point, exist_ok=True)
    os.makedirs(fs_mount_point, exist_ok=True)

    # Step 1: ewfmount
    ewf_result = run(["ewfmount", image_e01, ewf_mount_point], needs_sudo=True)
    if not ewf_result["success"]:
        return ewf_result

    ewf_device = os.path.join(ewf_mount_point, "ewf1")

    # Step 2: mmls to find NTFS partition
    mmls_result = run(["mmls", ewf_device], needs_sudo=True)
    if not mmls_result["success"]:
        return mmls_result

    sector_size = _mmls_sector_size(mmls_result["stdout"])
    candidates = _mmls_partitions(mmls_result["stdout"])
    if not candidates:
        return {"success": False,
                "stderr": "Could not read any partition from mmls output.",
                "mmls": mmls_result["stdout"]}

    # Confirm with fsstat which candidate actually holds NTFS. A GPT table
    # labels its partitions "Basic data partition", so the description does not
    # name the filesystem; guessing from it mounted nothing and left the agent
    # deriving an offset by hand.
    offset_sectors = None
    checked = []
    for part in candidates:
        probe = run(["fsstat", "-o", str(part["start"]), ewf_device], needs_sudo=True)
        fs_type = ""
        for line in (probe.get("stdout") or "").splitlines():
            if line.lower().startswith("file system type:"):
                fs_type = line.split(":", 1)[1].strip()
                break
        checked.append({**part, "fs_type": fs_type})
        if "ntfs" in fs_type.lower():
            offset_sectors = part["start"]
            break

    if offset_sectors is None:
        return {"success": False,
                "stderr": ("No NTFS filesystem found in any partition (fsstat probed "
                           + ", ".join(f"sector {c['start']}: {c['fs_type'] or 'unreadable'}"
                                       for c in checked) + ")."),
                "partitions": checked, "mmls": mmls_result["stdout"]}

    offset_bytes = offset_sectors * sector_size

    # Step 3: mount NTFS (read-only, explicit ntfs-3g fallback)
    mount_result = _mount_ntfs_ro(ewf_device, fs_mount_point, offset_bytes)
    mount_result["ntfs_offset_bytes"] = offset_bytes
    mount_result["ntfs_offset_sectors"] = offset_sectors
    mount_result["ewf_device"] = ewf_device
    return mount_result
