"""EWF / Expert Witness Format tools — mount and verify E01 images."""
import subprocess
import os
from typing import Optional
from fastmcp import FastMCP
from core import run

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
    return run(["ewfverify", image], timeout=3600)


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
    Always mounts read-only. Adds norecovery to prevent NTFS journal replay.
    """
    os.makedirs(mount_point, exist_ok=True)
    options = f"ro,loop,norecovery,offset={offset_bytes}"
    if not read_only:
        return {"success": False, "stderr": "Read-only mount is required for evidence integrity."}
    return run(
        ["mount", "-o", options, ewf_device, mount_point],
        needs_sudo=True,
    )


@mcp.tool()
def umount_filesystem(mount_point: str) -> dict:
    """Unmount a mounted filesystem."""
    return run(["umount", mount_point], needs_sudo=True)


@mcp.tool()
def mount_full_image(image_e01: str, ewf_mount_point: str, fs_mount_point: str) -> dict:
    """
    Convenience: mount an E01 image end-to-end.
    1. ewfmount the E01 to ewf_mount_point (exposes ewf1)
    2. Read partition table via mmls
    3. Mount the largest NTFS partition to fs_mount_point

    Returns the mount result and the detected NTFS offset in bytes.
    """
    import re

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

    # Parse largest NTFS partition start sector
    offset_sectors = None
    sector_size = 512
    best_len = 0
    for line in mmls_result["stdout"].splitlines():
        if "NTFS" in line or "0x07" in line:
            parts = line.split()
            # mmls columns: slot, start, end, length, description
            for i, p in enumerate(parts):
                try:
                    start = int(p)
                    length = int(parts[i + 2]) if i + 2 < len(parts) else 0
                    if length > best_len:
                        best_len = length
                        offset_sectors = start
                except (ValueError, IndexError):
                    continue

    if offset_sectors is None:
        return {"success": False, "stderr": "Could not detect NTFS partition from mmls output.", "mmls": mmls_result["stdout"]}

    offset_bytes = offset_sectors * sector_size

    # Step 3: mount NTFS
    options = f"ro,loop,norecovery,offset={offset_bytes}"
    mount_result = run(
        ["mount", "-o", options, ewf_device, fs_mount_point],
        needs_sudo=True,
    )
    mount_result["ntfs_offset_bytes"] = offset_bytes
    mount_result["ntfs_offset_sectors"] = offset_sectors
    mount_result["ewf_device"] = ewf_device
    return mount_result
