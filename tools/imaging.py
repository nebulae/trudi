"""Image mounting tools — vshadowmount, xmount, bdemount, photorec."""
import os
from typing import Optional
from fastmcp import FastMCP
from core import run, output_safe
from core.paths import assert_output_safe

mcp = FastMCP("imaging")


# ── Volume Shadow Copies ───────────────────────────────────────────────────────

_NO_VSS_MARKER = "No Volume Shadow Snapshots found"


@mcp.tool()
@output_safe
def vshadow_mount(
    image_or_device: str,
    mount_point: str,
    offset: int = 0,
    allow_other: bool = True,
) -> dict:
    """
    Mount Volume Shadow Copies (VSS) from a disk image or device using vshadowmount.
    Exposes shadow copies as vss1, vss2, ... under mount_point (libvshadow 2024
    naming; the returned `shadow_paths` list gives the exact paths). Each shadow
    copy is a raw NTFS volume image: run tsk.fls / tsk.icat directly on it, or
    mount it read-only with mount_ntfs().

    offset: byte offset of the NTFS VOLUME inside a whole-disk image
            (partition start sector x sector size — the same offset used
            to mount the volume itself, e.g. 105906176 for a 2048-sector
            start at 512 B/sector). REQUIRED for a full-disk E01/raw
            image: without it vshadowmount is pointed at the MBR, finds no
            VSS store, and exposes an EMPTY directory that looks mounted.
            Leave 0 for a bare volume image or a partition device.
    allow_other: pass -X allow_other so the unprivileged MCP process (and
            tsk.fls / fsstat run without sudo) can read the FUSE mount.
            Without it every follow-up call gets "Permission denied".

    The store is probed with vshadowinfo first; if none is found at this
    offset the call FAILS (with an offset hint) instead of leaving a silent
    empty mount behind.
    """
    os.makedirs(mount_point, exist_ok=True)
    offset_args = ["-o", str(int(offset))] if offset else []

    info = run(["vshadowinfo", *offset_args, image_or_device], needs_sudo=True)
    info_text = f"{info.get('stdout') or ''}\n{info.get('stderr') or ''}"
    if _NO_VSS_MARKER in info_text:
        return {
            **info,
            "success": False,
            "store_count": 0,
            "offset": int(offset),
            "error": (
                f"{_NO_VSS_MARKER} at offset {int(offset)}. For a whole-disk image pass "
                "offset=<NTFS partition start in BYTES> (tsk.mmls start sector x 512); "
                "the mount was NOT performed."
            ),
        }
    store_count = sum(1 for ln in str(info.get("stdout") or "").splitlines()
                      if ln.strip().startswith("Store:"))

    fuse_args = ["-X", "allow_other"] if allow_other else []
    result = run(["vshadowmount", *offset_args, *fuse_args, image_or_device, mount_point],
                 needs_sudo=True)
    result["mount_point"] = mount_point
    result["offset"] = int(offset)
    result["allow_other"] = bool(allow_other)
    result["store_count"] = store_count
    if result.get("success"):
        result["shadow_paths"] = [f"{mount_point}/vss{i}" for i in range(1, store_count + 1)]
    return result


@mcp.tool()
@output_safe
def vshadow_list(mount_point: str) -> dict:
    """
    List mounted Volume Shadow Copies after vshadow_mount.
    Shows available vss1, vss2, etc. entries (each a raw NTFS volume image).
    """
    return run(["ls", "-la", mount_point])


@mcp.tool()
@output_safe
def vshadow_umount(mount_point: str) -> dict:
    """Unmount a vshadowmount mount point."""
    return run(["umount", mount_point], needs_sudo=True)


# ── BitLocker ──────────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def bde_mount(
    image_path: str,
    mount_point: str,
    recovery_password: Optional[str] = None,
    recovery_key_file: Optional[str] = None,
) -> dict:
    """
    Mount a BitLocker-encrypted image or partition using bdemount.
    Provide either recovery_password (48-digit key) or recovery_key_file path.
    After mounting, run mount_ntfs() on mount_point/bde1 with offset=0.
    """
    os.makedirs(mount_point, exist_ok=True)
    cmd = ["bdemount"]
    if recovery_password:
        cmd += ["-r", recovery_password]
    elif recovery_key_file:
        cmd += ["-k", recovery_key_file]
    cmd += [image_path, mount_point]
    return run(cmd, needs_sudo=True)


@mcp.tool()
@output_safe
def bde_info(image_path: str) -> dict:
    """Display BitLocker encryption information from an image."""
    return run(["bdeinfo", image_path])


# ── xmount (multi-format image mounting) ──────────────────────────────────────

@mcp.tool()
@output_safe
def xmount_image(
    input_image: str,
    mount_point: str,
    input_format: str = "ewf",
    output_format: str = "raw",
) -> dict:
    """
    Mount a disk image in any format as a raw device using xmount.
    input_format: 'ewf' (E01), 'aff', 'vmdk', 'vhd', 'vdi', 'raw', 'dmg'.
    output_format: 'raw' (default) — exposes as /mount_point/<image>.dd.
    Useful when a tool doesn't support E01 natively (pass the raw file instead).
    """
    os.makedirs(mount_point, exist_ok=True)
    cmd = [
        "xmount",
        "--in", input_format, input_image,
        "--out", output_format,
        mount_point,
    ]
    return run(cmd, needs_sudo=True)


@mcp.tool()
@output_safe
def xmount_umount(mount_point: str) -> dict:
    """Unmount an xmount mount point."""
    return run(["fusermount", "-u", mount_point])


# ── PhotoRec (non-interactive carving) ────────────────────────────────────────

@mcp.tool()
@output_safe
def photorec_carve(
    image_path: str,
    output_dir: str,
    file_types: Optional[str] = None,
    partition: Optional[int] = None,
) -> dict:
    """
    Carve files from a disk image by file signature using PhotoRec (non-interactive mode).
    output_dir: destination directory for recovered files.
    file_types: comma-separated type extensions to recover e.g. 'jpg,pdf,doc,zip'.
    partition: partition number to scan (0 = whole disk, default).

    Note: PhotoRec creates numbered subdirectories (recup_dir.1, recup_dir.2, ...) inside output_dir.
    For large images this can take hours and recover thousands of files.
    """
    os.makedirs(output_dir, exist_ok=True)

    # Build photorec command-line (non-interactive via /cmd option)
    cmd = ["photorec", "/d", output_dir, "/cmd", image_path]

    if partition is not None:
        cmd += [f"partition_p{partition}"]

    if file_types:
        # Disable all then enable specific types
        types_str = ",".join(file_types.split(","))
        cmd += [f"fileopt,disable_all,enable,{types_str}"]

    cmd.append("search")

    return run(cmd, needs_sudo=True, timeout=14400, output_dir=output_dir)


# ── Partition tools ─────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def partprobe_refresh(device: str) -> dict:
    """Inform the OS of partition table changes on a device."""
    return run(["partprobe", device], needs_sudo=True)


@mcp.tool()
@output_safe
def losetup_create(image_path: str, offset_bytes: Optional[int] = None) -> dict:
    """
    Create a loop device from a disk image (alternative to mount -o loop).
    Returns the loop device path (e.g. /dev/loop0).
    """
    cmd = ["losetup", "-f", "--show"]
    if offset_bytes:
        cmd += ["-o", str(offset_bytes)]
    cmd.append(image_path)
    return run(cmd, needs_sudo=True)


@mcp.tool()
@output_safe
def losetup_list() -> dict:
    """List all active loop devices."""
    return run(["losetup", "-l"])


@mcp.tool()
@output_safe
def losetup_detach(loop_device: str) -> dict:
    """Detach a loop device (e.g. /dev/loop0)."""
    return run(["losetup", "-d", loop_device], needs_sudo=True)
