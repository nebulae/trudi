"""The Sleuth Kit — filesystem navigation and timeline tools."""
from typing import Optional
from fastmcp import FastMCP
from core import run, DEFAULT_TIMEOUT, VOL_TIMEOUT, PLASO_TIMEOUT

mcp = FastMCP("sleuthkit")


@mcp.tool()
def tsk_mmls(image: str) -> dict:
    """Display partition table (MBR and GPT) — get sector offsets for mounting."""
    return run(["mmls", image], needs_sudo=True)


@mcp.tool()
def tsk_fsstat(image: str, offset_sectors: Optional[int] = None) -> dict:
    """
    Filesystem metadata: NTFS version, cluster size, MFT offset, volume ID.
    offset_sectors: sector offset from mmls output (required for partitioned images).
    """
    cmd = ["fsstat"]
    if offset_sectors:
        cmd += ["-o", str(offset_sectors)]
    cmd.append(image)
    return run(cmd, needs_sudo=True)


@mcp.tool()
def tsk_fls(
    image: str,
    offset_sectors: Optional[int] = None,
    inode: Optional[int] = None,
    recursive: bool = True,
    deleted_only: bool = False,
    bodyfile: bool = False,
) -> dict:
    """
    List files and directories in a disk image, including deleted entries (marked *).
    offset_sectors: from mmls output.
    inode: list a specific directory by inode number.
    recursive: recurse into subdirectories.
    bodyfile: output in mactime bodyfile format for timeline creation.
    deleted_only: show only deleted entries.
    """
    cmd = ["fls"]
    if recursive:
        cmd.append("-r")
    if bodyfile:
        cmd += ["-m", "/"]
    if deleted_only:
        cmd.append("-d")
    if offset_sectors:
        cmd += ["-o", str(offset_sectors)]
    cmd.append(image)
    if inode is not None:
        cmd.append(str(inode))
    return run(cmd, needs_sudo=True, timeout=VOL_TIMEOUT)


@mcp.tool()
def tsk_istat(image: str, inode: int, offset_sectors: Optional[int] = None) -> dict:
    """
    Display inode metadata: MAC times, size, allocated blocks, file type.
    offset_sectors: from mmls output.
    """
    cmd = ["istat"]
    if offset_sectors:
        cmd += ["-o", str(offset_sectors)]
    cmd += [image, str(inode)]
    return run(cmd, needs_sudo=True)


@mcp.tool()
def tsk_icat(
    image: str,
    inode: str,
    output_path: str,
    offset_sectors: Optional[int] = None,
    recover_deleted: bool = False,
    slack_space: bool = False,
) -> dict:
    """
    Extract file content by inode number to output_path.
    inode: can be a number or 'number-stream-id' for ADS (e.g. '11-128-4').
    recover_deleted: attempt recovery of deleted file data.
    slack_space: extract file slack space.
    """
    from core.paths import assert_output_safe
    assert_output_safe(output_path)
    cmd = ["icat"]
    if recover_deleted:
        cmd.append("-r")
    if slack_space:
        cmd.append("-s")
    if offset_sectors:
        cmd += ["-o", str(offset_sectors)]
    cmd += [image, str(inode)]
    # icat outputs to stdout — redirect via shell
    result = run(cmd + [">", output_path], needs_sudo=True)
    # fallback: run with proper redirection
    import subprocess
    full_cmd = ["sudo", "icat"]
    if recover_deleted:
        full_cmd.append("-r")
    if slack_space:
        full_cmd.append("-s")
    if offset_sectors:
        full_cmd += ["-o", str(offset_sectors)]
    full_cmd += [image, str(inode)]
    try:
        with open(output_path, "wb") as f:
            proc = subprocess.run(full_cmd, stdout=f, stderr=subprocess.PIPE, timeout=120)
        return {
            "success": proc.returncode == 0,
            "stdout": f"Extracted to {output_path}",
            "stderr": proc.stderr.decode("utf-8", errors="replace")[:4096],
            "exit_code": proc.returncode,
            "truncated": False,
            "cmd": " ".join(full_cmd),
        }
    except Exception as e:
        return {"success": False, "stdout": "", "stderr": str(e), "exit_code": -1, "truncated": False, "cmd": ""}


@mcp.tool()
def tsk_ils(
    image: str,
    offset_sectors: Optional[int] = None,
    orphan_only: bool = False,
    unallocated_only: bool = False,
    allocated_only: bool = False,
) -> dict:
    """
    List inodes in a filesystem.
    orphan_only: unlinked inodes (deleted files with no directory entry).
    unallocated_only: only unallocated inodes.
    allocated_only: only allocated inodes.
    """
    cmd = ["ils"]
    if orphan_only:
        cmd.append("-p")
    elif unallocated_only:
        cmd.append("-A")
    elif allocated_only:
        cmd.append("-a")
    if offset_sectors:
        cmd += ["-o", str(offset_sectors)]
    cmd.append(image)
    return run(cmd, needs_sudo=True, timeout=DEFAULT_TIMEOUT)


@mcp.tool()
def tsk_ffind(image: str, inode: int, offset_sectors: Optional[int] = None) -> dict:
    """Find the filename(s) for a given inode number."""
    cmd = ["ffind"]
    if offset_sectors:
        cmd += ["-o", str(offset_sectors)]
    cmd += [image, str(inode)]
    return run(cmd, needs_sudo=True)


@mcp.tool()
def tsk_blkls(
    image: str,
    output_path: str,
    offset_sectors: Optional[int] = None,
    unallocated_only: bool = True,
) -> dict:
    """
    Extract raw disk blocks for carving.
    unallocated_only: extract only unallocated blocks (default — for carving).
    output_path: destination file for raw block data.
    """
    from core.paths import assert_output_safe
    assert_output_safe(output_path)
    import subprocess
    cmd = ["sudo", "blkls"]
    if unallocated_only:
        cmd.append("-A")
    if offset_sectors:
        cmd += ["-o", str(offset_sectors)]
    cmd.append(image)
    try:
        with open(output_path, "wb") as f:
            proc = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, timeout=VOL_TIMEOUT)
        return {
            "success": proc.returncode == 0,
            "stdout": f"Blocks written to {output_path}",
            "stderr": proc.stderr.decode("utf-8", errors="replace")[:4096],
            "exit_code": proc.returncode,
            "truncated": False,
            "cmd": " ".join(cmd),
        }
    except Exception as e:
        return {"success": False, "stdout": "", "stderr": str(e), "exit_code": -1, "truncated": False, "cmd": ""}


@mcp.tool()
def tsk_recover(
    image: str,
    output_dir: str,
    offset_sectors: Optional[int] = None,
    include_unallocated: bool = False,
) -> dict:
    """
    Bulk extract files from a disk image.
    include_unallocated: also recover deleted/unallocated files.
    """
    from core.paths import assert_output_safe
    assert_output_safe(output_dir)
    cmd = ["tsk_recover"]
    if include_unallocated:
        cmd.append("-e")
    else:
        cmd.append("-a")
    if offset_sectors:
        cmd += ["-o", str(offset_sectors)]
    cmd += [image, output_dir]
    return run(cmd, needs_sudo=True, timeout=VOL_TIMEOUT*3, output_dir=output_dir)


@mcp.tool()
def tsk_mactime(
    bodyfile: str,
    output_path: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    csv_output: bool = True,
) -> dict:
    """
    Generate a MAC timeline from a bodyfile (output of fls -m).
    start_date / end_date: filter to a date range, format YYYY-MM-DD.
    csv_output: produce comma-separated output (easier for analysis).
    """
    cmd = ["mactime", "-b", bodyfile, "-z", "UTC"]
    if csv_output:
        cmd.append("-d")
    if start_date:
        cmd.append(start_date)
    if end_date:
        cmd.append(end_date)
    if output_path:
        from core.paths import assert_output_safe
        assert_output_safe(output_path)
        import subprocess
        try:
            with open(output_path, "w") as f:
                proc = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, timeout=VOL_TIMEOUT)
            return {
                "success": proc.returncode == 0,
                "stdout": f"Timeline written to {output_path}",
                "stderr": proc.stderr.decode("utf-8", errors="replace")[:4096],
                "exit_code": proc.returncode,
                "truncated": False,
                "cmd": " ".join(cmd),
            }
        except Exception as e:
            return {"success": False, "stdout": "", "stderr": str(e), "exit_code": -1, "truncated": False, "cmd": ""}
    return run(cmd, timeout=VOL_TIMEOUT)


@mcp.tool()
def tsk_blkcat(image: str, block_number: int, offset_sectors: Optional[int] = None) -> dict:
    """Extract raw content of a specific data block."""
    cmd = ["blkcat"]
    if offset_sectors:
        cmd += ["-o", str(offset_sectors)]
    cmd += [image, str(block_number)]
    return run(cmd, needs_sudo=True)


@mcp.tool()
def tsk_blkstat(image: str, block_number: int, offset_sectors: Optional[int] = None) -> dict:
    """Display statistics on a specific data block (allocation status, containing file)."""
    cmd = ["blkstat"]
    if offset_sectors:
        cmd += ["-o", str(offset_sectors)]
    cmd += [image, str(block_number)]
    return run(cmd, needs_sudo=True)


@mcp.tool()
def tsk_blkcalc(image: str, block_number: int, offset_sectors: Optional[int] = None) -> dict:
    """Convert between disk and image block addresses."""
    cmd = ["blkcalc"]
    if offset_sectors:
        cmd += ["-o", str(offset_sectors)]
    cmd += [image, str(block_number)]
    return run(cmd, needs_sudo=True)


@mcp.tool()
def tsk_mmcat(image: str, partition_slot: int) -> dict:
    """Output the contents of a partition slot (raw partition data)."""
    return run(["mmcat", image, str(partition_slot)], needs_sudo=True)


@mcp.tool()
def tsk_mmstat(image: str) -> dict:
    """Display statistics about the volume system (disk layout metadata)."""
    return run(["mmstat", image], needs_sudo=True)


@mcp.tool()
def tsk_hfind(
    hash_db: str,
    hash_value: str,
    lookup_type: str = "md5",
) -> dict:
    """
    Look up a file hash in a hash database (NSRL, hashkeeper, md5sum format).
    hash_db: path to the hash database file.
    hash_value: the hash to look up.
    lookup_type: 'md5', 'sha1', 'nsrl-md5', 'nsrl-sha1'.
    """
    return run(["hfind", "-f", lookup_type, hash_db, hash_value])


@mcp.tool()
def tsk_sigfind(image: str, signature_hex: str, offset_sectors: Optional[int] = None) -> dict:
    """
    Find a hex byte signature in a disk image.
    signature_hex: hex string to search for e.g. 'MZ' header = '4D5A'.
    Useful for locating hidden PE files or deleted MBR signatures.
    """
    cmd = ["sigfind"]
    if offset_sectors:
        cmd += ["-o", str(offset_sectors)]
    cmd += [image, signature_hex]
    return run(cmd, needs_sudo=True, timeout=VOL_TIMEOUT)


@mcp.tool()
def tsk_sorter(
    image: str,
    output_dir: str,
    offset_sectors: Optional[int] = None,
    category: Optional[str] = None,
) -> dict:
    """
    Sort files from a disk image into categories based on file type.
    output_dir: destination for sorted file categories.
    category: limit to a specific category e.g. 'images', 'exec', 'audio', 'documents'.
    """
    from core.paths import assert_output_safe
    assert_output_safe(output_dir)
    cmd = ["sorter", "-d", output_dir]
    if offset_sectors:
        cmd += ["-o", str(offset_sectors)]
    if category:
        cmd += ["-s", category]
    cmd.append(image)
    return run(cmd, needs_sudo=True, timeout=VOL_TIMEOUT, output_dir=output_dir)


@mcp.tool()
def tsk_jls(image: str, offset_sectors: Optional[int] = None) -> dict:
    """
    List journal entries from an ext3/ext4 filesystem.
    Useful for recovering deleted files on Linux disk images.
    """
    cmd = ["jls"]
    if offset_sectors:
        cmd += ["-o", str(offset_sectors)]
    cmd.append(image)
    return run(cmd, needs_sudo=True, timeout=DEFAULT_TIMEOUT)


@mcp.tool()
def tsk_jcat(image: str, journal_inode: int, offset_sectors: Optional[int] = None) -> dict:
    """
    Output the contents of an ext3/ext4 journal entry by inode number.
    Use after tsk_jls to inspect a specific journal block.
    """
    cmd = ["jcat"]
    if offset_sectors:
        cmd += ["-o", str(offset_sectors)]
    cmd += [image, str(journal_inode)]
    return run(cmd, needs_sudo=True)
