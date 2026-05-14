"""Volatility 3 plugin wrappers — Windows, Linux, and cross-platform."""
import os
import glob
import struct
from typing import Optional, Any
from fastmcp import FastMCP, Context
from core import run, run_with_progress, vol3_bin, vol3_symbols

mcp = FastMCP("volatility")
VOL = vol3_bin()


# ── Symbol GUID scanner ───────────────────────────────────────────────────────

def _format_guid(b: bytes) -> str:
    """Format 16 raw GUID bytes into Volatility's cache filename format.

    Volatility cache filenames use: Data1(4B LE) + Data2(2B LE) + Data3(2B LE)
    + Data4(8B as-is), all uppercase hex, no dashes.
    Example: 31C51B7D1C2545A88F69E13FC73E6894
    """
    d1, d2, d3 = struct.unpack_from("<IHH", b, 0)
    return f"{d1:08X}{d2:04X}{d3:04X}{b[8:16].hex().upper()}"


def _scan_image_for_kernel_guid(image_path: str) -> list[dict]:
    """Scan a memory image for kernel PDB GUIDs without invoking Volatility.

    Searches for RSDS CodeView debug entries by locating the kernel PDB
    filename strings (ntkrnlmp.pdb, ntoskrnl.pdb) and reading the 24 bytes
    that precede them (RSDS signature + 16-byte GUID + 4-byte age).

    Scans from the END of the file — the Windows kernel is loaded at high
    physical addresses so it appears near the end of a sequential memory dump.
    Stops as soon as the first kernel GUID is found. Deduplicates by GUID+age.
    """
    TARGETS = [b"ntkrnlmp.pdb", b"ntoskrnl.pdb", b"ntkrpamp.pdb"]
    CHUNK = 2 * 1024 * 1024
    OVERLAP = 64

    results: list[dict] = []
    seen: set[str] = set()

    try:
        file_size = os.path.getsize(image_path)
        with open(image_path, "rb") as f:
            pos = file_size
            tail = b""
            while pos > 0:
                read_start = max(0, pos - CHUNK)
                f.seek(read_start)
                chunk = f.read(pos - read_start)
                if not chunk:
                    break
                # tail holds the start of the previous chunk (for cross-boundary matches)
                data = chunk + tail
                for target in TARGETS:
                    start = 0
                    while True:
                        idx = data.find(target, start)
                        if idx < 0:
                            break
                        if idx >= 24 and data[idx - 24: idx - 20] == b"RSDS":
                            guid_bytes = data[idx - 20: idx - 4]
                            age = struct.unpack_from("<I", data, idx - 4)[0]
                            guid_str = _format_guid(guid_bytes)
                            key = f"{guid_str}-{age}"
                            if key not in seen:
                                seen.add(key)
                                results.append({
                                    "pdb_name": target.decode(),
                                    "guid": guid_str,
                                    "age": age,
                                    "vol_filename": f"{guid_str}-{age}.json.xz",
                                })
                        start = idx + 1
                if results:
                    break  # found the kernel — stop scanning
                tail = data[:OVERLAP]
                pos = read_start
    except OSError as e:
        return [{"error": str(e)}]

    return results


def _vol(image: str, plugin: str, extra: list[str] | None = None, timeout: int = 300) -> dict:
    # plugin comes BEFORE extra so plugin-specific args (--pid, --dump, etc.)
    # are passed to the plugin, not interpreted as global vol args
    cmd = [VOL, "-s", vol3_symbols(), "-f", image, "-r", "json", plugin] + (extra or [])
    return run(cmd, timeout=timeout)


async def _vol_progress(image: str, plugin: str, ctx: Any, timeout: int = 600) -> dict:
    """Async variant of _vol() with FastMCP Context progress reporting."""
    cmd = [VOL, "-s", vol3_symbols(), "-f", image, "-r", "json", plugin]
    return await run_with_progress(cmd, ctx, timeout=timeout)


# ── Image info ──────────────────────────────────────────────────────────────

@mcp.tool()
def vol_info(image: str) -> dict:
    """Display OS version, architecture, and kernel build from a memory image."""
    return _vol(image, "windows.info")


@mcp.tool()
def vol_symbol_check(image: str) -> dict:
    """
    Pre-flight check: scan the memory image for kernel PDB GUIDs and verify
    whether the exact matching symbol files are in Volatility 3's cache.

    Scans the image in 2 MB chunks searching for RSDS CodeView debug entries
    near ntkrnlmp.pdb / ntoskrnl.pdb strings — no Volatility subprocess.
    Returns the kernel GUID(s) found in the image and whether each is cached.

    If symbols_ready is False, call vol_info once (requires internet) to
    trigger the download for this specific build, then retry memory plugins.
    """
    symbols_dir = vol3_symbols()

    # Scan the image for kernel PDB GUIDs
    guids_found = _scan_image_for_kernel_guid(image)

    # Check whether each found GUID exists in the cache
    for entry in guids_found:
        if "error" in entry:
            continue
        cache_path = os.path.join(
            symbols_dir, "windows", entry["pdb_name"], entry["vol_filename"]
        )
        entry["cached"] = os.path.exists(cache_path)

    # Also list everything already in cache for reference
    all_cached = glob.glob(os.path.join(symbols_dir, "windows", "ntkrnlmp.pdb", "*.json.xz"))
    all_cached += glob.glob(os.path.join(symbols_dir, "windows", "ntoskrnl.pdb", "*.json.xz"))

    symbols_ready = any(e.get("cached") for e in guids_found)

    return {
        "success": True,
        "image": image,
        "symbols_dir": symbols_dir,
        "kernel_guids_in_image": guids_found,
        "symbols_ready": symbols_ready,
        "all_cached_guids": [os.path.basename(p) for p in all_cached],
        "note": (
            "symbols_ready=True means the exact symbol file for this kernel build "
            "is cached. If False, call vol_info once to download it (requires internet)."
            if guids_found and "error" not in guids_found[0]
            else "No kernel PDB found in image — image may be unreadable or non-Windows."
        ),
    }


# ── Process enumeration ─────────────────────────────────────────────────────

@mcp.tool()
async def vol_pslist(image: str, ctx: Context, pid: Optional[int] = None) -> dict:
    """List processes via EPROCESS linked list walk. Fast; misses hidden processes."""
    if pid:
        return _vol(image, "windows.pslist", ["--pid", str(pid)])
    return await _vol_progress(image, "windows.pslist", ctx, timeout=600)


@mcp.tool()
async def vol_psscan(image: str, ctx: Context) -> dict:
    """Scan for EPROCESS pool tags — finds hidden and exited processes. Preferred over pslist."""
    return await _vol_progress(image, "windows.psscan", ctx, timeout=600)


@mcp.tool()
def vol_pstree(image: str, pid: Optional[int] = None) -> dict:
    """Display process hierarchy with parent-child relationships."""
    extra = ["--pid", str(pid)] if pid else []
    return _vol(image, "windows.pstree", extra)


@mcp.tool()
def vol_psxview(image: str) -> dict:
    """Cross-reference process lists (pslist, psscan, sessions, etc.) to find hidden processes."""
    return _vol(image, "windows.psxview")


# ── Process details ──────────────────────────────────────────────────────────

@mcp.tool()
def vol_cmdline(image: str, pid: Optional[int] = None) -> dict:
    """Extract command-line arguments for all or a specific process."""
    extra = ["--pid", str(pid)] if pid else []
    return _vol(image, "windows.cmdline", extra)


@mcp.tool()
def vol_envars(image: str, pid: Optional[int] = None) -> dict:
    """Extract environment variables per process (reveals working dir, injected vars)."""
    extra = ["--pid", str(pid)] if pid else []
    return _vol(image, "windows.envars", extra)


@mcp.tool()
def vol_getsids(image: str, pid: Optional[int] = None) -> dict:
    """Extract security identifiers (SIDs) associated with processes."""
    extra = ["--pid", str(pid)] if pid else []
    return _vol(image, "windows.getsids", extra)


@mcp.tool()
def vol_privileges(image: str, pid: Optional[int] = None) -> dict:
    """List token privileges per process (look for SeDebugPrivilege, SeTcbPrivilege)."""
    extra = ["--pid", str(pid)] if pid else []
    return _vol(image, "windows.privileges", extra)


@mcp.tool()
def vol_dlllist(image: str, pid: Optional[int] = None) -> dict:
    """List loaded DLLs per process. Check for spoofed or injected DLLs."""
    extra = ["--pid", str(pid)] if pid else []
    return _vol(image, "windows.dlllist", extra)


@mcp.tool()
def vol_handles(image: str, pid: Optional[int] = None, object_type: Optional[str] = None) -> dict:
    """
    List open handles per process (files, registry keys, mutexes, events, threads).
    object_type: File, Key, Mutant, Thread, Process, Section, Event, etc.
    """
    extra = []
    if pid:
        extra += ["--pid", str(pid)]
    if object_type:
        extra += ["--object-type", object_type]
    return _vol(image, "windows.handles", extra)


@mcp.tool()
def vol_ldrmodules(image: str, pid: Optional[int] = None) -> dict:
    """Cross-reference loaded modules across PEB/VAD/LDR lists. Discrepancies = injection indicator."""
    extra = ["--pid", str(pid)] if pid else []
    return _vol(image, "windows.ldrmodules", extra)


@mcp.tool()
def vol_sessions(image: str) -> dict:
    """List active user sessions."""
    return _vol(image, "windows.sessions")


# ── Network ──────────────────────────────────────────────────────────────────

@mcp.tool()
async def vol_netstat(image: str, ctx: Context) -> dict:
    """Walk TCP/IP structures — active connections at capture time."""
    return await _vol_progress(image, "windows.netstat", ctx, timeout=600)


@mcp.tool()
async def vol_netscan(image: str, ctx: Context) -> dict:
    """Pool-tag scan for network connections — finds historical/closed connections too."""
    return await _vol_progress(image, "windows.netscan", ctx, timeout=600)


# ── Services ─────────────────────────────────────────────────────────────────

@mcp.tool()
def vol_svcscan(image: str) -> dict:
    """Enumerate services via pool scan — finds hidden and deleted services still in memory."""
    return _vol(image, "windows.svcscan")


@mcp.tool()
def vol_svclist(image: str) -> dict:
    """List services via SCM (Service Control Manager) structures."""
    return _vol(image, "windows.svclist")


@mcp.tool()
def vol_svcdiff(image: str) -> dict:
    """Diff services found via SCM vs pool scan to detect hidden services."""
    return _vol(image, "windows.svcdiff")


# ── Registry ──────────────────────────────────────────────────────────────────

@mcp.tool()
def vol_registry_hivelist(image: str) -> dict:
    """List all loaded registry hives and their virtual addresses."""
    return _vol(image, "windows.registry.hivelist")


@mcp.tool()
def vol_registry_hivescan(image: str) -> dict:
    """Pool-tag scan for registry hives — finds unloaded/hidden hives."""
    return _vol(image, "windows.registry.hivescan")


@mcp.tool()
def vol_registry_printkey(image: str, key: str, hive_offset: Optional[str] = None) -> dict:
    """
    Print a registry key and its values from memory.
    key: e.g. 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
    """
    extra = ["--key", key]
    if hive_offset:
        extra += ["--offset", hive_offset]
    return _vol(image, "windows.registry.printkey", extra)


@mcp.tool()
def vol_userassist(image: str) -> dict:
    """Extract UserAssist registry entries — GUI execution evidence (programs run via Explorer)."""
    return _vol(image, "windows.registry.userassist")


@mcp.tool()
def vol_registry_amcache(image: str) -> dict:
    """Extract Amcache entries from memory (program execution evidence)."""
    return _vol(image, "windows.registry.amcache")


@mcp.tool()
def vol_scheduled_tasks(image: str) -> dict:
    """Extract scheduled tasks from registry in memory."""
    return _vol(image, "windows.registry.scheduled_tasks")


# ── Injection & anomalous memory ─────────────────────────────────────────────

@mcp.tool()
def vol_malfind(image: str, pid: Optional[int] = None, dump: bool = False, output_dir: Optional[str] = None) -> dict:
    """
    Find RWX memory regions with PE headers or shellcode — primary injection scanner.
    Set dump=True with output_dir to extract suspicious regions to disk.
    """
    extra = []
    if pid:
        extra += ["--pid", str(pid)]
    if dump and output_dir:
        from core.paths import assert_output_safe
        assert_output_safe(output_dir)
        extra += ["--dump", "--output-dir", output_dir]
    return _vol(image, "windows.malfind", extra)


@mcp.tool()
def vol_vadinfo(image: str, pid: Optional[int] = None) -> dict:
    """Inspect Virtual Address Descriptor tree for a process — all memory regions."""
    extra = ["--pid", str(pid)] if pid else []
    return _vol(image, "windows.vadinfo", extra)


@mcp.tool()
def vol_vadwalk(image: str, pid: Optional[int] = None) -> dict:
    """Walk the VAD tree structure for a process."""
    extra = ["--pid", str(pid)] if pid else []
    return _vol(image, "windows.vadwalk", extra)


@mcp.tool()
def vol_hollowprocesses(image: str) -> dict:
    """Detect process hollowing by comparing VAD entries against PEB module list."""
    return _vol(image, "windows.hollowprocesses")


@mcp.tool()
def vol_pebmasquerade(image: str) -> dict:
    """Detect PEB masquerading — process pretending to be a different executable."""
    return _vol(image, "windows.malware.pebmasquerade")


@mcp.tool()
def vol_suspicious_threads(image: str) -> dict:
    """Find threads with suspicious start addresses (e.g. starting in non-image memory)."""
    return _vol(image, "windows.suspicious_threads")


@mcp.tool()
def vol_vadyarascan(image: str, yara_rules: str, pid: Optional[int] = None) -> dict:
    """
    YARA scan of process VAD regions directly from memory.
    yara_rules: path to a .yar file or inline rule string.
    """
    extra = ["--yara-rules", yara_rules]
    if pid:
        extra += ["--pid", str(pid)]
    return _vol(image, "windows.vadyarascan", extra, timeout=600)


@mcp.tool()
def vol_cmdscanner(image: str) -> dict:
    """Scan for COMMAND_HISTORY and CONSOLE_INFORMATION structures — console input history."""
    return _vol(image, "windows.cmdscan")


@mcp.tool()
def vol_consoles(image: str) -> dict:
    """Extract console I/O buffers — what was typed and displayed in cmd.exe windows."""
    return _vol(image, "windows.consoles")


# ── Kernel modules & drivers ──────────────────────────────────────────────────

@mcp.tool()
def vol_modules(image: str) -> dict:
    """List loaded kernel modules via linked list walk."""
    return _vol(image, "windows.modules")


@mcp.tool()
def vol_modscan(image: str) -> dict:
    """Pool-tag scan for kernel modules — finds hidden/unlinked drivers."""
    return _vol(image, "windows.modscan")


@mcp.tool()
def vol_driverscan(image: str) -> dict:
    """Scan for DRIVER_OBJECT structures in pool memory."""
    return _vol(image, "windows.driverscan")


@mcp.tool()
def vol_driverirp(image: str) -> dict:
    """List IRP handlers for all drivers — used to find hooked dispatch routines."""
    return _vol(image, "windows.driverirp")


@mcp.tool()
def vol_devicetree(image: str) -> dict:
    """Display driver/device object tree — shows device stacking for rootkit detection."""
    return _vol(image, "windows.devicetree")


@mcp.tool()
def vol_callbacks(image: str) -> dict:
    """List kernel notification callbacks (PsSetCreateProcessNotifyRoutine, etc.)."""
    return _vol(image, "windows.callbacks")


@mcp.tool()
def vol_ssdt(image: str) -> dict:
    """Display the System Service Descriptor Table — detect SSDT hooks."""
    return _vol(image, "windows.ssdt")


@mcp.tool()
def vol_unhooked_system_calls(image: str) -> dict:
    """Compare SSDT entries to expected values to find unhooked system calls."""
    return _vol(image, "windows.unhooked_system_calls")


# ── File system artifacts ────────────────────────────────────────────────────

@mcp.tool()
async def vol_filescan(image: str, ctx: Context) -> dict:
    """Scan for FILE_OBJECT structures — lists all files cached in memory."""
    return await _vol_progress(image, "windows.filescan", ctx, timeout=600)


@mcp.tool()
def vol_dumpfiles(
    image: str,
    virt_addr: Optional[str] = None,
    pid: Optional[int] = None,
    output_dir: Optional[str] = None,
) -> dict:
    """
    Dump files from memory by virtual address (from filescan output) or PID.
    Requires output_dir.
    """
    if not output_dir:
        return {"success": False, "stderr": "output_dir is required for dumpfiles"}
    from core.paths import assert_output_safe
    assert_output_safe(output_dir)
    extra = ["--output-dir", output_dir]
    if virt_addr:
        extra += ["--virtaddr", virt_addr]
    if pid:
        extra += ["--pid", str(pid)]
    return _vol(image, "windows.dumpfiles", extra)


@mcp.tool()
def vol_mftscan(image: str) -> dict:
    """Scan for MFT entries in memory — finds files not in the live filesystem."""
    return _vol(image, "windows.mftscan", timeout=600)


@mcp.tool()
def vol_memmap(image: str, pid: int, dump: bool = False, output_dir: Optional[str] = None) -> dict:
    """
    Show or dump memory map for a process.
    Set dump=True with output_dir to write process memory to disk.
    """
    extra = ["--pid", str(pid)]
    if dump and output_dir:
        from core.paths import assert_output_safe
        assert_output_safe(output_dir)
        extra += ["--dump", "--output-dir", output_dir]
    return _vol(image, "windows.memmap", extra)


# ── Execution artifacts ───────────────────────────────────────────────────────

@mcp.tool()
def vol_amcache(image: str) -> dict:
    """Extract Amcache.hve entries from a running system — program execution evidence."""
    return _vol(image, "windows.amcache")


@mcp.tool()
def vol_shimcachemem(image: str) -> dict:
    """Extract AppCompatCache (ShimCache) from memory — execution evidence with timestamps."""
    return _vol(image, "windows.shimcachemem")


# ── Credentials ────────────────────────────────────────────────────────────────

@mcp.tool()
def vol_hashdump(image: str) -> dict:
    """Dump NTLM password hashes from SAM and SYSTEM hives in memory."""
    return _vol(image, "windows.hashdump")


@mcp.tool()
def vol_cachedump(image: str) -> dict:
    """Extract cached domain credentials (DCC2 hashes) from memory."""
    return _vol(image, "windows.cachedump")


@mcp.tool()
def vol_lsadump(image: str) -> dict:
    """Dump LSA secrets from memory (service account passwords, auto-logon creds)."""
    return _vol(image, "windows.lsadump")


# ── Misc Windows ──────────────────────────────────────────────────────────────

@mcp.tool()
def vol_mutantscan(image: str) -> dict:
    """Scan for mutex objects — malware often uses mutexes to prevent reinfection."""
    return _vol(image, "windows.mutantscan")


@mcp.tool()
def vol_symlinkscan(image: str) -> dict:
    """Scan for symbolic link objects in kernel pool memory."""
    return _vol(image, "windows.symlinkscan")


@mcp.tool()
def vol_thrdscan(image: str) -> dict:
    """Scan for ETHREAD objects — thread-level investigation."""
    return _vol(image, "windows.thrdscan")


@mcp.tool()
def vol_timeliner(image: str, output_dir: Optional[str] = None) -> dict:
    """
    Generate a unified timeline of all memory artifacts.
    Produces a bodyfile suitable for mactime.
    """
    extra = []
    if output_dir:
        from core.paths import assert_output_safe
        assert_output_safe(output_dir)
        extra += ["--output-dir", output_dir]
    return _vol(image, "timeliner", extra, timeout=600)


@mcp.tool()
def vol_yarascan(image: str, yara_rules: str, pid: Optional[int] = None) -> dict:
    """YARA scan across all process memory regions."""
    extra = ["--yara-rules", yara_rules]
    if pid:
        extra += ["--pid", str(pid)]
    return _vol(image, "windows.yarascan", extra, timeout=600)


# ── Linux plugins ─────────────────────────────────────────────────────────────

@mcp.tool()
def vol_linux_pslist(image: str) -> dict:
    """List Linux processes."""
    return _vol(image, "linux.pslist")


@mcp.tool()
def vol_linux_psscan(image: str) -> dict:
    """Scan for Linux TASK_STRUCT objects."""
    return _vol(image, "linux.psscan")


@mcp.tool()
def vol_linux_pstree(image: str) -> dict:
    """Linux process hierarchy."""
    return _vol(image, "linux.pstree")


@mcp.tool()
def vol_linux_netstat(image: str) -> dict:
    """Linux network connections from memory."""
    return _vol(image, "linux.ip")


@mcp.tool()
def vol_linux_lsof(image: str, pid: Optional[int] = None) -> dict:
    """List open files per Linux process."""
    extra = ["--pid", str(pid)] if pid else []
    return _vol(image, "linux.lsof", extra)


@mcp.tool()
def vol_linux_malfind(image: str) -> dict:
    """Find suspicious memory regions in Linux processes."""
    return _vol(image, "linux.malfind")


@mcp.tool()
def vol_linux_lsmod(image: str) -> dict:
    """List loaded Linux kernel modules."""
    return _vol(image, "linux.lsmod")


@mcp.tool()
def vol_linux_check_modules(image: str) -> dict:
    """Detect hidden kernel modules on Linux — compares sysfs vs module list."""
    return _vol(image, "linux.check_modules")
