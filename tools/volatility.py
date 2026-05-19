"""Volatility 3 plugin wrappers — Windows, Linux, and cross-platform."""
import os
import glob
from typing import Optional, Any
from fastmcp import FastMCP, Context
from core import run, run_with_progress, vol3_bin, vol3_symbols, DEFAULT_TIMEOUT, VOL_TIMEOUT

mcp = FastMCP("volatility")
VOL = vol3_bin()




def _vol(image: str, plugin: str, extra: list[str] | None = None,
         output_dir: str | None = None, timeout: int = VOL_TIMEOUT) -> dict:
    # -o OUTPUT_DIR is a global Volatility flag — must come before the plugin name.
    # Plugin-specific args (--pid, --dump, etc.) go in extra, after the plugin.
    out_flags = ["-o", output_dir] if output_dir else []
    cmd = [VOL, "-s", vol3_symbols()] + out_flags + ["-f", image, "-r", "json", plugin] + (extra or [])
    return run(cmd, timeout=timeout)


async def _vol_progress(image: str, plugin: str, ctx: Any,
                        output_dir: str | None = None, timeout: int = VOL_TIMEOUT) -> dict:
    """Async variant of _vol() with FastMCP Context progress reporting."""
    out_flags = ["-o", output_dir] if output_dir else []
    cmd = [VOL, "-s", vol3_symbols()] + out_flags + ["-f", image, "-r", "json", plugin]
    return await run_with_progress(cmd, ctx, timeout=timeout)


# ── Image info ──────────────────────────────────────────────────────────────

@mcp.tool()
def vol_info(image: str) -> dict:
    """Display OS version, architecture, and kernel build from a memory image."""
    return _vol(image, "windows.info")


@mcp.tool()
def vol_symbol_check(memory_image: str) -> dict:
    """
    Pre-flight check: verify the memory image exists and Volatility 3 symbol
    files are cached. Returns the resolved absolute path in the 'image' field
    so downstream plugins can use it directly without re-expanding ~.

    If symbols_ready is False, call vol_info once (requires internet) to
    trigger the download for this kernel build, then retry memory plugins.
    """
    expanded = os.path.expanduser(memory_image)
    if not os.path.exists(expanded):
        return {
            "success": False,
            "image": memory_image,
            "symbols_ready": False,
            "cached_symbol_count": 0,
            "cached_guids": [],
            "note": f"Image not found: {expanded} — check the path and try again.",
        }

    symbols_dir = vol3_symbols()
    cached = glob.glob(os.path.join(symbols_dir, "windows", "ntkrnlmp.pdb", "*.json.xz"))
    cached += glob.glob(os.path.join(symbols_dir, "windows", "ntoskrnl.pdb", "*.json.xz"))

    return {
        "success": True,
        "image": expanded,
        "symbols_ready": len(cached) > 0,
        "cached_symbol_count": len(cached),
        "cached_guids": [os.path.basename(p) for p in cached],
        "note": (
            "Symbol cache is populated — proceed with memory plugins."
            if cached else
            "Symbol cache is empty — call vol_info once to download symbols (requires internet)."
        ),
    }


# ── Process enumeration ─────────────────────────────────────────────────────

@mcp.tool()
async def vol_pslist(image: str, ctx: Context, pid: Optional[int] = None) -> dict:
    """List processes via EPROCESS linked list walk. Fast; misses hidden processes."""
    if pid:
        return _vol(image, "windows.pslist", ["--pid", str(pid)])
    return await _vol_progress(image, "windows.pslist", ctx, timeout=VOL_TIMEOUT)


@mcp.tool()
async def vol_psscan(image: str, ctx: Context) -> dict:
    """Scan for EPROCESS pool tags — finds hidden and exited processes. Preferred over pslist."""
    return await _vol_progress(image, "windows.psscan", ctx, timeout=VOL_TIMEOUT)


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
    return await _vol_progress(image, "windows.netstat", ctx, timeout=VOL_TIMEOUT)


@mcp.tool()
async def vol_netscan(image: str, ctx: Context) -> dict:
    """Pool-tag scan for network connections — finds historical/closed connections too."""
    return await _vol_progress(image, "windows.netscan", ctx, timeout=VOL_TIMEOUT)


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
        extra += ["--dump"]
    return _vol(image, "windows.malfind", extra, output_dir=output_dir if dump else None)


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
    return _vol(image, "windows.vadyarascan", extra, timeout=VOL_TIMEOUT)


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
    return await _vol_progress(image, "windows.filescan", ctx, timeout=VOL_TIMEOUT)


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
    extra = []
    if virt_addr:
        extra += ["--virtaddr", virt_addr]
    if pid:
        extra += ["--pid", str(pid)]
    return _vol(image, "windows.dumpfiles", extra, output_dir=output_dir)


@mcp.tool()
def vol_mftscan(image: str) -> dict:
    """Scan for MFT entries in memory — finds files not in the live filesystem."""
    return _vol(image, "windows.mftscan", timeout=VOL_TIMEOUT)


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
        extra += ["--dump"]
    return _vol(image, "windows.memmap", extra, output_dir=output_dir if dump else None)


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
    if output_dir:
        from core.paths import assert_output_safe
        assert_output_safe(output_dir)
    return _vol(image, "timeliner", output_dir=output_dir, timeout=VOL_TIMEOUT)


@mcp.tool()
def vol_yarascan(image: str, yara_rules: str, pid: Optional[int] = None) -> dict:
    """YARA scan across all process memory regions."""
    extra = ["--yara-rules", yara_rules]
    if pid:
        extra += ["--pid", str(pid)]
    return _vol(image, "windows.yarascan", extra, timeout=VOL_TIMEOUT)


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
