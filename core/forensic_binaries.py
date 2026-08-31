"""Forensic-binary ban list + MCP wrapper hints. Stdlib-only ON PURPOSE:
the PreToolUse guard hook (claude/hooks/guard_pretooluse.py) imports this
under whatever python3 the harness uses — it must never drag in fastmcp.
core.middleware re-exports these names for existing importers."""
import re

FORENSIC_BINARY_PATTERNS = (
    r"/usr/local/bin/vol\b",
    r"(?<![\w-])vol\.py\b",
    r"\bdotnet\s+\S*(?:MFTECmd|RECmd|EvtxECmd|PECmd|JLECmd|LECmd|SBECmd|"
    r"AmcacheParser|AppCompatCacheParser|WxTCmd|SQLECmd|RBCmd|RLA)\.dll",
    r"(?<![\w-])(?:fls|icat|istat|ils|blkls|mactime|tsk_recover|sigfind|"
    r"sorter|jls|jcat|mmls|fsstat|mmcat|mmstat|blkcalc|blkcat|blkstat|"
    r"ffind|hfind)\b",
    r"(?<![\w-])(?:hexdump|xxd|exiftool|ssdeep|hashdeep|md5deep)\b",
    r"(?<![\w-])(?:log2timeline\.py|psort\.py|pinfo\.py)\b",
    r"(?<![\w-])(?:yara|yarac|bulk_extractor|foremost|scalpel|photorec)\b",
    r"(?<![\w-])(?:ewfmount|ewfinfo|ewfverify|vshadowmount|bdemount|xmount)\b",
    r"(?<![\w-])tcpdump\b",
    r"(?<![\w-])clamscan\b",
    r"(?<![\w-])rip\.pl\b",
)

MCP_WRAPPER_HINTS = {
    "vol": "vol.* (e.g. vol.pslist, vol.netscan)",
    "RECmd": "ez.recmd_hive / ez.recmd_batch",
    "MFTECmd": "ez.mftecmd",
    "EvtxECmd": "ez.evtxecmd",
    "PECmd": "ez.pecmd",
    "JLECmd": "ez.jlecmd",
    "LECmd": "ez.lecmd",
    "SBECmd": "ez.sbecmd",
    "AmcacheParser": "ez.amcacheparser",
    "AppCompatCacheParser": "ez.appcompatcacheparser",
    "WxTCmd": "ez.wxtcmd",
    "SQLECmd": "ez.sqlecmd",
    "RBCmd": "ez.rbcmd",
    "RLA": "ez.rla",
    "fls": "tsk.fls",
    "icat": "tsk.icat",
    "istat": "tsk.istat",
    "ils": "tsk.ils",
    "blkls": "tsk.blkls",
    "mactime": "tsk.mactime",
    "tsk_recover": "tsk.recover",
    "sigfind": "tsk.sigfind",
    "sorter": "tsk.sorter",
    "jls": "tsk.jls",
    "jcat": "tsk.jcat",
    "mmls": "tsk.mmls",
    "fsstat": "tsk.fsstat",
    "hexdump": "strings.hexdump",
    "xxd": "strings.xxd_dump",
    "exiftool": "strings.exiftool_metadata / strings.exiftool_batch",
    "ssdeep": "hash.ssdeep_hash / hash.ssdeep_compare",
    "hashdeep": "hash.hashdeep_compute / hash.hashdeep_audit",
    "md5deep": "hash.md5deep_scan",
    "log2timeline.py": "plaso.create_timeline / plaso.create_targeted",
    "psort.py": "plaso.export_csv / plaso.export_json / plaso.filter_incident_window",
    "pinfo.py": "plaso.info / plaso.list_parsers",
    "yara": "yara.scan_file / yara.scan_directory / yara.scan_memory_image",
    "bulk_extractor": "carve.bulk_extractor_scan",
    "foremost": "carve.foremost_carve",
    "scalpel": "carve.scalpel_carve",
    "photorec": "img.photorec_carve",
    "ewfmount": "ewf.mount / ewf.mount_full_image",
    "ewfinfo": "ewf.info",
    "ewfverify": "ewf.verify",
    "vshadowmount": "img.vshadow_mount",
    "bdemount": "img.bde_mount",
    "xmount": "img.xmount_image",
    "tcpdump": "net.tcpdump_read / net.tcpdump_extract_http / net.tcpdump_extract_dns",
    "clamscan": "misc.clamscan_file / misc.clamscan_directory",
    "rip.pl": "misc.regripper_hive",
}


def _identify_forensic_binary(cmd: str) -> "str | None":
    if not cmd:
        return None
    for pat in FORENSIC_BINARY_PATTERNS:
        if not re.search(pat, cmd):
            continue
        for key in MCP_WRAPPER_HINTS:
            if key in cmd:
                return key
        return ""
    return None
