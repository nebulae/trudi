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
    "vol": "vol.vol_* (e.g. vol.vol_pslist, vol.vol_netscan)",
    "RECmd": "ez.ez_recmd_hive / ez.ez_recmd_batch",
    "MFTECmd": "ez.ez_mftecmd",
    "EvtxECmd": "ez.ez_evtxecmd",
    "PECmd": "ez.ez_pecmd",
    "JLECmd": "ez.ez_jlecmd",
    "LECmd": "ez.ez_lecmd",
    "SBECmd": "ez.ez_sbecmd",
    "AmcacheParser": "ez.ez_amcacheparser",
    "AppCompatCacheParser": "ez.ez_appcompatcacheparser",
    "WxTCmd": "ez.ez_wxtcmd",
    "SQLECmd": "ez.ez_sqlecmd",
    "RBCmd": "ez.ez_rbcmd",
    "RLA": "ez.ez_rla",
    "fls": "tsk.tsk_fls",
    "icat": "tsk.tsk_icat",
    "istat": "tsk.tsk_istat",
    "ils": "tsk.tsk_ils",
    "blkls": "tsk.tsk_blkls",
    "mactime": "tsk.tsk_mactime",
    "tsk_recover": "tsk.tsk_recover",
    "sigfind": "tsk.tsk_sigfind",
    "sorter": "tsk.tsk_sorter",
    "jls": "tsk.tsk_jls",
    "jcat": "tsk.tsk_jcat",
    "mmls": "tsk.tsk_mmls",
    "fsstat": "tsk.tsk_fsstat",
    "hexdump": "strings.hexdump",
    "xxd": "strings.xxd_dump",
    "exiftool": "strings.exiftool_metadata / strings.exiftool_batch",
    "ssdeep": "hash.ssdeep_hash / hash.ssdeep_compare",
    "hashdeep": "hash.hashdeep_compute / hash.hashdeep_audit",
    "md5deep": "hash.md5deep_scan",
    "log2timeline.py": "plaso.plaso_create_timeline / plaso.plaso_create_targeted",
    "psort.py": "plaso.plaso_export_csv / plaso.plaso_export_json / plaso.plaso_filter_incident_window",
    "pinfo.py": "plaso.plaso_info / plaso.plaso_list_parsers",
    "yara": "yara.yara_scan_file / yara.yara_scan_directory / yara.yara_scan_memory_image",
    "bulk_extractor": "carve.bulk_extractor_scan",
    "foremost": "carve.foremost_carve",
    "scalpel": "carve.scalpel_carve",
    "photorec": "img.photorec_carve",
    "ewfmount": "ewf.ewf_mount / ewf.mount_full_image",
    "ewfinfo": "ewf.ewf_info",
    "ewfverify": "ewf.ewf_verify",
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
