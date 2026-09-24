"""Curated TRUDI tool capability manifest.

The manifest is intentionally small and semantic. It is not a full inventory of
every MCP wrapper; it is the planning vocabulary DAIR/reasoning should use when
choosing the next batch. Focused wrappers can still exist outside this list, but
priority_tools should come from these known, phase-appropriate capabilities.
"""
from __future__ import annotations

import copy
import re
import shutil


MANIFEST_VERSION = "2026-09-24.1"


_CAPABILITIES: list[dict] = [
    {
        "id": "reasoning_control",
        "phases": ["Triage", "Analyze", "Report"],
        "evidence": ["all"],
        "purpose": "Plan, hypothesize, challenge, and prepare report synthesis.",
        "tools": [
            "reason.plan",
            "reason.hypothesize",
            "reason.evaluate_finding",
            "reason.confidence_score",
            "reason.cite_check",
            "reason.synthesize",
            "reason.pre_report_check",
            "reason.readiness_status",
            "reason.audit_findings",
            "misc.submit_finding",
        ],
    },
    {
        "id": "produced_output_reads",
        "phases": ["Collect", "Analyze", "Scan", "Report"],
        "evidence": ["all"],
        "purpose": ("Traced, citable reads of PRODUCED output — CSV/JSON/TXT under "
                    "analysis|exports|reports (read.output: query/columns/where) "
                    "and extracted mbox/.eml mail stores (read.mail: message "
                    "BODIES, sender/recipient roster). Replaces bash "
                    "python/jq/cat/mailbox, whose reads are untraced and uncitable."),
        "tools": [
            "read.output",
            "read.mail",
        ],
    },
    {
        "id": "memory_process_network",
        "phases": ["Triage", "Analyze", "Scan"],
        "evidence": ["memory"],
        "purpose": "Enumerate processes, command lines, sessions, injected memory (and decode Cobalt Strike beacon configs from it), and network sockets from memory.",
        "tools": [
            "vol.psscan",
            "vol.pslist",
            "vol.pstree",
            "vol.cmdline",
            "vol.sessions",
            "vol.netscan",
            "vol.netstat",
            "vol.malfind",
            "misc.cs_beacon_config",
            "vol.filescan",
            "vol.dumpfiles",
            "vol.yarascan",
        ],
    },
    {
        "id": "disk_filesystem_timeline",
        "phases": ["Collect", "Analyze"],
        "evidence": ["disk", "mounted_fs"],
        "purpose": "Collect filesystem listings, file bodies, execution artifacts, and timeline data.",
        "tools": [
            "tsk.fls",
            "tsk.icat",
            "tsk.istat",
            "tsk.mactime",
            "ez.mftecmd",
            "ez.jlecmd",
            "ez.lecmd",
            "ez.pecmd",
            "misc.srum_export",
            "misc.usnparser_parse",
            "plaso.create_timeline",
            "plaso.export_csv",
        ],
    },
    {
        "id": "windows_registry_identity",
        "phases": ["Collect", "Analyze"],
        "evidence": ["disk", "memory"],
        "purpose": "Resolve registry persistence, account bindings, app execution, and identity clues.",
        "tools": [
            "ez.recmd_hive",
            "ez.recmd_dir",
            "ez.recmd_batch",
            "ez.amcacheparser",
            "ez.appcompatcacheparser",
            "ez.recentfilecache",
            "misc.regripper_hive",
            "vol.registry_hivelist",
            "vol.registry_printkey",
            "vol.userassist",
            "vol.getsids",
        ],
    },
    {
        "id": "windows_event_logs",
        "phases": ["Collect", "Analyze"],
        "evidence": ["disk", "live"],
        "purpose": "Parse Windows event logs for authentication, service, task, PowerShell, and timeline events.",
        "tools": [
            "ez.evtxecmd",
            "misc.evtx_filter",
            "misc.evtx_dump",
            "misc.chainsaw_hunt",
            "live.event_log_tail",
        ],
    },
    {
        "id": "comms_stores",
        "phases": ["Collect", "Analyze"],
        "evidence": ["disk", "mounted_fs"],
        "purpose": ("Extract and enumerate communications stores — mail OST/PST "
                    "(readpst/pff_export) and chat/messenger sqlite "
                    "(chat_db_export: messages, file-transfer trail, full "
                    "sender/recipient roster). Mandatory before any "
                    "recipient/dissemination conclusion."),
        "tools": [
            "misc.readpst_extract",
            "misc.pff_export",
            "misc.chat_db_export",
        ],
    },
    {
        "id": "network_pcap",
        "phases": ["Triage", "Collect", "Analyze", "Scan"],
        "evidence": ["pcap"],
        "purpose": "Extract DNS, HTTP, sessions, identities, IPs, and payload streams from packet captures.",
        "tools": [
            "net.tcpdump_read",
            "net.tcpdump_list_connections",
            "net.tcpdump_extract_ips",
            "net.tcpdump_extract_dns",
            "net.tcpdump_extract_http",
            "net.http_session_inventory",
            "net.pcap_identity_timeline",
            "net.ngrep_search",
            "net.tcpxtract_streams",
        ],
    },
    {
        "id": "static_file_triage",
        "phases": ["Triage", "Analyze", "Scan"],
        "evidence": ["file", "mounted_fs"],
        "purpose": "Identify, hash, grep, inspect, and classify files or extracted payloads.",
        "tools": [
            "strings.stat_file",
            "strings.file_identify",
            "strings.grep",
            "strings.floss_extract",
            "hash.file",
            "hash.directory",
            "hash.verify_evidence_hash",
            "misc.capa_analyze",
            "misc.pe_scanner",
            "misc.densityscout_scan",
        ],
    },
    {
        "id": "ioc_scan_enrichment",
        "phases": ["Scan", "Analyze"],
        "evidence": ["file", "memory", "pcap", "mounted_fs"],
        "purpose": "Sweep for known indicators and enrich hashes, IPs, and domains.",
        "tools": [
            "misc.knowns_pattern_generate",
            "yara.scan_file",
            "yara.scan_directory",
            "yara.scan_memory_image",
            "yara.scan_strings",
            "enrich.vt_lookup_hash",
            "enrich.vt_lookup_ip",
            "enrich.vt_lookup_domain",
            "enrich.abuseipdb_check",
        ],
    },
    {
        "id": "anti_forensics",
        "phases": ["Analyze", "Scan"],
        "evidence": ["disk", "memory"],
        "purpose": "Check for timestomping, log clearing, Sysmon evasion, USN gaps, and prefetch deletion.",
        "tools": [
            "af.timestomp_drift",
            "af.event_log_clear",
            "af.sysmon_evasion",
            "af.usn_gaps",
            "af.prefetch_deletion",
        ],
    },
    {
        "id": "live_endpoint",
        "phases": ["Triage", "Collect", "Analyze", "Scan"],
        "evidence": ["live"],
        "purpose": "Read-only live endpoint enumeration through fixed SSH argv wrappers.",
        "tools": [
            "live.hosts",
            "live.processes",
            "live.process_details",
            "live.network_connections",
            "live.recent_logins",
            "live.services",
            "live.scheduled_tasks",
            "live.persistence_audit",
            "live.open_files",
            "live.read_file",
            "live.yara_scan",
        ],
    },
    {
        "id": "cross_artifact_correlation",
        "phases": ["Analyze", "Report"],
        "evidence": ["all"],
        "purpose": "Join process/file/network evidence, validate ATT&CK IDs, assess coverage, and attribute observed TTPs.",
        "tools": [
            "correlate.process_to_file",
            "correlate.network_to_process",
            "correlate.mitre_map",
            "correlate.mitre_validate",
            "coverage.report",
            "attribution.attribute_actors",
        ],
    },
]


_SUBSTITUTIONS: list[dict] = [
    {
        "when": "pcap_only",
        "avoid_prefixes": ["vol.", "ez.", "tsk."],
        "prefer_capabilities": ["network_pcap", "ioc_scan_enrichment"],
        "note": "Use net.* extraction/search tools instead of memory, filesystem, or Windows artifact parsers.",
    },
    {
        "when": "disk_only",
        "avoid_prefixes": ["net.tcpdump_", "net.ngrep_search", "vol."],
        "prefer_capabilities": ["disk_filesystem_timeline", "windows_registry_identity", "windows_event_logs"],
        "note": "Use tsk.*, ez.*, misc.*, strings.*, hash.*, and yara.* over packet or memory tools.",
    },
    {
        "when": "memory_only",
        "avoid_prefixes": ["ez.", "tsk.", "plaso."],
        "prefer_capabilities": ["memory_process_network", "static_file_triage", "ioc_scan_enrichment"],
        "note": "Use vol.* memory wrappers and dump/extract files before disk-artifact parsers.",
    },
    {
        "when": "live_endpoint",
        "avoid_prefixes": ["vol.", "ez.", "tsk."],
        "prefer_capabilities": ["live_endpoint"],
        "note": "Use live.* read-only wrappers unless a collected image/artifact is explicitly available.",
    },
]


# Evidence kinds (core.evidence_kinds.KINDS) a tool needs — ANY one of the
# listed kinds suffices. A tool matched by neither table is GENERIC (strings,
# yara, hash, read, reason, dair, enrich, carve, control-plane misc.*): it runs
# on whatever the case holds. DAIR drops a prescribed tool — or a verification
# challenge whose challenge_method is one — when the case holds none of the
# kinds it needs (tools/dair.py), so no round trip is spent on it and it never
# becomes an open work-order item or challenge.
_WINDOWS_ARTIFACTS = frozenset({"disk_image", "triage"})
_EVIDENCE_NEEDS_PREFIX: tuple[tuple[str, frozenset], ...] = (
    ("vol.", frozenset({"memory"})),
    ("net.", frozenset({"pcap"})),
    ("tsk.", frozenset({"disk_image"})),
    ("ewf.", frozenset({"disk_image"})),
    ("img.", frozenset({"disk_image"})),
    ("ez.", _WINDOWS_ARTIFACTS),
    ("af.", _WINDOWS_ARTIFACTS),           # every detector reads a disk-artifact parse
    ("live.", frozenset({"live"})),
    ("velo.", frozenset({"live"})),
    ("monitor.", frozenset({"live"})),
    ("respond.", frozenset({"live"})),
)
_EVIDENCE_NEEDS_TOOL: dict[str, frozenset] = {
    "ez.sqlecmd": frozenset({"disk_image", "triage", "mobile"}),   # any SQLite store
    "correlate.process_to_file": frozenset({"memory"}),
    "correlate.network_to_process": frozenset({"memory"}),
    "yara.scan_memory_image": frozenset({"memory"}),
    "yara.scan_process_memory": frozenset({"memory"}),
    "plaso.create_timeline": frozenset({"disk_image", "triage", "mobile"}),
    "plaso.create_targeted": frozenset({"disk_image", "triage", "mobile"}),
    "misc.chat_db_export": frozenset({"disk_image", "triage", "mobile"}),
    **{t: _WINDOWS_ARTIFACTS for t in (
        "misc.evtx_filter", "misc.evtx_dump", "misc.chainsaw_hunt", "misc.regripper_hive",
        "misc.usnparser_parse", "misc.analyzemft_parse", "misc.srum_export",
        "misc.device_install_inventory", "misc.parse_scheduled_tasks",
        "misc.usbdeviceforensics", "misc.hindsight_chrome")},
}


def canonical_tool_id(tool) -> str:
    """'vol.pslist' for any spelling of a prescribed tool: vol_pslist,
    vol_vol_pslist, mcp__trudi-sift__vol_pslist, 'vol.pslist(pid=4)', or a
    structured {'tool': ...} item."""
    if isinstance(tool, dict):
        tool = tool.get("tool") or ""
    t = str(tool or "").strip().split("(", 1)[0].strip()
    t = (t.split() or [""])[0].rstrip(",").lower()
    if t.startswith("mcp__"):
        t = t.split("__")[-1]
    if "." not in t and "_" in t:
        from tools._fk import normalize_tool_name
        t = normalize_tool_name(t).replace("_", ".", 1)
    return t


def tool_evidence_needs(tool) -> frozenset | None:
    """Evidence kinds `tool` needs (any one), or None when it is generic."""
    t = canonical_tool_id(tool)
    if t in _EVIDENCE_NEEDS_TOOL:
        return _EVIDENCE_NEEDS_TOOL[t]
    for prefix, needs in _EVIDENCE_NEEDS_PREFIX:
        if t.startswith(prefix):
            return needs
    return None


def tool_fits_evidence(tool, evidence_kinds) -> bool:
    """True unless the case's evidence kinds are KNOWN (non-empty) and hold
    none of the kinds `tool` needs. An empty/None kind set is undetermined —
    everything fits (fail-open)."""
    if not evidence_kinds:
        return True
    needs = tool_evidence_needs(tool)
    return needs is None or bool(needs & set(evidence_kinds))


def challenge_method_tools(method) -> list[str]:
    """The tool ids a challenge_method names — backends write one tool, a
    parametrised call, or a comma-separated list ('ez.mftecmd (dir),
    misc.usnparser_parse')."""
    out = []
    for part in re.split(r",(?![^()]*\))", str(method or "")):
        t = canonical_tool_id(part)
        if t:
            out.append(t)
    return out


# Wrappers that shell out to an OPTIONAL binary (not on every SIFT build).
# tool id -> (candidate names/paths — any one present = installed, install hint).
# A tool whose binary is missing fails fast with a typed `tool_unavailable`
# result and is left out of the manifest, so DAIR never prescribes it.
_OPTIONAL_BINARIES: dict[str, tuple[tuple[str, ...], str]] = {
    "misc.chainsaw_hunt": (("chainsaw",), "see install.sh for the binary release "
                                         "(github.com/WithSecureLabs/chainsaw)"),
    "misc.capa_analyze": (("capa",), "pip install flare-capa"),
    "strings.floss_extract": (("floss",), "pip install flare-floss"),
    "misc.olevba_scan": (("olevba", "olevba3"), "pip install oletools"),
    "misc.mraptor_scan": (("mraptor", "mraptor3"), "pip install oletools"),
    "misc.densityscout_scan": (("densityscout", "/usr/local/bin/densityscout"),
                               "install densityscout (cert.at) to /usr/local/bin"),
    "misc.hindsight_chrome": (("/usr/local/bin/hindsight.py",), "pip install pyhindsight"),
    "misc.usnparser_parse": (("/usr/local/bin/usnparser",), "install usnparser to /usr/local/bin"),
    "misc.pff_export": (("pffexport",), "apt install pff-tools"),
    "misc.readpst_extract": (("readpst",), "sudo apt install pst-utils"),
    "misc.srum_export": (("esedbexport",), "apt install libesedb-utils"),
}


def optional_binary(tool_id: str, which=None) -> str | None:
    """Resolved binary for an optional-binary tool; None when none is installed.
    Tools outside the table are always considered available ("")."""
    spec = _OPTIONAL_BINARIES.get(tool_id)
    if not spec:
        return ""
    which = which or shutil.which
    return next((b for b in (which(n) for n in spec[0]) if b), None)


def tool_unavailable_result(tool_id: str, which=None) -> dict | None:
    """Typed fail-fast result when `tool_id`'s binary is missing, else None."""
    if optional_binary(tool_id, which) is not None:
        return None
    names, hint = _OPTIONAL_BINARIES[tool_id]
    return {"success": False, "status": "tool_unavailable", "tool_unavailable": True,
            "binary": names[0],
            "error": f"{names[0].rsplit('/', 1)[-1]} not installed — {hint}",
            "note": ("An uninstalled tool establishes nothing about the evidence; "
                     "settle it with misc.record_disposition(target_kind='tool', "
                     "reason='inapplicable') or use another parser.")}


def unavailable_tools() -> set[str]:
    """Optional-binary tools whose binary is not installed on this host."""
    return {t for t in _OPTIONAL_BINARIES if optional_binary(t) is None}


def _installed(tools: list[str]) -> list[str]:
    missing = unavailable_tools()
    return [t for t in tools if t not in missing]


def tool_capability_manifest() -> dict:
    """Return a copy of the structured manifest."""
    return {
        "version": MANIFEST_VERSION,
        "capabilities": copy.deepcopy(_CAPABILITIES),
        "substitutions": copy.deepcopy(_SUBSTITUTIONS),
    }


def allowed_tool_names(evidence_kinds=None) -> set[str]:
    """Return every tool ID that DAIR/reasoning may place in priority_tools —
    only those the case's evidence can feed when `evidence_kinds` is known."""
    names: set[str] = set()
    for cap in _CAPABILITIES:
        names.update(cap.get("tools", []))
    return {t for t in names - unavailable_tools() if tool_fits_evidence(t, evidence_kinds)}


def capability_for_tool(tool_name: str) -> str:
    """Return the capability id for a tool, or an empty string if unknown."""
    for cap in _CAPABILITIES:
        if tool_name in cap.get("tools", []):
            return cap["id"]
    return ""


def unknown_priority_tools(priority_tools: list[str] | None) -> list[str]:
    """Return priority tool names not present in the manifest."""
    allowed = allowed_tool_names()
    return [t for t in (priority_tools or []) if isinstance(t, str) and t not in allowed]


def annotate_directives_with_manifest(directives: dict) -> dict:
    """Add manifest metadata to directives without changing the work order."""
    out = copy.deepcopy(directives)
    priority_tools = out.get("priority_tools") or []
    out["tool_manifest_version"] = MANIFEST_VERSION
    out["unknown_priority_tools"] = unknown_priority_tools(priority_tools)
    out["priority_tool_capabilities"] = [
        {"tool": t, "capability": capability_for_tool(t)}
        for t in priority_tools
        if isinstance(t, str)
    ]
    return out


def format_tool_manifest_for_prompt(max_tools_per_capability: int = 8,
                                    evidence_kinds=None) -> str:
    """Compact text block for model system prompts. With `evidence_kinds`
    (non-empty), tools the case's evidence cannot feed are left out, and a
    capability left with no tool is dropped."""
    lines = [
        "TOOL CAPABILITY MANIFEST:",
        f"- version: {MANIFEST_VERSION}",
        "- Use only these tool IDs in directives.priority_tools and challenge_method.",
        "- Select by capability/evidence type, then choose the smallest executable batch.",
    ]
    if evidence_kinds:
        lines.append(f"- listed for the evidence this case holds: {', '.join(sorted(evidence_kinds))}")
    for cap in _CAPABILITIES:
        installed = [t for t in _installed(cap["tools"]) if tool_fits_evidence(t, evidence_kinds)]
        if not installed:
            continue
        tools = installed[:max_tools_per_capability]
        if len(installed) > max_tools_per_capability:
            tools = tools + ["..."]
        lines.append(
            f"- {cap['id']} | phases={','.join(cap['phases'])} | "
            f"evidence={','.join(cap['evidence'])} | tools={', '.join(tools)}"
        )
    lines.append("Evidence-type substitution rules:")
    for rule in _SUBSTITUTIONS:
        lines.append(
            f"- {rule['when']}: avoid {', '.join(rule['avoid_prefixes'])}; "
            f"prefer {', '.join(rule['prefer_capabilities'])}. {rule['note']}"
        )
    return "\n".join(lines)
