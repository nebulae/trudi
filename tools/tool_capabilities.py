"""Curated TRUDI tool capability manifest.

The manifest is intentionally small and semantic. It is not a full inventory of
every MCP wrapper; it is the planning vocabulary DAIR/reasoning should use when
choosing the next batch. Focused wrappers can still exist outside this list, but
priority_tools should come from these known, phase-appropriate capabilities.
"""
from __future__ import annotations

import copy


MANIFEST_VERSION = "2026-06-11.2"


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
        ],
    },
    {
        "id": "memory_process_network",
        "phases": ["Triage", "Analyze", "Scan"],
        "evidence": ["memory"],
        "purpose": "Enumerate processes, command lines, sessions, injected memory, and network sockets from memory.",
        "tools": [
            "vol.psscan",
            "vol.pslist",
            "vol.pstree",
            "vol.cmdline",
            "vol.sessions",
            "vol.netscan",
            "vol.netstat",
            "vol.malfind",
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
            "live.live_event_log_tail",
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
            "strings.strings_grep",
            "strings.floss_extract",
            "hash.hash_file",
            "hash.hash_directory",
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
            "af.af_timestomp_drift",
            "af.af_event_log_clear",
            "af.af_sysmon_evasion",
            "af.af_usn_gaps",
            "af.af_prefetch_deletion",
        ],
    },
    {
        "id": "live_endpoint",
        "phases": ["Triage", "Collect", "Analyze", "Scan"],
        "evidence": ["live"],
        "purpose": "Read-only live endpoint enumeration through fixed SSH argv wrappers.",
        "tools": [
            "live.live_hosts",
            "live.live_processes",
            "live.live_process_details",
            "live.live_network_connections",
            "live.live_recent_logins",
            "live.live_services",
            "live.live_scheduled_tasks",
            "live.live_persistence_audit",
            "live.live_open_files",
            "live.live_read_file",
            "live.live_yara_scan",
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
            "coverage.coverage_report",
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


def tool_capability_manifest() -> dict:
    """Return a copy of the structured manifest."""
    return {
        "version": MANIFEST_VERSION,
        "capabilities": copy.deepcopy(_CAPABILITIES),
        "substitutions": copy.deepcopy(_SUBSTITUTIONS),
    }


def allowed_tool_names() -> set[str]:
    """Return every tool ID that DAIR/reasoning may place in priority_tools."""
    names: set[str] = set()
    for cap in _CAPABILITIES:
        names.update(cap.get("tools", []))
    return names


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


def format_tool_manifest_for_prompt(max_tools_per_capability: int = 8) -> str:
    """Compact text block for model system prompts."""
    lines = [
        "TOOL CAPABILITY MANIFEST:",
        f"- version: {MANIFEST_VERSION}",
        "- Use only these tool IDs in directives.priority_tools and challenge_method.",
        "- Select by capability/evidence type, then choose the smallest executable batch.",
    ]
    for cap in _CAPABILITIES:
        tools = cap["tools"][:max_tools_per_capability]
        if len(cap["tools"]) > max_tools_per_capability:
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
