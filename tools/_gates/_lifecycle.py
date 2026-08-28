"""Attack-lifecycle coverage model — the DFIR goals that drive what a
forensic investigation must try to uncover, as DATA (same spirit as
_manifests.py). The five phases of the cyber attack lifecycle each have:

  establishes  — the typed finding claim that ESTABLISHES the phase (a positive
                 finding whose category ∈ categories OR act ∈ acts).
  sources      — [(source_id, cmd_regex, where_hint)] : the canonical artifact
                 sources for the phase; a phase is EXAMINED when any source's
                 regex matches a successful tool_call command/output. Regexes
                 run over TOOL COMMANDS + stdout excerpts, never over agent prose.

This is the coverage skeleton, not a gate that demands attacks exist. A phase is
"covered" three ways — established by a finding, ruled out by a grounded negative,
or its sources examined (supporting either) — so it is evidence-symmetric: finding
an attack and proving its absence both count. Windows-first; extensible to
Linux/macOS via alt source ids (last/wtmp, cron, launchd).
"""
from __future__ import annotations

import re


def _rx(p: str) -> "re.Pattern":
    return re.compile(p, re.IGNORECASE)


# phase_id -> spec. Order is the lifecycle order (persistence … exfil).
LIFECYCLE: dict = {
    "persistence": {
        "label": "Persistence",
        "establishes": {"categories": {"persistence"}, "acts": {"persistence_install"}},
        "sources": [
            ("scheduled_tasks", _rx(r"parse_scheduled_tasks|schtask|taskcache|[\\/]Tasks[\\/]|\b(?:106|200|201)\b.*task"),
             "scheduled tasks — \\Windows\\System32\\Tasks + TaskScheduler 106/200/201"),
            ("run_keys", _rx(r"\brun(?:once)?\b|currentversion[\\/]?run|recmd[^\n]*(?:software|ntuser)"),
             "Run/RunOnce keys (SOFTWARE + NTUSER, HKLM/HKCU)"),
            ("services", _rx(r"\b7045\b|svcscan|svclist|service creation|recmd[^\n]*system"),
             "Windows services (System 7045 / SYSTEM hive)"),
            ("startup_folder", _rx(r"startup|start menu[\\/]?programs"),
             "Startup folder (per-user + all-users)"),
            ("wmi", _rx(r"\bwmi\b|objects\.data|eventconsumer|eventfilter"),
             "WMI permanent event subscriptions (OBJECTS.DATA)"),
        ],
    },
    "privilege_escalation": {
        "label": "Privilege Escalation",
        "establishes": {"categories": {"privilege_escalation"}, "acts": {"privilege_escalation"}},
        "sources": [
            ("special_privileges", _rx(r"\b4672\b|special privileges"),
             "Security 4672 — special privileges assigned to new logon"),
            ("group_modification", _rx(r"\b4728\b|\b4732\b|member added|administrators group|domain admins"),
             "Security 4728/4732 — additions to privileged groups"),
            ("process_masquerade", _rx(r"parent process|masquerad|pebmasquerade|hollowprocess|spoolsv|pstree"),
             "process masquerading / unusual parent (pstree / hollowprocesses)"),
            ("uac_token", _rx(r"\buac\b|elevated token|integrity level|consent\.exe"),
             "UAC bypass / token elevation artifacts"),
        ],
    },
    "lateral_movement": {
        "label": "Lateral Movement",
        "establishes": {"categories": set(), "acts": {"lateral_movement"}},
        "sources": [
            ("network_rdp_logon", _rx(r"\b4624\b.*(?:type\s*3|type\s*10)|logon\s*type\s*(?:3|10)|\b4624\b|\b4625\b"),
             "Security 4624/4625 by logon type — network (3) / RDP (10)"),
            ("psexec", _rx(r"psexec|psexesvc|\b4697\b|\b7045\b.*(?:svc|remote)"),
             "PsExec — 4697 / 7045 (PSEXESVC-style service names)"),
            ("winrm_ps_remoting", _rx(r"winrm|\b4104\b|script ?block|wsmprovhost|enter-pssession"),
             "WinRM / PowerShell remoting — 4104 script-block logging"),
            ("terminalservices", _rx(r"localsessionmanager|remoteconnectionmanager|terminalservices|\b(?:21|22|25)\b.*session"),
             "TerminalServices-LocalSessionManager/Operational 21/22/25"),
            ("network_shares", _rx(r"\b5140\b|network share|admin\$|c\$|ipc\$"),
             "Security 5140 — network share object accessed"),
        ],
    },
    "execution": {
        "label": "Evidence of Execution",
        "establishes": {"categories": {"execution"}, "acts": {"execution"}},
        "sources": [
            ("prefetch", _rx(r"prefetch|\bpecmd\b"),
             "Prefetch (C:\\Windows\\Prefetch)"),
            ("shimcache", _rx(r"shimcache|appcompatcache|appcompatcacheparser"),
             "Shimcache / AppCompatCache (SYSTEM hive)"),
            ("amcache", _rx(r"amcache"),
             "Amcache.hve (execution + SHA-1)"),
            ("userassist", _rx(r"userassist"),
             "UserAssist (HKCU Explorer)"),
            ("srum", _rx(r"\bsrum\b|srudb|sru[\\/]"),
             "SRUM (SRUDB.dat — app network/run duration)"),
        ],
    },
    "exfil": {
        "label": "Exfiltration",
        "establishes": {"categories": {"exfil"}, "acts": {"egress"}},
        "sources": [
            ("network_flow", _rx(r"netflow|proxy log|firewall log|tcpdump|ngrep|pcap|http_session"),
             "network flow / proxy / firewall / PCAP for outbound transfers"),
            ("archive_sync_tools", _rx(r"7-?zip|winrar|\brar\b|rclone|megasync|mega\.nz|robocopy|\bzip\b|veracrypt"),
             "archiver / cloud-sync tools (7-Zip, WinRAR, Rclone, MegaSync)"),
            ("dns_tunneling", _rx(r"dns tunnel|tcpdump_extract_dns|dns log|subdomain"),
             "DNS logs — tunnelling (high-volume subdomain requests)"),
            ("browser_upload", _rx(r"hindsight|webcache|places\.sqlite|\bhistory\b|file-?sharing|webmail|upload"),
             "browser history — file-sharing / webmail upload"),
            ("usb_history", _rx(r"usbstor|mounteddevices|usbdevice|\blecmd\b|\blnk\b|removable|usn"),
             "USB history (USBSTOR / MountedDevices / LNK / USN $J)"),
            ("ftp_transfer", _rx(r"\bftp\b|transfer\.log|smallftpd|srum"),
             "FTP / transfer logs"),
        ],
    },
}


def _fclaim(e: dict) -> dict:
    c = e.get("claim")
    return c if isinstance(c, dict) else {}


def coverage(entries) -> dict:
    """Per-phase coverage of the attack lifecycle from the trace. Returns
    {phase_id: {label, status, sources_examined, sources_total}} where status is:
      established  — a positive finding asserts the phase,
      ruled_out    — a negative finding in the phase's category (a grounded 'no X'),
      examined     — the phase's artifact sources were touched (no verdict yet),
      not_examined — none of the above (the coverage gap to surface).
    Advisory only: this is the coverage skeleton, never a demand that attacks exist."""
    findings = [e for e in (entries or []) if e.get("type") == "finding"]
    # tool commands + stdout excerpts of successful tool calls (regexes run over
    # these, never over agent prose).
    haystack = [
        ((e.get("cmd") or "") + " " + (e.get("stdout_excerpt") or "")).lower()
        for e in (entries or [])
        if e.get("type") == "tool_call" and e.get("success") is not False
    ]
    out: dict = {}
    for pid, spec in LIFECYCLE.items():
        cats = spec["establishes"]["categories"]
        acts = spec["establishes"]["acts"]
        established, ruled_out = False, False
        for f in findings:
            c = _fclaim(f)
            in_phase = (c.get("category") in cats) or (c.get("act") in acts)
            if not in_phase:
                continue
            if c.get("kind") == "negative":
                ruled_out = True
            else:
                established = True
        exam = [sid for (sid, rx, _hint) in spec["sources"] if any(rx.search(h) for h in haystack)]
        if established:
            status = "established"
        elif ruled_out:
            status = "ruled_out"
        elif exam:
            status = "examined"
        else:
            status = "not_examined"
        out[pid] = {"label": spec["label"], "status": status,
                    "sources_examined": exam, "sources_total": len(spec["sources"])}
    return out


def uncovered_phases(entries) -> list:
    """Phase specs (id, label, where-hints) whose status is not_examined — the
    lifecycle coverage the investigation never looked at."""
    cov = coverage(entries)
    out = []
    for pid, spec in LIFECYCLE.items():
        if cov[pid]["status"] == "not_examined":
            hints = "; ".join(h for (_sid, _rx, h) in spec["sources"][:3])
            out.append((pid, spec["label"], hints))
    return out


# MCP collection tools per phase — disk / event-log based, so they apply to any
# Windows disk image (the evidence-aware prescription in dair_assess filters out
# memory/pcap tools). dair_assess backfills an empty work order from these for
# the phases still not examined, so the director always has a concrete agenda.
COLLECT_TOOLS: dict = {
    "persistence": ["ez.recmd_hive", "misc.parse_scheduled_tasks", "ez.evtxecmd",
                    "misc.regripper_hive"],
    "privilege_escalation": ["ez.evtxecmd", "misc.evtx_filter"],
    "lateral_movement": ["ez.evtxecmd", "misc.evtx_filter"],
    "execution": ["ez.pecmd", "ez.amcacheparser", "ez.appcompatcacheparser", "ez.sqlecmd"],
    "exfil": ["misc.usnparser_parse", "ez.lecmd", "misc.device_install_inventory",
              "misc.chat_db_export"],
}


def prescribe_for_gaps(entries) -> list:
    """Collection tools for the lifecycle phases still `not_examined`, deduped and
    filtered to those not already run (by binary signature). Empty when every
    phase is at least examined — the signal that the phase's work is done and the
    investigation can advance rather than backfill."""
    cov = coverage(entries)
    from tools._gates.work_order import _binary_sig
    succ = [(e.get("cmd") or "").lower() for e in (entries or [])
            if e.get("type") == "tool_call" and e.get("success") is not False and e.get("cmd")]
    out: list = []
    for pid in LIFECYCLE:
        if cov[pid]["status"] != "not_examined":
            continue
        for t in COLLECT_TOOLS.get(pid, []):
            if t in out:
                continue
            sig = _binary_sig(t)
            if sig and any(sig in c for c in succ):     # tool already ran anywhere
                continue
            out.append(t)
    return out
