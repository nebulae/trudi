"""Per-category source manifests for the negative_completeness gate.

A negative/absence finding is only valid if the investigation searched the
COMPLETE set of sources where the thing could be. This encodes, as data, the
"complete source set" for each case-inverting claim category — the same lists
that live as prose in CLAUDE.md (Exhaustive Evidence Rule, Identity Exhaustion
Gate, Authentication-Session Inventory, Exfil-Channel Enumeration).

Each category has:
  trigger        — regex over a finding description that marks it as this kind
                   of absence claim (only matched UNCONFIRMED findings are gated)
  required       — [(source_id, cmd_regex, where_hint)] : every source must have
                   been touched by some tool_call (cmd substring match) OR proven
                   absent from evidence
  alt_satisfies  — optional regex that waives `required` entirely (e.g. a Linux
                   host satisfies LOGON_AUTH via wtmp/last instead of the Windows
                   event channels)
  where          — human hint appended to the refusal: where the missing sources
                   live (so the agent is steered to them, not just blocked)
"""
import re


def _rx(p: str) -> "re.Pattern":
    return re.compile(p, re.IGNORECASE)


MANIFESTS: dict = {
    # Order matters: classify() returns the FIRST matching category, so the
    # most specific / case-inverting (LOGON_AUTH) is listed first.
    "LOGON_AUTH": {
        "trigger": _rx(
            r"\bno\b[^.\n]*(?:logon|log-on|rdp|remote[- ]?interactive|type ?10|"
            r"authenticat|session|sign[- ]?in|external network)"
            r"|local[- ]console only"
            r"|controller (?:unknown|unidentified|unestablished|cannot be|not established)"
            r"|no (?:authentication|session|logon)[- ]?(?:artifact|event|source)"
        ),
        "required": [
            ("security_evtx",
             _rx(r"security\.evtx|security_logons|\b4624\b|\b4625\b"),
             "Security.evtx 4624/4625 by logon type + source address"),
            ("terminalservices",
             _rx(r"localsessionmanager|remoteconnectionmanager|terminalservices"),
             "TerminalServices RDP channels (LocalSessionManager / RemoteConnectionManager "
             "Operational) — these record type-10/RDP sessions with user + source IP"),
        ],
        "alt_satisfies": _rx(r"\bwtmp\b|\butmp\b|lastlog|\blast\s+-|\bjournalctl\b|sshd|secure\.log"),
        "where": (
            "the FULL winevt\\Logs on the mounted image (the TerminalServices channels are "
            "NOT in a CyLR/triage set), plus VSS / carved EVTX for windows that predate live-log "
            "coverage"
        ),
    },
    # NOTE: DEVICE_INITIAL_ACCESS satisfaction is handled directly in
    # negative_completeness.check() against a COMPLETE structured device-install
    # inventory (misc.device_install_inventory + coverage span + flagged_count) —
    # not via the generic `required` cmd-substring loop. `required`/`where` below
    # are informational only and intentionally carry no device-specific signatures.
    "DEVICE_INITIAL_ACCESS": {
        "trigger": _rx(
            r"\bno\b[^.\n]*(?:malicious (?:usb|device)|bad ?usb|hid (?:injection|attack|device)"
            r"|keystroke inject\w*|rogue device|physical (?:access|device))"
            r"|no initial[- ]access|not (?:a )?bad ?usb"
        ),
        "required": [
            ("device_inventory", _rx(r"device_install_inventory"),
             "a complete device-install inventory from setupapi.dev.log "
             "(misc.device_install_inventory) — enumerate every device, don't grep"),
        ],
        "alt_satisfies": None,
        "where": "the complete device-install inventory (misc.device_install_inventory) over "
                 "setupapi.dev.log — USBSTOR/mass-storage enumeration alone cannot reveal a "
                 "keystroke-injection device",
    },
    "IDENTITY": {
        "trigger": _rx(
            r"\b(?:identity|attribution|operator|owner|actor)\b[^.\n]*"
            r"(?:unknown|unidentified|cannot be|not (?:established|determined|known))"
            r"|no (?:match|identity)[^.\n]*(?:roster|suspect|directory)"
            r"|requires?[^.\n]*(?:subpoena|legal process)"
            r"|\bunattributed\b"
        ),
        "required": [
            ("sam", _rx(r"\bsam\b|sam hive|recmd[^\n]*sam"),
             "SAM hive — local accounts / last-login"),
            ("ntuser", _rx(r"ntuser"),
             "NTUSER.DAT per user profile — Office LiveId / owner identity"),
            ("browser", _rx(r"hindsight|webcache|places\.sqlite|\bhistory\b|cookies|chrome|firefox|edge"),
             "browser history/cookies across all profiles"),
            ("comms", _rx(r"readpst|pff_export|\.ost\b|\.pst\b|outlook|main\.db|skype|whatsapp|telegram"),
             "mail/chat stores — full sender/recipient inventory"),
            ("roster_xref", _rx(r"knowns_pattern|roster|cross-referenc|suspect list|user directory"),
             "roster / suspect-list cross-reference (normalized identifiers)"),
        ],
        "alt_satisfies": None,
        "where": "every identity-bearing artifact on the host (the Identity Exhaustion list), each cross-referenced against the case roster",
    },
    "PERSISTENCE": {
        "trigger": _rx(
            r"\bno\b[^.\n]*(?:persistence|persist|autostart|auto[- ]?run|run key|"
            r"scheduled task|service|wmi|startup|implant|foothold)"
        ),
        "required": [
            ("run_keys", _rx(r"\brun\b|runonce|recmd[^\n]*(software|ntuser)"),
             "all 4 Run/RunOnce hives (SOFTWARE + NTUSER, HKLM/HKCU)"),
            ("services", _rx(r"svcscan|svclist|\bservices?\b|recmd[^\n]*system"),
             "services (SYSTEM hive / vol.svcscan)"),
            ("scheduled_tasks", _rx(r"scheduled_task|schtask|\btasks?\b|parse_scheduled"),
             "scheduled tasks (\\Windows\\System32\\Tasks)"),
            ("startup_wmi_amcache", _rx(r"amcache|userassist|startup|\bwmi\b|autoruns|winlogon"),
             "Startup folder / WMI subscriptions / Winlogon / Amcache / UserAssist"),
        ],
        "alt_satisfies": None,
        "where": "all persistence locations (Run keys, services, scheduled tasks, WMI, Startup, Winlogon)",
    },
    "EXFIL": {
        "trigger": _rx(
            r"\bno\b[^.\n]*(?:exfil|exfiltrat|data (?:left|leav)|egress|"
            r"transfer(?:red)? (?:out|off|to)|dissemination|data (?:theft|removed))"
        ),
        "required": [
            ("removable", _rx(r"usbstor|mounteddevices|usbdevice|\blecmd\b|\blnk\b|removable|usn"),
             "removable-media trail (USBSTOR / MountedDevices / LNK / USN $J)"),
            ("cloud", _rx(r"dropbox|onedrive|gdrive|google ?drive|hindsight|filecache"),
             "cloud-client DBs (Dropbox / OneDrive / GDrive)"),
            ("mail_web", _rx(r"readpst|pff_export|attachment|\bhttp\b|ngrep|pcap|web upload"),
             "mail attachments / web-upload / HTTP sessions"),
            ("srum_ftp", _rx(r"srum|srudb|\bftp\b|transfer\.log|netflow"),
             "SRUM / FTP-transfer logs / netflow"),
        ],
        "alt_satisfies": None,
        "where": "every candidate egress channel (removable, cloud, mail, web, FTP, C2), each checked for a transfer artifact",
    },
}


def classify(description: str):
    """Return the first category whose `trigger` matches `description`, else None.
    Only the four case-inverting categories are gated; everything else passes."""
    for cat, spec in MANIFESTS.items():
        if spec["trigger"].search(description or ""):
            return cat
    return None
