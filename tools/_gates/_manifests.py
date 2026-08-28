"""Per-category source manifests for the negative_completeness gate.

A negative/absence finding is only valid if the investigation searched the
COMPLETE set of sources where the thing could be. This encodes, as data, the
"complete source set" for each case-inverting claim category — the same lists
that live as prose in CLAUDE.md (Exhaustive Evidence Rule, Identity Exhaustion
Gate, Authentication-Session Inventory, Exfil-Channel Enumeration).

A finding is gated by its DECLARED claim (claim_kind="negative" + category —
see tools/_gates/_claims.py); there is no wording classifier. Each category has:
  required       — [(source_id, cmd_regex, where_hint)] : every source must have
                   been touched by some tool_call (cmd regex — a regex over TOOL
                   COMMANDS, not prose) OR settled by a typed disposition
                   (misc.record_disposition(target_kind="source", target_id=<source_id>,
                   reason="absent_from_evidence"|"inapplicable"|"out_of_scope"))
  alt_satisfies  — optional regex that waives `required` entirely (e.g. a Linux
                   host satisfies LOGON_AUTH via wtmp/last instead of the Windows
                   event channels)
  where          — human hint appended to the refusal: where the missing sources
                   live (so the agent is steered to them, not just blocked)
"""
import re


def _rx(p: str) -> "re.Pattern":
    return re.compile(p, re.IGNORECASE)


# claim.category (typed claim) → manifest key. Only these categories carry a
# complete-source manifest; a negative in any other category is not gated here.
CATEGORY_MAP = {"exfil": "EXFIL", "logon_auth": "LOGON_AUTH", "identity": "IDENTITY",
                "persistence": "PERSISTENCE", "device_initial_access": "DEVICE_INITIAL_ACCESS"}

# Disposition reasons that settle a manifest source without searching it.
SOURCE_WAIVER_REASONS = ("absent_from_evidence", "inapplicable", "out_of_scope")

MANIFESTS: dict = {
    "LOGON_AUTH": {
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
        "required": [
            ("device_inventory", _rx(r"device_install_inventory"),
             "a complete device-install inventory from setupapi.dev.log "
             "(misc.device_install_inventory) — enumerate every device, don't grep"),
            ("scheduled_tasks", _rx(r"parse_scheduled_tasks|scheduled_task|taskcache|[\\/]Tasks[\\/]"),
             "scheduled tasks / autoruns — a keystroke injector commonly plants a "
             "hidden task (\Windows\System32\Tasks, no 4698 event when auditing is off)"),
        ],
        "alt_satisfies": None,
        "where": "the complete device-install inventory (misc.device_install_inventory) over "
                 "setupapi.dev.log — USBSTOR/mass-storage enumeration alone cannot reveal a "
                 "keystroke-injection device",
    },
    "IDENTITY": {
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
        "required": [
            ("removable", _rx(r"usbstor|mounteddevices|usbdevice|\blecmd\b|\blnk\b|removable|usn"),
             "removable-media trail (USBSTOR / MountedDevices / LNK / USN $J)"),
            ("cloud", _rx(r"dropbox|onedrive|gdrive|google ?drive|hindsight|filecache"),
             "cloud-client DBs (Dropbox / OneDrive / GDrive)"),
            ("mail_web", _rx(r"readpst|pff_export|attachment|\bhttp\b|ngrep|pcap|web upload"),
             "mail attachments / web-upload / HTTP sessions"),
            ("srum_ftp", _rx(r"srum|srudb|\bftp\b|transfer\.log|netflow"),
             "SRUM / FTP-transfer logs / netflow"),
            ("chat_messenger",
             _rx(r"main\.db|skype|whatsapp|telegram|msgstore|chat_db_export"),
             "chat/messenger stores (message + file-transfer trail)"),
        ],
        "alt_satisfies": None,
        "where": "every candidate egress channel (removable, cloud, mail, web, FTP, C2), each checked for a transfer artifact",
    },
}


# Chat/messenger store FAMILIES a case's evidence may hold — the
# presence-completeness check keys on these (a family token in collected
# output means the store exists and must be parsed or dispositioned).
# Data-driven so coverage grows here, never in inline code. Patterns are
# path/product-context anchored to avoid prose false-positives.
CHAT_FAMILIES: dict = {
    "skype": _rx(r"skype"),
    "whatsapp": _rx(r"whatsapp"),
    "telegram": _rx(r"telegram"),
    "signal": _rx(r"signal-desktop|[\\/ ]signal[\\/ .]"),
    "wechat": _rx(r"wechat|weixin"),
    "qq": _rx(r"[\\/ ]qq[\\/ .]|tencent"),
    "discord": _rx(r"discord"),
    "viber": _rx(r"viber"),
    "slack": _rx(r"[\\/ ]slack[\\/ .]"),
    "imessage": _rx(r"imessage|chat\.db|sms\.db"),
}


def manifest_for_claim(claim: dict | None):
    """Manifest key for a DECLARED negative claim, else None."""
    c = claim or {}
    if str(c.get("kind") or "").lower() != "negative":
        return None
    return CATEGORY_MAP.get(str(c.get("category") or "").lower())
