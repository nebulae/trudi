"""CEF (ArcSight Common Event Format) parsing + the Acalvio ShadowPlex → TRUDI
alert mapping.

Pure stdlib, no MCP imports — shared by the `bin/trudi-cef-ingest.py` sidecar
(which must run standalone), `tools/monitor.py`, and the tests.

Why this exists: a deception platform's decoy-touch alert is the cleanest
"confirmed positive detection in hand" TRUDI's live loop can start from — a
decoy has no legitimate business reason to be touched, so the alert carries
no false-positive class, AND it names the credential presented (a honey
account) as well as the touching host. This module turns one ShadowPlex CEF
record (the fused incident line, optionally merged with its per-protocol
"service interaction" line that shares the incidentID) into the alert JSON
shape `bin/trudi-velo-watcher.py` writes, so `/trudi-check-alerts` and
`/trudi-watch-alerts` consume it with no changes.

Field layout follows the Acalvio ShadowPlex Incident Mapping Guide for CEF
Log Format (release 2026.8.2.0) as shown in the published Splunk sample;
the emitter in `demo/live-monitoring/decoy/` is a format EMULATOR built from
that spec, not Acalvio software.

Evidence-key orientation (matters for the response recipe): the alert is
acted on at the SOURCE host (the beachhead that touched the decoy), so from
that host's point of view the decoy is the REMOTE endpoint:

    source_ip / source_port     the host that touched the decoy (CEF srcIP)
    remote_ip / remote_port     the decoy address:port (CEF dstIP/dstPort)

That lets the existing `block_egress_to_endpoint` template (which reads
`remote_ip`/`remote_port`) cut the beachhead→decoy channel unchanged.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

DETECTOR = "Custom.TRUDI.DecoyTouch"
SOURCE_TAG = "acalvio_shadowplex_cef"

# ── CEF tokenising ──────────────────────────────────────────────────────────

_HEADER_FIELDS = (
    "cef_version", "device_vendor", "device_product", "device_version",
    "event_class_id", "name", "severity",
)

# key=value pairs. Values are either a double-quoted string (the ShadowPlex
# sample quotes values containing spaces — non-standard but common) or an
# unquoted run that ends just before the next `key=` token or end of line
# (standard CEF, where spaces inside values are allowed).
_EXT_RE = re.compile(
    r'(?P<key>[A-Za-z][A-Za-z0-9_]*)='
    r'(?P<val>"(?:[^"\\]|\\.)*"|.*?)'
    r'(?=\s+[A-Za-z][A-Za-z0-9_]*=|\s*$)',
    re.DOTALL,
)
_LABEL_RE = re.compile(r"^(?P<base>(?:cs|cn|cfp|flex(?:Date|String|Number))\d+)Label$")


def _split_header(header: str) -> list[str]:
    """Split the CEF header on unescaped pipes (`\\|` stays literal)."""
    parts, cur, i = [], [], 0
    while i < len(header):
        c = header[i]
        if c == "\\" and i + 1 < len(header):
            cur.append(header[i + 1])
            i += 2
            continue
        if c == "|":
            parts.append("".join(cur))
            if len(parts) == 7:
                # Extension escaping has different rules. Leave that entire
                # suffix untouched, including literal pipes and JSON escapes.
                parts.append(header[i + 1:])
                return parts
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    parts.append("".join(cur))
    return parts


def _unescape_ext(value: str) -> str:
    quoted = len(value) >= 2 and value[0] == '"' and value[-1] == '"'
    if quoted:
        value = value[1:-1]
    escapes = {"=": "=", "n": "\n", "r": "\r", "\\": "\\"}
    if quoted:
        escapes['"'] = '"'
    # One pass: an escaped backslash followed by n is a literal \\n, not LF.
    return re.sub(r'\\(.)', lambda m: escapes.get(m[1], m[0]), value)


def parse_cef(line: str) -> dict[str, Any]:
    """Parse one CEF record (optionally syslog-framed) into
    {"syslog": {...}, "header": {...}, "extension": {raw key: value},
     "fields": {label-resolved name: value}, "raw": line}.

    Raises ValueError when the line carries no `CEF:` marker.
    """
    raw = line.rstrip("\r\n")
    idx = raw.find("CEF:")
    if idx < 0:
        raise ValueError("not a CEF record (no 'CEF:' marker)")
    prefix, body = raw[:idx], raw[idx:]

    syslog: dict[str, Any] = {}
    m = re.match(r"^<(?P<pri>\d{1,3})>\s*(?P<ts>\S+)?\s*(?P<host>\S+)?\s*$", prefix)
    if m:
        syslog = {"pri": int(m.group("pri")), "timestamp": m.group("ts"), "host": m.group("host")}
    elif prefix.strip():
        syslog = {"prefix": prefix.strip()}

    parts = _split_header(body)
    if len(parts) < 8:
        raise ValueError(f"CEF header has {len(parts)} fields, expected 7 + extension")
    header = dict(zip(_HEADER_FIELDS, parts[:7]))
    header["cef_version"] = header["cef_version"].split(":", 1)[-1]
    try:
        header["severity"] = int(str(header["severity"]).strip())
    except ValueError:
        pass
    extension_text = "|".join(parts[7:])  # a value may legitimately contain '|'
    # The sample pretty-prints cs78's JSON over several lines; a real syslog
    # record is one line. Collapse whitespace runs so the tokenizer is stable.
    extension_text = extension_text.strip()

    extension: dict[str, str] = {}
    for m in _EXT_RE.finditer(extension_text):
        extension[m.group("key")] = _unescape_ext(m.group("val").strip())

    fields: dict[str, Any] = {}
    labels = {}
    for k, v in extension.items():
        lm = _LABEL_RE.match(k)
        if lm:
            labels[lm.group("base")] = v
    for k, v in extension.items():
        if _LABEL_RE.match(k):
            continue
        fields[labels.get(k, k)] = v
    return {"syslog": syslog, "header": header, "extension": extension,
            "fields": fields, "raw": raw}


# ── ShadowPlex semantics ────────────────────────────────────────────────────

# ShadowPlex ships ATT&CK *names*, not ids. Map the ones a decoy touch can
# produce; the agent still validates with correlate.mitre_validate before a
# finding cites one, and anything unmapped is carried as a name only.
TECHNIQUE_IDS: dict[str, str] = {
    "remote services.remote desktop protocol": "T1021.001",
    "remote services.smb/windows admin shares": "T1021.002",
    "remote services.ssh": "T1021.004",
    "remote services.vnc": "T1021.005",
    "network service discovery": "T1046",
    "network share discovery": "T1135",
    "remote system discovery": "T1018",
    "valid accounts": "T1078",
    "valid accounts.domain accounts": "T1078.002",
    "valid accounts.local accounts": "T1078.003",
    "brute force": "T1110",
    "brute force.password spraying": "T1110.003",
    "os credential dumping": "T1003",
}

_TS_FORMATS = (
    "%B %d %Y %H:%M:%S.%f UTC",
    "%B %d %Y %H:%M:%S UTC",
    "%b %d %Y %H:%M:%S.%f UTC",
    "%b %d %Y %H:%M:%S UTC",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
)


def to_utc_iso(value: Optional[str]) -> Optional[str]:
    """ShadowPlex `start=`/`end=` ("July 10 2026 11:36:57.130 UTC") or ISO →
    "YYYY-MM-DDTHH:MM:SSZ". Returns None when unparseable (the raw value is
    kept alongside by the caller)."""
    if not value:
        return None
    v = value.strip()
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(v, fmt).replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00")).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


def severity_from_cef(sev: Any) -> str:
    try:
        n = int(sev)
    except (TypeError, ValueError):
        return "medium"
    if n >= 7:
        return "high"
    if n >= 4:
        return "medium"
    return "low"


def _split_list(value: Optional[str]) -> list[str]:
    return [s.strip() for s in (value or "").split(",") if s.strip()]


def _int_or_none(v: Any) -> Optional[int]:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def is_service_interaction(parsed: dict) -> bool:
    """The per-protocol record carries `event_data` (cs78) — a JSON blob with
    the adversary's client fingerprint — and no srcIP/dstIP of its own."""
    f = parsed.get("fields", {})
    return "event_data" in f and "srcIP" not in f


def shadowplex_to_evidence(parsed: dict) -> dict[str, Any]:
    """Map a parsed fused-incident CEF record to the alert `evidence` dict.
    Keys are lowercase (respond.* placeholders are matched lowercased)."""
    h, f = parsed.get("header", {}), parsed.get("fields", {})
    techniques = _split_list(f.get("techniqueName"))
    ev: dict[str, Any] = {
        "incident_id": f.get("incidentID"),
        "category": f.get("cat"),
        "incident_status": f.get("incidentStatus"),
        "event_class_id": h.get("event_class_id"),
        "event_name": h.get("name"),
        "cef_severity": h.get("severity"),
        "vendor": h.get("device_vendor"),
        "product": h.get("device_product"),
        "product_version": h.get("device_version"),
        "attack_tactics": _split_list(f.get("tacticName")),
        "attack_techniques": techniques,
        "attack_technique_ids": [TECHNIQUE_IDS[t.lower()] for t in techniques if t.lower() in TECHNIQUE_IDS],
        # The touching host — the one TRUDI investigates and contains.
        "source_ip": f.get("srcIP"),
        # The decoy — the remote endpoint from the beachhead's point of view.
        "remote_ip": f.get("dstIP"),
        "remote_port": _int_or_none(f.get("dstPort")),
        "decoy_name": f.get("dstEndpointName"),
        "honey_credential": f.get("userIdAttempted"),
        "callback_url": f.get("callbackURL"),
        "start_utc": to_utc_iso(f.get("start")),
        "end_utc": to_utc_iso(f.get("end")),
        "start_raw": f.get("start"),
        "end_raw": f.get("end"),
        "timestamp_utc": to_utc_iso(f.get("end")) or to_utc_iso(f.get("start"))
                         or to_utc_iso((parsed.get("syslog") or {}).get("timestamp")),
    }
    return ev


def service_interaction_to_fingerprint(parsed: dict) -> dict[str, Any]:
    """Map the cs78 `event_data` JSON (adversary client fingerprint) to the
    `client_fingerprint` sub-dict: hostname, MAC, source port, service."""
    f = parsed.get("fields", {})
    raw = f.get("event_data") or ""
    try:
        data = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        data = {"_unparsed": raw}
    if not isinstance(data, dict):
        data = {"_unparsed": raw}
    svc = data.get("service_details") or {}
    if not isinstance(svc, dict):
        svc = {}
    fp = {
        "user_name": data.get("user_name"),
        "host_mac": svc.get("host_mac"),
        "source_port": _int_or_none(svc.get("remote_port")),
        "source_address": svc.get("remote_address"),
        "client_host_name": svc.get("client_host_name"),
        "client_host_ip": svc.get("client_host_ip"),
        "service_name": svc.get("service_name"),
        "service_port": _int_or_none(svc.get("service_port")),
        "auth_attempted": svc.get("auth_attempted"),
        "service_host_name": svc.get("service_host_name"),
        "service_host_address": svc.get("service_host_address"),
    }
    if "_unparsed" in data:
        fp["_unparsed"] = data["_unparsed"]
    return fp


def merge_fingerprint(evidence: dict[str, Any], fingerprint: dict[str, Any]) -> dict[str, Any]:
    """Fold the service-interaction fingerprint into the fused evidence.
    Fills `source_port` / `client_host_name` at top level (the kill/session
    discriminators) without overwriting fused-line values."""
    out = dict(evidence)
    out["client_fingerprint"] = fingerprint
    if out.get("source_port") is None and fingerprint.get("source_port") is not None:
        out["source_port"] = fingerprint["source_port"]
    if not out.get("client_host_name") and fingerprint.get("client_host_name"):
        out["client_host_name"] = fingerprint["client_host_name"]
    if not out.get("source_ip") and fingerprint.get("source_address"):
        out["source_ip"] = fingerprint["source_address"]
    if not out.get("remote_ip") and fingerprint.get("service_host_address"):
        out["remote_ip"] = fingerprint["service_host_address"]
    if out.get("remote_port") is None and fingerprint.get("service_port") is not None:
        out["remote_port"] = fingerprint["service_port"]
    return out


def summarize(evidence: dict[str, Any]) -> str:
    cred = evidence.get("honey_credential")
    cred_s = f" presenting credential {cred!r}" if cred else ""
    tactics = ",".join(evidence.get("attack_tactics") or []) or "?"
    host = evidence.get("client_host_name")
    host_s = f" ({host})" if host else ""
    return (f"{DETECTOR}: {evidence.get('source_ip')}{host_s} touched decoy "
            f"{evidence.get('decoy_name') or evidence.get('remote_ip')} "
            f"{evidence.get('remote_ip')}:{evidence.get('remote_port')}{cred_s} "
            f"[{evidence.get('category')}; {tactics}; incident {evidence.get('incident_id')}]")


SUGGESTED_PIVOT_TOOLS = [
    # The decoy belongs to the deception platform; the pivot is the SOURCE host.
    "velo.collect_artifact(Linux.Network.Netstat)   # find the flow to remote_ip:remote_port and its pid",
    "velo.collect_artifact(Linux.Sys.Pslist)        # the owning process + lineage",
    "velo.collect_artifact(Linux.Sys.ProcessOpenFiles)",
    "live.recent_logins                               # session binding for any principal claim",
    "misc.knowns_pattern_generate(reference_set=[honey_credential])  # hunt the breadcrumb on the source host",
    "correlate.mitre_validate(attack_technique_ids[*])",
]


def build_alert(evidence: dict[str, Any], *, case_id: str, seq: int,
                client_id: Optional[str], raw_lines: list[str],
                client_resolution: Optional[dict] = None,
                alert_id: Optional[str] = None) -> dict[str, Any]:
    """The alert record `bin/trudi-velo-watcher.py` would write, plus the
    CEF-specific `source`, `raw_cef` and `client_resolution` fields."""
    ts = evidence.get("timestamp_utc") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ev = dict(evidence)
    ev["timestamp_utc"] = ts
    if client_id:
        ev["ClientId"] = client_id
    return {
        "alert_id": alert_id or str(uuid.uuid4()),
        "seq": seq,
        "case_id": case_id,
        "client_id": client_id,
        "hostname": evidence.get("client_host_name"),
        "timestamp_utc": ts,
        "detector": DETECTOR,
        "severity": severity_from_cef(evidence.get("cef_severity")),
        "summary": summarize(evidence),
        "evidence": ev,
        "suggested_pivot_tools": list(SUGGESTED_PIVOT_TOOLS),
        "consumed": False,
        "source": SOURCE_TAG,
        "raw_cef": list(raw_lines),
        "client_resolution": client_resolution or {"method": "none", "matched": False},
    }


# ── Velociraptor client resolution (pure matching; the query runs elsewhere) ─

def _host_labels(name: Optional[str]) -> set[str]:
    """Candidate short names for a hostname: first DNS label, with and without
    the demo container prefix, lowercased. 'trudi-victim-a.lan-net' →
    {'trudi-victim-a', 'victim-a'}."""
    if not name:
        return set()
    label = str(name).strip().lower().split(".", 1)[0]
    out = {label}
    if label.startswith("trudi-"):
        out.add(label[len("trudi-"):])
    return out


def resolve_client(clients: list[dict], *, source_ip: Optional[str],
                   client_host_name: Optional[str],
                   source_map: Optional[dict] = None) -> dict[str, Any]:
    """Pick the Velociraptor client for the touching host.

    Order: (1) an explicit `source_map` {ip-or-hostname: client_id} from the
    case config (authoritative — for a topology where the beachhead reaches the
    server on a different network than the one it touched the decoy from, so
    `last_ip` does NOT match the CEF srcIP; empty-string values are ignored, not
    resolved to an empty client_id); (2) `last_ip` match on the CEF srcIP — a
    source IP is a far more reliable identifier than the sensor-supplied
    `client_host_name`, which on a deception decoy is frequently the **decoy's
    own** hostname (the decoy only knows what the RDP client's 4624 workstation
    field claimed), so matching on it would resolve the touch to the decoy
    itself; (3) hostname match against `os_info.hostname` / `hostname` as a last
    resort (most recent `last_seen_at` wins). Returns {"client_id", "method",
    "matched", "candidates"}.
    """
    source_map = {str(k).lower(): v for k, v in (source_map or {}).items() if v}
    for key in (source_ip, *sorted(_host_labels(client_host_name))):
        if key and str(key).lower() in source_map:
            return {"client_id": source_map[str(key).lower()], "method": "source_map",
                    "matched": True, "candidates": []}

    def _seen(c: dict) -> float:
        """Most-recent-wins key. Velociraptor's last_seen_at is an epoch
        (int/float); normalise to a float so numeric values sort numerically
        (not lexically — '100' must out-rank '50'). ISO strings are parsed to
        epoch; anything unparseable sorts oldest."""
        v = c.get("last_seen_at") or c.get("last_seen") or ""
        try:
            return float(v)
        except (TypeError, ValueError):
            try:
                return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
            except (TypeError, ValueError):
                return 0.0

    if source_ip:
        by_ip = [c for c in clients if str(c.get("last_ip") or "").split(":", 1)[0] == source_ip]
        if by_ip:
            best = sorted(by_ip, key=_seen)[-1]
            return {"client_id": best.get("client_id"), "method": "last_ip", "matched": True,
                    "candidates": [c.get("client_id") for c in by_ip]}

    wanted = _host_labels(client_host_name)
    by_host = [c for c in clients
               if _host_labels(c.get("hostname") or (c.get("os_info") or {}).get("hostname")) & wanted]
    if by_host:
        best = sorted(by_host, key=_seen)[-1]
        return {"client_id": best.get("client_id"), "method": "hostname", "matched": True,
                "candidates": [c.get("client_id") for c in by_host]}

    return {"client_id": None, "method": "none", "matched": False, "candidates": [],
            "note": (f"no Velociraptor client matched source_ip={source_ip!r} / "
                     f"client_host_name={client_host_name!r}; resolve via velo.list_clients "
                     f"or set monitoring/config.json cef_ingest.source_map")}


# ── CEF emission (used by the decoy emulator and by tests) ──────────────────

def _esc_header(v: Any) -> str:
    return str(v).replace("\\", "\\\\").replace("|", "\\|")


def _esc_ext(v: Any) -> str:
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\r", "\\r").replace("\n", "\\n")


def format_cef(*, vendor: str, product: str, version: str, event_class_id: str,
               name: str, severity: int, extension: list[tuple[str, Any]],
               quote_values: bool = True) -> str:
    """Render a CEF record. `extension` is an ordered list of (key, value) so
    csNLabel/csN pairs stay adjacent like the vendor's output; values with
    spaces are double-quoted when `quote_values` (the ShadowPlex style)."""
    header = "|".join(_esc_header(x) for x in (
        "CEF:0", vendor, product, version, event_class_id, name, severity))
    ext = []
    for k, v in extension:
        if v is None:
            continue
        s = _esc_ext(v)
        if quote_values and (" " in s or s == ""):
            s = '"' + s.replace('"', '\\"') + '"'
        ext.append(f"{k}={s}")
    return header + "|" + " ".join(ext)
