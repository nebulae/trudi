"""Network analysis tools — tcpdump, ngrep, pcap inspection."""
from typing import Optional
from fastmcp import FastMCP
from core import run, run_with_output_file, output_safe
from core.paths import assert_output_safe

mcp = FastMCP("network")


def _run_tcpdump_ascii(cmd: list[str], timeout: int) -> dict:
    """Run a large tcpdump ASCII extraction without the normal stdout cap."""
    import os
    import tempfile

    fh = tempfile.NamedTemporaryFile(
        prefix="trudi-tcpdump-", suffix=".txt", dir="/tmp", delete=False
    )
    path = fh.name
    fh.close()
    raw = run_with_output_file(cmd, output_path=path, needs_sudo=True, timeout=timeout)
    if raw.get("success"):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                raw["stdout"] = f.read()
        except OSError as e:
            raw["success"] = False
            raw["stderr"] = f"failed to read tcpdump output {path}: {e}"
    try:
        os.unlink(path)
    except OSError:
        pass
    return raw


def _record_structured_marker(tool_name: str, raw: dict, summary: dict | None = None) -> int | None:
    """Record the MCP wrapper name, not only the underlying tcpdump command."""
    try:
        import json
        from core.execution_log import log

        raw_id = raw.get("_trudi_call_id")
        return log.record_tool_call(
            cmd=f"<py>:{tool_name}",
            success=bool(raw.get("success")),
            truncated=False,
            retries=0,
            exit_code=0 if raw.get("success") else int(raw.get("exit_code", 1) or 1),
            stderr=raw.get("stderr", ""),
            elapsed_seconds=0.0,
            stdout_excerpt=json.dumps(summary or {}, sort_keys=True)[:600],
            input_call_ids=[raw_id] if raw_id else None,
        )
    except Exception as e:
        import sys
        print(f"[TRUDI WARN] structured marker failed for {tool_name}: {e}",
              file=sys.stderr)
        return None


@mcp.tool()
@output_safe
def tcpdump_read(
    pcap_file: str,
    filter_expr: Optional[str] = None,
    count: int = 100,
    output_path: Optional[str] = None,
) -> dict:
    """
    Read and display packets from a PCAP file.
    filter_expr: BPF filter expression e.g. 'tcp and host 192.0.2.10' or 'port 443'.
    count: maximum number of packets to display (default 100; 0 = all).
    """
    cmd = ["tcpdump", "-r", pcap_file, "-nn", "-tttt"]
    if count > 0:
        cmd += ["-c", str(count)]
    if filter_expr:
        cmd += filter_expr.split()
    return run(cmd, needs_sudo=True, timeout=120)


@mcp.tool()
@output_safe
def tcpdump_extract_http(pcap_file: str, output_path: Optional[str] = None) -> dict:
    """Extract HTTP traffic (ports 80, 8080, 8000, 8443) from a PCAP file."""
    cmd = ["tcpdump", "-r", pcap_file, "-nn", "-A", "tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 8443"]
    return run(cmd, needs_sudo=True, timeout=120)


@mcp.tool()
@output_safe
def tcpdump_extract_dns(pcap_file: str) -> dict:
    """Extract DNS queries and responses from a PCAP file."""
    cmd = ["tcpdump", "-r", pcap_file, "-nn", "port 53"]
    return run(cmd, needs_sudo=True, timeout=60)


@mcp.tool()
@output_safe
def tcpdump_list_connections(pcap_file: str) -> dict:
    """Extract unique source/destination IP pairs and ports from a PCAP."""
    cmd = ["tcpdump", "-r", pcap_file, "-nn", "-q", "tcp or udp"]
    return run(cmd, needs_sudo=True, timeout=120)


@mcp.tool()
@output_safe
def ngrep_search(
    pcap_file: str,
    pattern: str,
    protocol: Optional[str] = None,
    case_insensitive: bool = True,
) -> dict:
    """
    Search PCAP payload data for a string or regex pattern using ngrep.
    pattern: string or regex to match in packet payloads.
    protocol: 'tcp', 'udp', 'icmp' — omit for all.
    Useful for finding credentials, commands, or malware C2 beacons in traffic.
    """
    # -q suppresses the per-packet '#' progress dump. Without it, ngrep prints
    # one '#' per inspected packet, and on a large pcap that progress noise
    # fills the captured stdout buffer before any actual match line is emitted
    # — causing real matches to be invisible under `truncated: true` output.
    cmd = ["ngrep", "-q", "-I", pcap_file]
    if case_insensitive:
        cmd.append("-i")
    cmd.append(pattern)
    if protocol:
        cmd.append(protocol)
    return run(cmd, needs_sudo=True, timeout=120)


@mcp.tool()
@output_safe
def tcpdump_extract_ips(pcap_file: str) -> dict:
    """
    Extract all unique IP addresses from a PCAP.
    Returns sorted unique source and destination addresses.
    """
    import re
    result = run(["tcpdump", "-r", pcap_file, "-nn", "-q"], needs_sudo=True, timeout=120)
    if not result["success"]:
        return {
            "success": False,
            "pcap": pcap_file,
            "error": result.get("stderr", ""),
            "_trudi_call_id": result.get("_trudi_call_id"),
        }
    ips = set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', result.get("stdout", "")))
    return {
        "success": True,
        "pcap": pcap_file,
        "unique_ips": sorted(ips),
        "count": len(ips),
        "_trudi_call_id": result.get("_trudi_call_id"),
    }


@mcp.tool()
@output_safe
def tcpdump_write_filtered(
    pcap_file: str,
    output_pcap: str,
    filter_expr: str,
) -> dict:
    """
    Write a filtered subset of packets to a new PCAP file.
    filter_expr: BPF filter e.g. 'host 192.0.2.10 and tcp'.
    output_pcap: path for the new PCAP (must be in exports/ or analysis/).
    """
    cmd = ["tcpdump", "-r", pcap_file, "-w", output_pcap] + filter_expr.split()
    return run(cmd, needs_sudo=True, timeout=300, output_dir=output_pcap)


@mcp.tool()
@output_safe
def http_session_inventory(
    pcap_file: str,
    output_path: Optional[str] = None,
) -> dict:
    """
    Structured extraction of every HTTP session identity artifact from a PCAP.
    Returns a deterministic table — prefer this over keyword `ngrep` searches
    when hunting identity, session, or attribution data in plaintext HTTP.

    Extracts and groups by (source_ip, host, user_agent):
        - All Cookie names and values (Yahoo Y/T/B, Gmail gmailchat/NID/SID,
          Hotmail MSPAuth, AOL a/b, Facebook c_user/login_x, etc.)
        - URL auth parameters from GET/POST request lines
          (login=, email=, user=, gausr=, account=, screenname=, sn=)
        - Authorization headers
        - Email-like strings in URL paths/queries

    Output is a structured dict rather than raw text — no keyword guessing,
    no missed fields. Use this as the first identity-extraction step on any
    PCAP investigation; only fall back to ngrep for ad-hoc keyword lookups.

    output_path: optional path under analysis/ or exports/ to persist the
    structured table as JSON.
    """
    import json
    import re as _re

    # Pull HTTP traffic in ASCII; the same flags as tcpdump_extract_http but
    # we parse the output rather than return it raw.
    raw = _run_tcpdump_ascii(
        ["tcpdump", "-r", pcap_file, "-nn", "-A",
         "tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 8443"],
        timeout=180,
    )
    if not raw.get("success"):
        return {
            "success": False,
            "pcap": pcap_file,
            "error": raw.get("stderr", "tcpdump failed"),
            "_trudi_call_id": raw.get("_trudi_call_id"),
        }

    text = raw.get("stdout", "") or ""

    # Group requests by (src_ip, host, user_agent) — each (src, host, UA)
    # tuple is roughly one browser session.
    src_re = _re.compile(r"IP (\d{1,3}(?:\.\d{1,3}){3})\.\d+ > \d{1,3}(?:\.\d{1,3}){3}\.\d+")
    host_re = _re.compile(r"Host:\s*([^\r\n]+)", _re.IGNORECASE)
    ua_re = _re.compile(r"User-Agent:\s*([^\r\n]+)", _re.IGNORECASE)
    cookie_re = _re.compile(r"Cookie:\s*([^\r\n]+)", _re.IGNORECASE)
    set_cookie_re = _re.compile(r"Set-Cookie:\s*([^\r\n]+)", _re.IGNORECASE)
    auth_re = _re.compile(r"Authorization:\s*([^\r\n]+)", _re.IGNORECASE)
    reqline_re = _re.compile(r"(GET|POST|HEAD|PUT|DELETE)\s+(\S+)\s+HTTP/", _re.IGNORECASE)
    url_param_re = _re.compile(
        r"[?&](login|email|username|user|gausr|account|screenname|sn|usr|uname)=([^&\s]+)",
        _re.IGNORECASE,
    )
    email_re = _re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

    # Block requests on blank-line boundaries (best-effort for tcpdump -A output)
    blocks = _re.split(r"\n(?=\d{2}:\d{2}:\d{2})", text)

    sessions: dict[tuple, dict] = {}

    for block in blocks:
        src_m = src_re.search(block)
        host_m = host_re.search(block)
        ua_m = ua_re.search(block)
        if not src_m:
            continue
        src = src_m.group(1)
        host = host_m.group(1).strip() if host_m else "(no_host)"
        ua = ua_m.group(1).strip() if ua_m else "(no_ua)"
        key = (src, host, ua)

        if key not in sessions:
            sessions[key] = {
                "source_ip": src,
                "host": host,
                "user_agent": ua,
                "cookies": {},          # cookie_name -> set of values
                "set_cookies": {},
                "url_params": {},       # param_name -> set of values
                "auth_headers": [],
                "request_paths": [],
                "emails": [],
            }
        sess = sessions[key]

        for m in cookie_re.finditer(block):
            for kv in m.group(1).split(";"):
                kv = kv.strip()
                if "=" in kv:
                    name, value = kv.split("=", 1)
                    sess["cookies"].setdefault(name.strip(), set()).add(value.strip())

        for m in set_cookie_re.finditer(block):
            cookie_str = m.group(1).split(";")[0].strip()
            if "=" in cookie_str:
                name, value = cookie_str.split("=", 1)
                sess["set_cookies"].setdefault(name.strip(), set()).add(value.strip())

        for m in auth_re.finditer(block):
            val = m.group(1).strip()
            if val not in sess["auth_headers"]:
                sess["auth_headers"].append(val)

        for m in reqline_re.finditer(block):
            path = m.group(2)
            if path not in sess["request_paths"]:
                sess["request_paths"].append(path)
            for pm in url_param_re.finditer(path):
                sess["url_params"].setdefault(pm.group(1).lower(), set()).add(pm.group(2))

        for em in email_re.findall(block):
            if em not in sess["emails"]:
                sess["emails"].append(em)

    # Serialise sets to sorted lists for JSON
    out_sessions = []
    for sess in sessions.values():
        out_sessions.append({
            "source_ip": sess["source_ip"],
            "host": sess["host"],
            "user_agent": sess["user_agent"],
            "cookies": {k: sorted(v) for k, v in sess["cookies"].items()},
            "set_cookies": {k: sorted(v) for k, v in sess["set_cookies"].items()},
            "url_params": {k: sorted(v) for k, v in sess["url_params"].items()},
            "auth_headers": sess["auth_headers"],
            "request_paths": sess["request_paths"][:50],
            "emails": sess["emails"],
        })

    # Identity-bearing summary: every distinct cookie/param/email value seen
    all_cookie_values: dict[str, set] = {}
    all_url_param_values: dict[str, set] = {}
    all_emails: set = set()
    for sess in sessions.values():
        for k, vs in sess["cookies"].items():
            all_cookie_values.setdefault(k, set()).update(vs)
        for k, vs in sess["url_params"].items():
            all_url_param_values.setdefault(k, set()).update(vs)
        all_emails.update(sess["emails"])

    summary = {
        "session_count": len(sessions),
        "unique_cookie_names": sorted(all_cookie_values.keys()),
        "unique_cookie_values_by_name": {k: sorted(v) for k, v in all_cookie_values.items()},
        "unique_url_param_names": sorted(all_url_param_values.keys()),
        "unique_url_param_values_by_name": {k: sorted(v) for k, v in all_url_param_values.items()},
        "unique_emails": sorted(all_emails),
    }

    result = {
        "success": True,
        "pcap": pcap_file,
        "summary": summary,
        "sessions": out_sessions,
        "raw_call_id": raw.get("_trudi_call_id"),
    }
    marker_id = _record_structured_marker(
        "net_http_session_inventory",
        raw,
        {"session_count": summary["session_count"],
         "unique_emails": summary["unique_emails"][:10]},
    )
    result["_trudi_call_id"] = marker_id or raw.get("_trudi_call_id")

    if output_path:
        assert_output_safe(output_path)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        result["output_path"] = output_path

    return result


def _packet_blocks(text: str) -> list[str]:
    """Split tcpdump -tttt -A output into packet-ish blocks."""
    import re as _re

    starts = [
        m.start()
        for m in _re.finditer(
            r"(?m)^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+IP\s+",
            text,
        )
    ]
    if not starts:
        return [b for b in _re.split(r"\n(?=\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+IP\s+)", text) if b.strip()]
    starts.append(len(text))
    return [text[starts[i]:starts[i + 1]] for i in range(len(starts) - 1)]


def _roster_index(roster_names: Optional[list[str]]) -> dict[str, list[str]]:
    if not roster_names:
        return {}
    try:
        from tools.misc import _derive_person_variants
    except Exception:
        _derive_person_variants = None

    out: dict[str, list[str]] = {}
    for name in roster_names:
        raw = (name or "").strip()
        if not raw:
            continue
        if _derive_person_variants:
            variants = _derive_person_variants(raw)
        else:
            parts = raw.lower().split()
            variants = parts[:]
            if len(parts) >= 2:
                first, last = parts[0], parts[-1]
                variants += [first + last, first[0] + last, last + first[0]]
        out[raw] = sorted({v.lower() for v in variants if len(v) >= 3})
    return out


def _match_roster(value: str, roster: dict[str, list[str]]) -> list[str]:
    import re as _re

    value_l = value.lower()
    prefix = value_l.split("@", 1)[0]
    compact = _re.sub(r"[^a-z0-9]", "", value_l)
    prefix_compact = _re.sub(r"[^a-z0-9]", "", prefix)
    matches: list[str] = []
    for name, variants in roster.items():
        for variant in variants:
            v_compact = _re.sub(r"[^a-z0-9]", "", variant)
            if (
                variant == prefix
                or variant == value_l
                or v_compact == prefix_compact
                or (len(v_compact) >= 5 and v_compact in compact)
            ):
                matches.append(name)
                break
    return sorted(matches)


@mcp.tool()
@output_safe
def pcap_identity_timeline(
    pcap_file: str,
    source_ip: Optional[str] = None,
    roster_names: Optional[list[str]] = None,
    output_path: Optional[str] = None,
) -> dict:
    """
    Build a deterministic timeline of identity-bearing PCAP artifacts.

    This is the attribution-safe companion to ad-hoc ngrep searches: it extracts
    HTTP query identities, identity cookies, email addresses, and simple YMSG
    profile/login fields, then cross-references them against roster-derived
    username variants. Use it before attributing a person from plaintext PCAP
    traffic, especially when multiple accounts appear on the same source host.

    source_ip: optional source IP to focus on after extraction.
    roster_names: optional list such as ["Amy Smith", "Johnny Coach"].
    output_path: optional JSON path under analysis/ or exports/.
    """
    import json
    import re as _re
    from urllib.parse import parse_qsl, unquote_plus, urlsplit

    raw = _run_tcpdump_ascii(
        [
            "tcpdump", "-r", pcap_file, "-nn", "-tttt", "-A",
            "tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 8443 or tcp port 5050",
        ],
        timeout=180,
    )
    if not raw.get("success"):
        return {
            "success": False,
            "pcap": pcap_file,
            "error": raw.get("stderr", "tcpdump failed"),
            "_trudi_call_id": raw.get("_trudi_call_id"),
        }

    roster = _roster_index(roster_names)
    host_re = _re.compile(r"Host:\s*([^\r\n]+)", _re.IGNORECASE)
    ua_re = _re.compile(r"User-Agent:\s*([^\r\n]+)", _re.IGNORECASE)
    req_re = _re.compile(r"(GET|POST|HEAD|PUT|DELETE)\s+(\S+)\s+HTTP/", _re.IGNORECASE)
    cookie_re = _re.compile(r"(?:Cookie|Set-Cookie):\s*([^\r\n]+)", _re.IGNORECASE)
    email_re = _re.compile(
        r"\b[A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,62}[A-Za-z0-9])?"
        r"@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b"
    )
    ip_re = _re.compile(
        r"(?m)^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+IP\s+"
        r"(?P<src>\d{1,3}(?:\.\d{1,3}){3})\.(?P<src_port>\d+)\s+>\s+"
        r"(?P<dst>\d{1,3}(?:\.\d{1,3}){3})\.(?P<dst_port>\d+):"
    )
    identity_params = {
        "login", "email", "username", "user", "gausr", "account",
        "screenname", "sn", "usr", "uname", "req0_value",
    }
    identity_cookies = {
        "gmailchat", "ol_session", "ys", "y", "t", "f", "mspauth",
        "c_user", "login_x",
    }

    rows: list[dict] = []

    def add_row(order: int, header: _re.Match, block: str, kind: str,
                field: str, value: str) -> None:
        decoded = unquote_plus(value.strip())
        if not decoded:
            return
        matches = _match_roster(decoded, roster)
        confidence = "high" if matches and (kind in {"url_param", "cookie", "email"}) else (
            "medium" if matches else "low"
        )
        excerpt = " ".join(block.split())[:240]
        rows.append({
            "order": order,
            "timestamp": header.group("ts"),
            "source_ip": header.group("src"),
            "source_port": int(header.group("src_port")),
            "destination_ip": header.group("dst"),
            "destination_port": int(header.group("dst_port")),
            "host": (host_re.search(block).group(1).strip()
                     if host_re.search(block) else ""),
            "user_agent": (ua_re.search(block).group(1).strip()
                           if ua_re.search(block) else ""),
            "identity_type": kind,
            "field": field,
            "value": decoded,
            "roster_matches": matches,
            "confidence": confidence,
            "evidence_excerpt": excerpt,
        })

    for order, block in enumerate(_packet_blocks(raw.get("stdout", "") or ""), start=1):
        header = ip_re.search(block)
        if not header:
            continue
        if source_ip and header.group("src") != source_ip:
            continue
        decoded_block = unquote_plus(block)

        for req_m in req_re.finditer(block):
            path = req_m.group(2)
            split = urlsplit(path)
            for key, value in parse_qsl(split.query, keep_blank_values=False):
                if key.lower() in identity_params:
                    add_row(order, header, block, "url_param", key.lower(), value)

        for key, value in _re.findall(
            r"(?:^|[?&;\s])"
            r"(login|email|username|user|gausr|account|screenname|sn|usr|uname|req0_value)"
            r"=([^&;\s]+)",
            decoded_block,
            flags=_re.IGNORECASE,
        ):
            add_row(order, header, block, "param", key.lower(), value)

        for cookie_m in cookie_re.finditer(block):
            cookie_blob = cookie_m.group(1)
            for part in cookie_blob.split(";"):
                if "=" not in part:
                    continue
                name, value = part.strip().split("=", 1)
                name_l = name.strip().lower()
                decoded_value = unquote_plus(value)
                if name_l in identity_cookies or email_re.search(decoded_value):
                    add_row(order, header, block, "cookie", name.strip(), value)

        for email in email_re.findall(decoded_block):
            add_row(order, header, block, "email", "payload", email)

        if "YMSG" in block:
            for field, value in _re.findall(r"(1|216|254)\.\.([A-Za-z][A-Za-z0-9._-]{2,})", block):
                add_row(order, header, block, "ymsg_field", field, value)

    seen: set[tuple] = set()
    deduped: list[dict] = []
    for row in rows:
        key = (
            row["timestamp"], row["source_ip"], row["host"], row["identity_type"],
            row["field"], row["value"],
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)

    matched_by_person: dict[str, list[str]] = {}
    identities_by_source: dict[str, list[str]] = {}
    for row in deduped:
        identities_by_source.setdefault(row["source_ip"], [])
        if row["value"] not in identities_by_source[row["source_ip"]]:
            identities_by_source[row["source_ip"]].append(row["value"])
        for name in row["roster_matches"]:
            matched_by_person.setdefault(name, [])
            if row["value"] not in matched_by_person[name]:
                matched_by_person[name].append(row["value"])

    result = {
        "success": True,
        "pcap": pcap_file,
        "source_ip": source_ip,
        "summary": {
            "identity_artifact_count": len(deduped),
            "roster_match_count": sum(1 for r in deduped if r["roster_matches"]),
            "matched_by_person": matched_by_person,
            "identities_by_source_ip": identities_by_source,
        },
        "identities": deduped,
        "raw_call_id": raw.get("_trudi_call_id"),
    }
    marker_id = _record_structured_marker(
        "net_pcap_identity_timeline",
        raw,
        {
            "identity_artifact_count": result["summary"]["identity_artifact_count"],
            "roster_match_count": result["summary"]["roster_match_count"],
            "matched_by_person": matched_by_person,
        },
    )
    result["_trudi_call_id"] = marker_id or raw.get("_trudi_call_id")

    if output_path:
        assert_output_safe(output_path)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        result["output_path"] = output_path

    return result


@mcp.tool()
@output_safe
def tcpxtract_streams(
    pcap_file: str,
    output_dir: str,
) -> dict:
    """
    Extract TCP streams from a PCAP file using tcpxtract.
    Reconstructs full TCP sessions as individual files — useful for recovering
    transferred documents, executables, or web content from captured traffic.
    output_dir: destination for extracted stream files.
    """
    import os
    os.makedirs(output_dir, exist_ok=True)
    cmd = ["tcpxtract", "-f", pcap_file, "-o", output_dir]
    return run(cmd, needs_sudo=True, timeout=300, output_dir=output_dir)
