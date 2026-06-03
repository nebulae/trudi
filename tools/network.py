"""Network analysis tools — tcpdump, ngrep, pcap inspection."""
from typing import Optional
from fastmcp import FastMCP
from core import run, output_safe
from core.paths import assert_output_safe

mcp = FastMCP("network")


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
    filter_expr: BPF filter expression e.g. 'tcp and host 172.15.1.20' or 'port 443'.
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
    filter_expr: BPF filter e.g. 'host 172.15.1.20 and tcp'.
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
    raw = run(
        ["tcpdump", "-r", pcap_file, "-nn", "-A",
         "tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 8443"],
        needs_sudo=True,
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
        "_trudi_call_id": raw.get("_trudi_call_id"),
    }

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
