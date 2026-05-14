"""Network analysis tools — tcpdump, ngrep, pcap inspection."""
from typing import Optional
from fastmcp import FastMCP
from core import run
from core.paths import assert_output_safe

mcp = FastMCP("network")


@mcp.tool()
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
    if output_path:
        assert_output_safe(output_path)
    cmd = ["tcpdump", "-r", pcap_file, "-nn", "-tttt"]
    if count > 0:
        cmd += ["-c", str(count)]
    if filter_expr:
        cmd += filter_expr.split()
    return run(cmd, needs_sudo=True, timeout=120)


@mcp.tool()
def tcpdump_extract_http(pcap_file: str, output_path: Optional[str] = None) -> dict:
    """Extract HTTP traffic (ports 80, 8080, 8000, 8443) from a PCAP file."""
    if output_path:
        assert_output_safe(output_path)
    cmd = ["tcpdump", "-r", pcap_file, "-nn", "-A", "tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 8443"]
    return run(cmd, needs_sudo=True, timeout=120)


@mcp.tool()
def tcpdump_extract_dns(pcap_file: str) -> dict:
    """Extract DNS queries and responses from a PCAP file."""
    cmd = ["tcpdump", "-r", pcap_file, "-nn", "port 53"]
    return run(cmd, needs_sudo=True, timeout=60)


@mcp.tool()
def tcpdump_list_connections(pcap_file: str) -> dict:
    """Extract unique source/destination IP pairs and ports from a PCAP."""
    cmd = ["tcpdump", "-r", pcap_file, "-nn", "-q", "tcp or udp"]
    return run(cmd, needs_sudo=True, timeout=120)


@mcp.tool()
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
    cmd = ["ngrep", "-I", pcap_file]
    if case_insensitive:
        cmd.append("-i")
    cmd.append(pattern)
    if protocol:
        cmd.append(protocol)
    return run(cmd, needs_sudo=True, timeout=120)


@mcp.tool()
def tcpdump_extract_ips(pcap_file: str) -> dict:
    """
    Extract all unique IP addresses from a PCAP.
    Returns sorted unique source and destination addresses.
    """
    import subprocess
    try:
        proc = subprocess.run(
            ["tcpdump", "-r", pcap_file, "-nn", "-q"],
            capture_output=True, timeout=120
        )
        output = proc.stdout.decode("utf-8", errors="replace")
        import re
        ips = set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', output))
        return {
            "success": proc.returncode == 0,
            "pcap": pcap_file,
            "unique_ips": sorted(ips),
            "count": len(ips),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
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
    assert_output_safe(output_pcap)
    cmd = ["tcpdump", "-r", pcap_file, "-w", output_pcap] + filter_expr.split()
    return run(cmd, needs_sudo=True, timeout=300, output_dir=output_pcap)


@mcp.tool()
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
    assert_output_safe(output_dir)
    import os
    os.makedirs(output_dir, exist_ok=True)
    cmd = ["tcpxtract", "-f", pcap_file, "-o", output_dir]
    return run(cmd, needs_sudo=True, timeout=300, output_dir=output_dir)
