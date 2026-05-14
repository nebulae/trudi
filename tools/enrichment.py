"""IOC enrichment — VirusTotal, AbuseIPDB, machinae. Degrade gracefully without API keys."""
import os
from typing import Optional
from fastmcp import FastMCP

mcp = FastMCP("enrichment")

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")


def _no_key(service: str) -> dict:
    return {
        "success": False,
        "error": f"{service} API key not configured. Set {service.upper().replace(' ', '_')}_API_KEY environment variable.",
    }


@mcp.tool()
def vt_lookup_hash(file_hash: str) -> dict:
    """
    Look up a file hash (MD5/SHA1/SHA256) on VirusTotal.
    Returns detection ratio, engine results, and file metadata.
    Requires VIRUSTOTAL_API_KEY environment variable.
    """
    if not VT_API_KEY:
        return _no_key("VirusTotal")
    try:
        import httpx
        resp = httpx.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": VT_API_KEY},
            timeout=30,
        )
        if resp.status_code == 404:
            return {"success": True, "found": False, "hash": file_hash, "message": "Not found in VirusTotal."}
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "success": True,
            "found": True,
            "hash": file_hash,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": sum(stats.values()),
            "names": attrs.get("names", [])[:10],
            "type_description": attrs.get("type_description"),
            "first_submission": attrs.get("first_submission_date"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "full_stats": stats,
        }
    except Exception as e:
        return {"success": False, "error": str(e), "hash": file_hash}


@mcp.tool()
def vt_lookup_ip(ip_address: str) -> dict:
    """
    Look up an IP address on VirusTotal.
    Returns reputation score, country, ASN, and detection history.
    Requires VIRUSTOTAL_API_KEY environment variable.
    """
    if not VT_API_KEY:
        return _no_key("VirusTotal")
    try:
        import httpx
        resp = httpx.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
            headers={"x-apikey": VT_API_KEY},
            timeout=30,
        )
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "success": True,
            "ip": ip_address,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "country": attrs.get("country"),
            "asn": attrs.get("asn"),
            "as_owner": attrs.get("as_owner"),
            "reputation": attrs.get("reputation"),
            "tags": attrs.get("tags", []),
            "full_stats": stats,
        }
    except Exception as e:
        return {"success": False, "error": str(e), "ip": ip_address}


@mcp.tool()
def vt_lookup_domain(domain: str) -> dict:
    """
    Look up a domain on VirusTotal.
    Returns detection ratio, categories, and DNS resolutions.
    Requires VIRUSTOTAL_API_KEY environment variable.
    """
    if not VT_API_KEY:
        return _no_key("VirusTotal")
    try:
        import httpx
        resp = httpx.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VT_API_KEY},
            timeout=30,
        )
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "success": True,
            "domain": domain,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "categories": attrs.get("categories", {}),
            "reputation": attrs.get("reputation"),
            "registrar": attrs.get("registrar"),
            "creation_date": attrs.get("creation_date"),
            "last_dns_records": attrs.get("last_dns_records", [])[:5],
            "full_stats": stats,
        }
    except Exception as e:
        return {"success": False, "error": str(e), "domain": domain}


@mcp.tool()
def abuseipdb_check(ip_address: str, max_age_days: int = 90) -> dict:
    """
    Check an IP address against the AbuseIPDB database.
    Returns abuse confidence score, number of reports, country, and ISP.
    Requires ABUSEIPDB_API_KEY environment variable.
    """
    if not ABUSEIPDB_API_KEY:
        return _no_key("AbuseIPDB")
    try:
        import httpx
        resp = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip_address, "maxAgeInDays": max_age_days, "verbose": True},
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            timeout=30,
        )
        data = resp.json().get("data", {})
        return {
            "success": True,
            "ip": ip_address,
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "is_tor": data.get("isTor"),
            "is_whitelisted": data.get("isWhitelisted"),
            "last_reported": data.get("lastReportedAt"),
        }
    except Exception as e:
        return {"success": False, "error": str(e), "ip": ip_address}


@mcp.tool()
def machinae_lookup(indicator: str, indicator_type: Optional[str] = None) -> dict:
    """
    Look up an IOC (IP, domain, hash, URL) using machinae (multi-source OSINT tool).
    indicator_type: 'ipv4', 'fqdn', 'hash', 'url' — machinae auto-detects if omitted.
    machinae queries multiple free OSINT sources without requiring API keys.
    """
    from core import run
    cmd = ["machinae", indicator]
    if indicator_type:
        cmd += ["-t", indicator_type]
    return run(cmd, timeout=60)


@mcp.tool()
def enrichment_status() -> dict:
    """Check which enrichment services are currently configured (API keys present)."""
    return {
        "virustotal": VT_API_KEY is not None,
        "abuseipdb": ABUSEIPDB_API_KEY is not None,
        "machinae": True,  # no API key required
        "note": "Set VIRUSTOTAL_API_KEY and ABUSEIPDB_API_KEY env vars to enable full enrichment.",
    }
