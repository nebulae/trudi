"""Tests for tools/enrichment.py — API key graceful degradation and mocked HTTP."""
import pytest
import httpx
from unittest.mock import patch, MagicMock


def _resp(status, data):
    m = MagicMock()
    m.status_code = status
    m.json.return_value = data
    return m


# httpx is imported inside each tool function, so patch at the httpx module level
HTTP_PATCH = "httpx.get"


class TestVtLookupHash:
    def test_no_key_degrades_gracefully(self, monkeypatch):
        monkeypatch.setattr("tools.enrichment.VT_API_KEY", None)
        from tools.enrichment import vt_lookup_hash
        r = vt_lookup_hash("abc123")
        assert r["success"] is False
        assert "API key" in r["error"]

    def test_hash_found(self, monkeypatch):
        monkeypatch.setattr("tools.enrichment.VT_API_KEY", "testkey")
        attrs = {
            "last_analysis_stats": {"malicious": 10, "undetected": 60},
            "meaningful_name": "malware.exe",
        }
        with patch(HTTP_PATCH, return_value=_resp(200, {"data": {"attributes": attrs}})):
            from tools.enrichment import vt_lookup_hash
            r = vt_lookup_hash("deadbeef" * 8)
        assert r["success"] is True
        assert r["found"] is True
        assert r["malicious"] == 10

    def test_hash_not_found_404(self, monkeypatch):
        monkeypatch.setattr("tools.enrichment.VT_API_KEY", "testkey")
        with patch(HTTP_PATCH, return_value=_resp(404, {})):
            from tools.enrichment import vt_lookup_hash
            r = vt_lookup_hash("clean_hash")
        assert r["success"] is True
        assert r["found"] is False


class TestVtLookupIp:
    def test_no_key_degrades(self, monkeypatch):
        monkeypatch.setattr("tools.enrichment.VT_API_KEY", None)
        from tools.enrichment import vt_lookup_ip
        r = vt_lookup_ip("1.2.3.4")
        assert r["success"] is False

    def test_ip_lookup(self, monkeypatch):
        monkeypatch.setattr("tools.enrichment.VT_API_KEY", "testkey")
        attrs = {"last_analysis_stats": {"malicious": 5, "undetected": 70}}
        with patch(HTTP_PATCH, return_value=_resp(200, {"data": {"attributes": attrs}})):
            from tools.enrichment import vt_lookup_ip
            r = vt_lookup_ip("1.2.3.4")
        assert r["success"] is True
        assert r["ip"] == "1.2.3.4"


class TestVtLookupDomain:
    def test_no_key_degrades(self, monkeypatch):
        monkeypatch.setattr("tools.enrichment.VT_API_KEY", None)
        from tools.enrichment import vt_lookup_domain
        r = vt_lookup_domain("evil.com")
        assert r["success"] is False

    def test_domain_lookup(self, monkeypatch):
        monkeypatch.setattr("tools.enrichment.VT_API_KEY", "testkey")
        attrs = {"last_analysis_stats": {"malicious": 3, "undetected": 80}}
        with patch(HTTP_PATCH, return_value=_resp(200, {"data": {"attributes": attrs}})):
            from tools.enrichment import vt_lookup_domain
            r = vt_lookup_domain("evil.com")
        assert r["success"] is True
        assert r["domain"] == "evil.com"


class TestAbuseIpdb:
    def test_no_key_degrades(self, monkeypatch):
        monkeypatch.setattr("tools.enrichment.ABUSEIPDB_API_KEY", None)
        from tools.enrichment import abuseipdb_check
        r = abuseipdb_check("1.2.3.4")
        assert r["success"] is False
        assert "API key" in r["error"]

    def test_ip_check(self, monkeypatch):
        monkeypatch.setattr("tools.enrichment.ABUSEIPDB_API_KEY", "testkey")
        data = {"data": {"abuseConfidenceScore": 85, "totalReports": 10, "countryCode": "CN"}}
        with patch(HTTP_PATCH, return_value=_resp(200, data)):
            from tools.enrichment import abuseipdb_check
            r = abuseipdb_check("1.2.3.4")
        assert r["success"] is True
        assert r["abuse_confidence_score"] == 85
