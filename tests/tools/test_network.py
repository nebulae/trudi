"""Tests for tools/network.py."""
import pytest
from unittest.mock import patch, MagicMock

PCAP = "/captures/traffic.pcap"


@pytest.fixture(autouse=True)
def mock_run(run_ok):
    with patch("tools.network.run", return_value=run_ok) as m:
        yield m


class TestTcpdumpRead:
    def test_basic_read(self, mock_run):
        from tools.network import tcpdump_read
        tcpdump_read(PCAP)
        cmd = mock_run.call_args[0][0]
        assert "tcpdump" in cmd
        assert "-r" in cmd
        assert PCAP in cmd

    def test_with_filter(self, mock_run):
        from tools.network import tcpdump_read
        tcpdump_read(PCAP, filter_expr="tcp and port 443")
        cmd = mock_run.call_args[0][0]
        assert "tcp" in cmd
        assert "443" in cmd

    def test_count_applied(self, mock_run):
        from tools.network import tcpdump_read
        tcpdump_read(PCAP, count=50)
        cmd = mock_run.call_args[0][0]
        assert "-c" in cmd
        assert "50" in cmd

    def test_count_zero_omits_c_flag(self, mock_run):
        from tools.network import tcpdump_read
        tcpdump_read(PCAP, count=0)
        cmd = mock_run.call_args[0][0]
        assert "-c" not in cmd

    def test_output_path_evidence_blocked(self):
        from tools.network import tcpdump_read
        with pytest.raises(Exception):
            tcpdump_read(PCAP, output_path="/cases/srl/evidence/out.txt")


class TestTcpdumpExtract:
    def test_extract_http(self, mock_run):
        from tools.network import tcpdump_extract_http
        tcpdump_extract_http(PCAP)
        cmd = mock_run.call_args[0][0]
        assert "port 80" in " ".join(cmd) or "8080" in " ".join(cmd)

    def test_extract_dns(self, mock_run):
        from tools.network import tcpdump_extract_dns
        tcpdump_extract_dns(PCAP)
        cmd = mock_run.call_args[0][0]
        assert "port 53" in " ".join(cmd) or "53" in cmd

    def test_list_connections(self, mock_run):
        from tools.network import tcpdump_list_connections
        tcpdump_list_connections(PCAP)
        cmd = mock_run.call_args[0][0]
        assert "tcpdump" in cmd
        assert "-q" in cmd


class TestNgrepSearch:
    def test_basic_search(self, mock_run):
        from tools.network import ngrep_search
        ngrep_search(PCAP, "password")
        cmd = mock_run.call_args[0][0]
        assert "ngrep" in cmd
        assert "password" in cmd

    def test_case_insensitive_flag(self, mock_run):
        from tools.network import ngrep_search
        ngrep_search(PCAP, "test", case_insensitive=True)
        cmd = mock_run.call_args[0][0]
        assert "-i" in cmd

    def test_protocol_filter(self, mock_run):
        from tools.network import ngrep_search
        ngrep_search(PCAP, "test", protocol="tcp")
        cmd = mock_run.call_args[0][0]
        assert "tcp" in cmd


class TestTcpdumpExtractIps:
    def test_extracts_unique_ips(self):
        from tools.network import tcpdump_extract_ips
        fake_output = (
            b"IP 192.168.1.1.443 > 10.0.0.5.56789\n"
            b"IP 192.168.1.1.443 > 10.0.0.6.56790\n"
            b"IP 172.16.1.100.80 > 10.0.0.5.56791\n"
        )
        with patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(
                returncode=0, stdout=fake_output, stderr=b""
            )
            r = tcpdump_extract_ips(PCAP)
        assert r["success"] is True
        assert "192.168.1.1" in r["unique_ips"]
        assert "10.0.0.5" in r["unique_ips"]
        assert r["count"] >= 3

    def test_deduplicates_ips(self):
        from tools.network import tcpdump_extract_ips
        fake_output = b"192.168.1.1 192.168.1.1 192.168.1.1\n"
        with patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(
                returncode=0, stdout=fake_output, stderr=b""
            )
            r = tcpdump_extract_ips(PCAP)
        assert r["unique_ips"].count("192.168.1.1") == 1


class TestTcpdumpWriteFiltered:
    def test_evidence_output_blocked(self):
        from tools.network import tcpdump_write_filtered
        with pytest.raises(Exception):
            tcpdump_write_filtered(PCAP, "/cases/srl/evidence/filtered.pcap", "tcp")

    def test_safe_output_allowed(self, tmp_path, mock_run):
        from tools.network import tcpdump_write_filtered
        out = str(tmp_path / "filtered.pcap")
        tcpdump_write_filtered(PCAP, out, "host 10.0.0.1")
        cmd = mock_run.call_args[0][0]
        assert "-w" in cmd
        assert out in cmd


class TestTcpxtractStreams:
    def test_output_dir_safe(self, tmp_path, mock_run):
        from tools.network import tcpxtract_streams
        out = str(tmp_path / "streams")
        tcpxtract_streams(PCAP, out)
        cmd = mock_run.call_args[0][0]
        assert "tcpxtract" in cmd
        assert "-o" in cmd

    def test_evidence_output_blocked(self):
        from tools.network import tcpxtract_streams
        with pytest.raises(Exception):
            tcpxtract_streams(PCAP, "/cases/srl/evidence/streams")
