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
            tcpdump_read(PCAP, output_path="/cases/example/evidence/out.txt")


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
    def test_extracts_unique_ips(self, mock_run):
        from tools.network import tcpdump_extract_ips
        mock_run.return_value = {
            "success": True,
            "stdout": (
                "IP 192.168.1.1.443 > 10.0.0.5.56789\n"
                "IP 192.168.1.1.443 > 10.0.0.6.56790\n"
                "IP 10.0.1.100.80 > 10.0.0.5.56791\n"
            ),
            "stderr": "",
            "exit_code": 0,
            "_trudi_call_id": 1,
        }
        r = tcpdump_extract_ips(PCAP)
        assert r["success"] is True
        assert "192.168.1.1" in r["unique_ips"]
        assert "10.0.0.5" in r["unique_ips"]
        assert r["count"] >= 3

    def test_deduplicates_ips(self, mock_run):
        from tools.network import tcpdump_extract_ips
        mock_run.return_value = {
            "success": True,
            "stdout": "192.168.1.1 192.168.1.1 192.168.1.1\n",
            "stderr": "",
            "exit_code": 0,
            "_trudi_call_id": 1,
        }
        r = tcpdump_extract_ips(PCAP)
        assert r["unique_ips"].count("192.168.1.1") == 1


class TestPcapIdentityTimeline:
    def test_matches_jcoachj_roster_identity_before_ymsg_amy(self, mock_run):
        from tools.network import pcap_identity_timeline
        raw = {
            "success": True,
            "stdout": (
                "2008-07-21 23:01:01.000000 IP 192.168.15.4.35796 > 74.125.19.104.80: Flags [P.]\n"
                "GET /calendar/render?gausr=jcoachj%40gmail.com HTTP/1.1\r\n"
                "Host: www.google.com\r\n"
                "User-Agent: Firefox\r\n"
                "Cookie: OL_SESSION=jcoachj%40gmail.com-cal; gmailchat=jcoachj%40gmail.com/475090\r\n\r\n"
                "2008-07-21 23:09:58.000000 IP 192.168.15.4.36518 > 66.163.181.179.5050: Flags [P.]\n"
                "YMSG....1..amy789smith..216..Amy..254..Smith\n"
            ),
            "stderr": "",
            "exit_code": 0,
            "_trudi_call_id": 7,
        }

        with patch("tools.network._run_tcpdump_ascii", return_value=raw):
            r = pcap_identity_timeline(
                PCAP,
                source_ip="192.168.15.4",
                roster_names=["Amy Smith", "Johnny Coach"],
            )

        assert r["success"] is True
        assert "Johnny Coach" in r["summary"]["matched_by_person"]
        assert "jcoachj@gmail.com" in r["summary"]["matched_by_person"]["Johnny Coach"]
        assert "Amy Smith" in r["summary"]["matched_by_person"]
        johnny = [
            row for row in r["identities"]
            if "Johnny Coach" in row["roster_matches"]
        ]
        amy = [
            row for row in r["identities"]
            if "Amy Smith" in row["roster_matches"]
        ]
        assert min(row["order"] for row in johnny) < min(row["order"] for row in amy)

    def test_records_structured_wrapper_marker(self, tmp_path, mock_run):
        from core.execution_log import ExecutionLog
        from tools.network import pcap_identity_timeline
        raw = {
            "success": True,
            "stdout": (
                "2008-07-21 23:01:01.000000 IP 192.168.15.4.35796 > 74.125.19.104.80: Flags [P.]\n"
                "GET /calendar/render?gausr=jcoachj%40gmail.com HTTP/1.1\r\n"
                "Host: www.google.com\r\n\r\n"
            ),
            "stderr": "",
            "exit_code": 0,
            "_trudi_call_id": 7,
        }
        log = ExecutionLog()
        log.configure("NET-PCAP", str(tmp_path / "trace.json"), save_session=False)

        with patch("tools.network._run_tcpdump_ascii", return_value=raw), \
             patch("core.execution_log.log", log):
            r = pcap_identity_timeline(PCAP, roster_names=["Johnny Coach"])

        assert r["_trudi_call_id"] != 7
        marker = log._entries[-1]
        assert marker["type"] == "tool_call"
        assert marker["cmd"] == "<py>:net_pcap_identity_timeline"
        assert marker["input_call_ids"] == [7]


class TestTcpdumpWriteFiltered:
    def test_evidence_output_blocked(self):
        from tools.network import tcpdump_write_filtered
        with pytest.raises(Exception):
            tcpdump_write_filtered(PCAP, "/cases/example/evidence/filtered.pcap", "tcp")

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
            tcpxtract_streams(PCAP, "/cases/example/evidence/streams")
