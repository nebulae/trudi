"""Tests for the read.* produced-output readers and assert_readable_output.

These close the gap that forced the agent to raw Bash for the content-read step
(most bash in observed runs) and made those reads uncitable — the failure
behind the subject-line-only recipient exoneration.
"""
import os
import pytest
from unittest.mock import patch

from core.paths import assert_readable_output
from core.execution_log import ExecutionLog


# ── path guard ────────────────────────────────────────────────────────────────
class TestAssertReadableOutput:
    def test_accepts_exports_analysis_reports(self, tmp_path):
        for seg in ("exports", "analysis", "reports"):
            f = tmp_path / seg / "x.csv"
            f.parent.mkdir(parents=True, exist_ok=True); f.write_text("a\n")
            assert assert_readable_output(str(f)) == os.path.realpath(str(f))

    def test_case_insensitive_segment(self, tmp_path):
        f = tmp_path / "Exports" / "x.csv"
        f.parent.mkdir(parents=True); f.write_text("a\n")
        # resolve_path_ci corrects Exports→exports where needed; segment match is ci
        assert assert_readable_output(str(f))

    def test_rejects_mnt_and_evidence(self, tmp_path):
        for bad in ("/mnt/vanko/Users/x/mail.pst", "/media/x", str(tmp_path / "evidence" / "d.E01")):
            with pytest.raises(ValueError):
                assert_readable_output(bad)

    def test_rejects_arbitrary_system_path(self):
        with pytest.raises(ValueError):
            assert_readable_output("/etc/passwd")


# ── read_output ────────────────────────────────────────────────────────────────
def _tool(fn):
    return getattr(fn, "fn", fn)  # unwrap @mcp.tool if wrapped


@pytest.fixture
def live_log(tmp_path):
    l = ExecutionLog()
    l.configure("READ-TEST", str(tmp_path / "trace.json"), save_session=False)
    l.record_dair_call("Collect", "", False, "", "", "stay", "")  # active phase
    with patch("core.execution_log.log", l):
        yield l


@pytest.fixture
def exports(tmp_path):
    d = tmp_path / "exports"; d.mkdir()
    return d


class TestReadOutput:
    def _csv(self, exports):
        f = exports / "evtx.csv"
        f.write_text(
            "RecordNumber,EventId,MapDescription,PayloadData1\n"
            "1,4624,Logon,noise\n"
            "2,4738,User account changed,DisplayName: Anthony Vanko\n"
            "3,4634,Logoff,other noise\n")
        return f

    def test_query_ranks_the_right_row_header_kept(self, live_log, exports):
        from tools.read_output import read_output
        f = self._csv(exports)
        r = _tool(read_output)(str(f), query="4738 Anthony")
        assert r["success"] is True
        assert r["body"].startswith("RecordNumber,EventId")   # header retained
        assert "4738" in r["body"] and "Anthony Vanko" in r["body"]
        assert "4624" not in r["body"] and "4634" not in r["body"]

    def test_columns_projection(self, live_log, exports):
        from tools.read_output import read_output
        f = self._csv(exports)
        r = _tool(read_output)(str(f), query="Anthony", columns="EventId,MapDescription")
        assert "DisplayName" not in r["body"]          # PayloadData1 projected out
        assert r["body"].split("\n")[0].replace(" ", "") == "EventId,MapDescription"
        assert "4738" in r["body"]

    def test_where_exact_filter(self, live_log, exports):
        from tools.read_output import read_output
        f = self._csv(exports)
        r = _tool(read_output)(str(f), where="EventId=4624")
        assert "4624" in r["body"] and "4738" not in r["body"]

    def test_evidence_path_structured_error(self, live_log):
        from tools.read_output import read_output
        r = _tool(read_output)("/mnt/vanko/Windows/System32/config/SYSTEM")
        assert r["success"] is False and "extract" in r["hint"].lower()

    def test_missing_file_structured_error(self, live_log, exports):
        from tools.read_output import read_output
        r = _tool(read_output)(str(exports / "nope.csv"))
        assert r["success"] is False and "not found" in r["error"]

    def test_citability_end_to_end(self, live_log, exports):
        from tools.read_output import read_output
        from tools._output_reader import _resolve_cited_output, _cited_query_terms
        f = self._csv(exports)
        r = _tool(read_output)(str(f), query="4738 Anthony")
        cid = r["_trudi_call_id"]
        assert cid and cid in live_log.index().by_call_id
        entry = live_log.index().by_call_id[cid]
        assert entry["cmd"].startswith("read.output --output ")
        assert entry.get("source") != "claude_code_bash"
        # reviewer re-expansion re-reads the same file with a finding's terms
        got = _resolve_cited_output(entry["cmd"], _cited_query_terms("EID 4738 Anthony Vanko"), 6000)
        assert "4738" in got and "Anthony Vanko" in got


# ── read_mail (body-level mail reads) ───────────────────────────────────────────
class TestReadMail:
    def _mbox(self, exports):
        maildir = exports / "mail"; maildir.mkdir()
        mb = maildir / "icloud.mbox"
        mb.write_text(
            "From vanko Sat Jun 18 16:27:01 2016\n"
            "From: Anthony Vanko <anthony.vanko@icloud.example>\n"
            "To: Nina <nina_kwai@qq.example>\n"
            "Subject: research paper\n\n"
            "Here is the sturgeon chemistry draft you asked for.\n\n"
            "From vanko Sat Jun 29 12:24:00 2016\n"
            "From: Anthony Vanko <anthony.vanko@icloud.example>\n"
            "To: Vladimir <vladimir.bulgakov@titan-biotech.example>\n"
            "Subject: files\n\n"
            "Encrypted container attached, all the research is on the usb.\n")
        return mb

    def test_recipient_field_returns_body(self, live_log, exports):
        from tools.read_output import read_mail
        mb = self._mbox(exports)
        r = _tool(read_mail)(str(mb), query="nina_kwai@qq.example", field="recipient")
        assert r["success"] is True and r["match_count"] == 1
        msg = r["messages"][0]
        assert "nina_kwai@qq.example" in msg["to"]
        assert "sturgeon" in msg["body"]           # BODY returned, not just subject
        assert r["_trudi_call_id"] in live_log.index().by_call_id

    def test_body_field_matches_content_not_subject(self, live_log, exports):
        from tools.read_output import read_mail
        mb = self._mbox(exports)
        r = _tool(read_mail)(str(mb), query="usb", field="body")
        assert r["match_count"] == 1
        assert "vladimir.bulgakov@titan-biotech.example" in r["messages"][0]["to"]

    def test_senders_roster(self, live_log, exports):
        from tools.read_output import read_mail
        r = _tool(read_mail)(str(self._mbox(exports)), mode="senders")
        assert any("nina_kwai@qq.example" in s for s, _ in r["senders"])

    def test_eml_directory(self, live_log, exports):
        from tools.read_output import read_mail
        d = exports / "mail_eml"; d.mkdir()
        (d / "m1.eml").write_text("From: a@x\nTo: nina_kwai@qq.example\nSubject: hi\n\nbody one\n")
        r = _tool(read_mail)(str(d), query="nina_kwai", field="recipient")
        assert r["match_count"] == 1 and "body one" in r["messages"][0]["body"]

    def test_citable_cmd_has_output_flag(self, live_log, exports):
        from tools.read_output import read_mail
        r = _tool(read_mail)(str(self._mbox(exports)), query="nina")
        entry = live_log.index().by_call_id[r["_trudi_call_id"]]
        assert entry["cmd"].startswith("read.mail -o ")

    def test_annotates_correspondent_roster_from_all_scanned(self, live_log,
                                                             exports):
        # Registry feeder: the roster covers EVERY scanned message — even with
        # a query that matches nothing — and marks the scan complete.
        from tools.read_output import read_mail
        r = _tool(read_mail)(str(self._mbox(exports)), query="zzz-no-match")
        entry = live_log.index().by_call_id[r["_trudi_call_id"]]
        oc = entry.get("observed_correspondents", [])
        assert any("nina_kwai@qq.example" in a for a in oc)
        assert any("vladimir.bulgakov@titan-biotech.example" in a for a in oc)
        assert entry.get("correspondents_partial") is False

    def test_rfc_bulk_headers_flag_the_sender(self, live_log, exports):
        # A2: a sender whose messages carry List-Unsubscribe / Precedence: bulk
        # is stamped in observed_correspondent_bulk regardless of its address
        # shape — so inbound volume is never read as engagement downstream.
        from tools.read_output import read_mail
        d = exports / "mail_bulk"; d.mkdir()
        (d / "n1.eml").write_text(
            "From: promo8x2k@esp.example\nTo: subject@mail.example\n"
            "List-Unsubscribe: <mailto:u@esp.example>\nSubject: deal 1\n\nad\n")
        (d / "n2.eml").write_text(
            "From: promo8x2k@esp.example\nTo: subject@mail.example\n"
            "Precedence: bulk\nSubject: deal 2\n\nad\n")
        (d / "h1.eml").write_text(
            "From: subject@mail.example\nTo: handler@far.example\nSubject: re\n\nreply\n")
        r = _tool(read_mail)(str(d), query="zzz-no-match")
        entry = live_log.index().by_call_id[r["_trudi_call_id"]]
        assert "promo8x2k@esp.example" in entry.get("observed_correspondent_bulk", [])
        # a normal two-way address is NOT flagged bulk
        assert "handler@far.example" not in entry.get("observed_correspondent_bulk", [])


class TestReadMailIntegrity:
    """K-3a/K-6: partial only when the scan was cut short; zero yield is
    retried, flagged, and never feeds the registry as complete; the cmd
    records HOW the store was read."""

    def _mbox(self, exports, n=5, senders=None):
        d = exports / "mailk"
        d.mkdir(exist_ok=True)
        msgs = []
        for i in range(n):
            fr = (senders or [f"s{i}@ext.example"])[i % len(senders or [1])]
            msgs.append(f"From x@x Thu Jan  1 00:00:0{i % 10} 2026\nFrom: <{fr}>\n"
                        f"To: <me@case.example>\nSubject: m{i}\n\nbody {i}\n")
        (d / "Inbox.mbox").write_text("".join(msgs))
        return str(d)

    def test_large_roster_is_not_partial(self, live_log, exports):
        from tools.read_output import read_mail
        senders = [f"sender{i:03d}@ext.example" for i in range(250)]
        path = self._mbox(exports, n=250, senders=senders)
        r = _tool(read_mail)(path, mode="senders")
        e = live_log.index().by_call_id[r["_trudi_call_id"]]
        assert e["messages_scanned"] == 250
        assert e["correspondents_partial"] is False           # scan completed
        assert len(e["observed_correspondents"]) >= 250       # roster kept (cap 1000)
        assert "mode=senders" in e["cmd"]

    def test_zero_yield_is_flagged_and_never_complete(self, live_log, exports):
        from tools.read_output import read_mail
        d = exports / "mailz"
        d.mkdir()
        (d / "Inbox.mbox").write_text("")                     # store yields nothing
        r = _tool(read_mail)(str(d), mode="messages", query="nina")
        assert r["messages_scanned"] == 0
        assert "0 messages" in r["warning"] and "absence" in r["warning"]
        e = live_log.index().by_call_id[r["_trudi_call_id"]]
        assert e["correspondents_partial"] is True            # never a complete registry

    def test_cmd_records_mode_field_query(self, live_log, exports):
        from tools.read_output import read_mail
        path = self._mbox(exports, n=3, senders=["a@ext.example"])
        r = _tool(read_mail)(path, mode="messages", field="subject", query="m1")
        e = live_log.index().by_call_id[r["_trudi_call_id"]]
        assert "mode=messages" in e["cmd"] and "field=subject" in e["cmd"] and "q=m1" in e["cmd"]
        assert r["match_count"] == 1


class TestStructuralMailMarkers:
    """A3: transfer/receipt markers are structural — an actual MIME attachment
    part / a bounce-daemon message with an SMTP status code — never body
    vocabulary."""

    def test_body_vocabulary_does_not_mark(self, live_log, exports):
        from tools.read_output import read_mail
        d = exports / "mailv"; d.mkdir()
        (d / "m.mbox").write_text(
            "From x Thu Jan  1 00:00:00 2026\nFrom: <a@ext.example>\nTo: <b@case.example>\n"
            "Subject: files\n\nplease see the attachment I mentioned, x.zip\n")
        r = _tool(read_mail)(str(d), mode="messages", query="attachment")
        e = live_log.index().by_call_id[r["_trudi_call_id"]]
        assert not e.get("transfer_artifact") and not e.get("receipt_artifact")

    def test_real_attachment_and_dsn_do_mark(self, live_log, exports):
        from tools.read_output import read_mail
        d = exports / "mailw"; d.mkdir()
        (d / "m.mbox").write_text(
            'From x Thu Jan  1 00:00:00 2026\nFrom: <a@ext.example>\nTo: <b@case.example>\n'
            'Subject: docs\nMIME-Version: 1.0\n'
            'Content-Type: multipart/mixed; boundary="B"\n\n'
            '--B\nContent-Type: text/plain\n\nhere it is\n'
            '--B\nContent-Type: application/zip\nContent-Disposition: attachment; filename="r.zip"\n\nZZ\n--B--\n'
            "From y Thu Jan  1 00:01:00 2026\nFrom: MAILER-DAEMON <mailer-daemon@mx.example>\n"
            "To: <b@case.example>\nSubject: failure\n\n552 5.3.4 Message size exceeds fixed limit\n")
        r = _tool(read_mail)(str(d), mode="messages", query="docs failure")
        e = live_log.index().by_call_id[r["_trudi_call_id"]]
        assert e.get("transfer_artifact") is True
        assert e.get("receipt_artifact") is True         # the DSN itself is the receipt-side artifact
        assert any(m.get("has_attachment") for m in r["messages"])


class TestCommandOutputPaths:
    """Regression (VANKO-2016-DEEPSEEK41 run 2, 2026-09-20): `-o` is Sleuth
    Kit's partition OFFSET and `-t` is mount's filesystem TYPE. Reading those
    as promised output files made every tsk call look like an invocation log
    whose output had vanished — refusing it as evidence and permanently
    blocking synthesis for any finding that cited it."""

    def test_tsk_offset_is_not_an_output_path(self):
        from tools._output_reader import _cmd_output_paths
        assert _cmd_output_paths('sudo fls -o 1411072 /ev/img.E01 85578') == []
        assert _cmd_output_paths('sudo icat -o 1411072 /ev/img.E01 85578') == []

    def test_mount_type_is_not_an_output_path(self):
        from tools._output_reader import _cmd_output_paths
        cmd = 'sudo mount -t ntfs-3g -o ro,loop,offset=722468864 /mnt/ewf/ewf1 /mnt/c'
        assert _cmd_output_paths(cmd) == []

    def test_real_output_paths_are_still_detected(self):
        from tools._output_reader import _cmd_output_paths
        assert _cmd_output_paths(
            'dotnet MFTECmd.dll -f /mnt/c/$MFT --csv /case/exports --csvf mft.csv'
        ) == ['/case/exports/mft.csv']
        assert _cmd_output_paths('read.output --output /case/exports/rows.csv') == [
            '/case/exports/rows.csv']


class TestManifestedOutputStaleness:
    """Regression (VANKO run 5, 2026-09-21): the agent re-ran an extractor into
    the same path. The bytes were identical (same sha256) but the inode and
    mtime changed, a stat-only check called the output "changed", and the first
    live pull-mode synthesis was refused outright."""

    def _item(self, path):
        import hashlib
        from core.evidence_packets import file_version
        return {'path': str(path), 'version': file_version(str(path)),
                'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}

    def test_identical_rewrite_is_not_stale(self, tmp_path):
        import os
        from tools._output_reader import _content_changed
        out = tmp_path / 'evtx.csv'
        out.write_text('TimeCreated,EventId\n2016-06-18,4624\n')
        item = self._item(out)
        body = out.read_bytes()
        out.unlink()                       # new inode, new mtime, same bytes
        out.write_bytes(body)
        os.utime(out, ns=(1, 1))
        assert _content_changed(str(out), item) is False

    def test_modified_content_is_stale(self, tmp_path):
        from tools._output_reader import _content_changed
        out = tmp_path / 'evtx.csv'
        out.write_text('TimeCreated,EventId\n2016-06-18,4624\n')
        item = self._item(out)
        out.write_text('TimeCreated,EventId\n2016-06-18,4625\n')
        assert _content_changed(str(out), item) is True

    def test_missing_file_is_stale(self, tmp_path):
        from tools._output_reader import _content_changed
        out = tmp_path / 'gone.csv'
        out.write_text('a\n')
        item = self._item(out)
        out.unlink()
        assert _content_changed(str(out), item) is True

    def test_without_a_recorded_hash_metadata_still_decides(self, tmp_path):
        import os
        from tools._output_reader import _content_changed
        from core.evidence_packets import file_version
        out = tmp_path / 'legacy.csv'
        out.write_text('a\n')
        item = {'path': str(out), 'version': file_version(str(out))}   # no sha256
        os.utime(out, ns=(1, 1))
        assert _content_changed(str(out), item) is True
