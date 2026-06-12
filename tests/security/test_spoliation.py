"""Spoliation prevention tests.

These tests prove TRUDI's architectural guardrails refuse any attempt to write
to evidence locations, regardless of which tool's output-path argument the
agent passes. Cited in the hackathon Component #6 (Accuracy Report) as
evidence of architectural-vs-prompt-based enforcement (Criterion #4).
"""
import inspect
import os
import pytest


class TestEvidenceWriteRefusal:
    """assert_output_safe refuses every protected location."""

    def test_refuses_cases_evidence_subpath(self):
        from core.paths import assert_output_safe
        with pytest.raises(ValueError, match="protected evidence"):
            assert_output_safe("/cases/example-case/evidence/foo.bin")

    def test_refuses_cases_root(self):
        from core.paths import assert_output_safe
        with pytest.raises(ValueError, match="protected evidence"):
            assert_output_safe("/cases/example-case/analysis/foo.bin")

    def test_refuses_mnt_path(self):
        from core.paths import assert_output_safe
        with pytest.raises(ValueError, match="protected evidence"):
            assert_output_safe("/mnt/rd01/Windows/foo.bin")

    def test_refuses_media_path(self):
        from core.paths import assert_output_safe
        with pytest.raises(ValueError, match="protected evidence"):
            assert_output_safe("/media/usb0/foo.bin")

    def test_refuses_evidence_segment_anywhere(self):
        from core.paths import assert_output_safe
        with pytest.raises(ValueError, match="protected evidence"):
            assert_output_safe("/tmp/case/evidence/extracted.bin")

    def test_accepts_analysis_dir(self, tmp_path, monkeypatch):
        # Use the safe ./analysis directory inside a fresh cwd.
        from core.paths import assert_output_safe
        monkeypatch.chdir(tmp_path)
        (tmp_path / "analysis").mkdir()
        # Should not raise
        assert_output_safe(str(tmp_path / "analysis" / "out.json"))

    def test_accepts_exports_dir(self, tmp_path, monkeypatch):
        from core.paths import assert_output_safe
        monkeypatch.chdir(tmp_path)
        (tmp_path / "exports").mkdir()
        assert_output_safe(str(tmp_path / "exports" / "out.json"))

    def test_accepts_reports_dir(self, tmp_path, monkeypatch):
        from core.paths import assert_output_safe
        monkeypatch.chdir(tmp_path)
        (tmp_path / "reports").mkdir()
        assert_output_safe(str(tmp_path / "reports" / "out.md"))


class TestBypassAttempts:
    """Path tricks the agent might try to use to escape the gate."""

    def test_path_traversal_into_mnt_refused(self, tmp_path, monkeypatch):
        """A relative path with .. segments that actually resolves into /mnt
        is caught because assert_output_safe uses os.path.realpath."""
        from core.paths import assert_output_safe
        # Set CWD inside a fake /mnt-resolvable structure: realpath of
        # "../../../mnt/foo" must end up under /mnt for this test to be
        # meaningful. We pass an absolute path with embedded "..".
        with pytest.raises(ValueError, match="protected evidence"):
            assert_output_safe("/tmp/../mnt/rd01/Windows/foo")

    def test_symlink_to_evidence_refused(self, tmp_path, monkeypatch):
        """A symlink under ./analysis/ pointing into /mnt is resolved via
        os.path.realpath and refused."""
        from core.paths import assert_output_safe
        monkeypatch.chdir(tmp_path)
        analysis = tmp_path / "analysis"
        analysis.mkdir()
        link = analysis / "outlet"
        os.symlink("/mnt/rd01", str(link))
        with pytest.raises(ValueError, match="protected evidence"):
            assert_output_safe(str(link / "tampered.bin"))

    def test_absolute_path_into_mnt_refused(self):
        from core.paths import assert_output_safe
        with pytest.raises(ValueError, match="protected evidence"):
            assert_output_safe("/mnt/dc/Windows/System32/config/SYSTEM")


class TestNoEvidenceModifyParameters:
    """Programmatic: no @mcp.tool function has a parameter name that suggests
    destructive evidence modification. Criterion #4 architectural evidence."""

    SUSPICIOUS = {
        "delete_evidence", "modify_evidence", "write_to_evidence",
        "rm_evidence", "overwrite_evidence", "unlink_evidence",
        "erase_evidence", "wipe_evidence",
    }

    def test_no_tool_takes_destructive_evidence_param(self):
        import tools.imaging, tools.volatility, tools.sleuthkit, tools.ewf
        import tools.eztools, tools.plaso, tools.yara_tools, tools.hashing
        import tools.strings_tools, tools.carving, tools.network, tools.enrichment
        import tools.misc, tools.reasoning, tools.dair, tools.accuracy

        offenders: list[str] = []
        modules = [
            tools.imaging, tools.volatility, tools.sleuthkit, tools.ewf,
            tools.eztools, tools.plaso, tools.yara_tools, tools.hashing,
            tools.strings_tools, tools.carving, tools.network, tools.enrichment,
            tools.misc, tools.reasoning, tools.dair, tools.accuracy,
        ]
        for mod in modules:
            for name in dir(mod):
                obj = getattr(mod, name)
                if not callable(obj):
                    continue
                try:
                    sig = inspect.signature(obj)
                except (TypeError, ValueError):
                    continue
                for param_name in sig.parameters:
                    if param_name.lower() in self.SUSPICIOUS:
                        offenders.append(f"{mod.__name__}.{name}({param_name})")
        assert offenders == [], f"destructive-looking parameters found: {offenders}"


class TestRecordFindingWriteSafety:
    """record_finding never accepts or relays paths that could be used to
    overwrite evidence — the only path-shaped argument it touches is the
    execution log file (which lives in analysis/)."""

    def test_record_finding_signature_has_no_path_param(self):
        from tools.misc import record_finding
        sig = inspect.signature(record_finding)
        names = set(sig.parameters)
        for forbidden in ("path", "output_path", "evidence_path", "out_path"):
            assert forbidden not in names, (
                f"record_finding should not accept {forbidden}"
            )


class TestDairGatePreventsRogueTools:
    """dair_required architectural enforcement — non-allowlisted tools refuse to run
    without an active DAIR batch, even if the agent tries."""

    def test_dair_gate_module_constants_exist(self):
        from core.middleware import DAIR_GATE_ALLOWLIST, DAIR_WINDOW
        assert isinstance(DAIR_GATE_ALLOWLIST, frozenset)
        assert DAIR_WINDOW > 0

    def test_volatility_tool_not_allowlisted(self):
        """vol.* tools must require DAIR engagement before running."""
        from core.middleware import DAIR_GATE_ALLOWLIST
        for vol_tool in (
            "vol_vol_psscan", "vol_vol_netscan", "vol_vol_malfind",
        ):
            assert vol_tool not in DAIR_GATE_ALLOWLIST, (
                f"{vol_tool} should not be on the allowlist"
            )

    def test_destructive_eztools_not_allowlisted(self):
        # ez_ez_recmd_hive IS allowlisted (pre-plan read of hives before first
        # dair_assess). Other ez.* tools are NOT allowlisted.
        from core.middleware import DAIR_GATE_ALLOWLIST
        for ez_tool in (
            "ez_ez_evtxecmd", "ez_ez_mftecmd", "ez_ez_pecmd",
            "ez_ez_jlecmd", "ez_ez_lecmd",
        ):
            assert ez_tool not in DAIR_GATE_ALLOWLIST


class TestForensicAuditHook:
    """The Stop-hook forensic audit writer (claude/hooks/forensic_audit.py)
    resolves the audit log from the TRUDI session beacon (absolute), never the
    shell CWD.

    Closes a spoliation/bypass-test finding: the previous inline hook
    `mkdir -p ./analysis/ && echo ... >> ./analysis/forensic_audit.log` is
    CWD-relative — it scattered audit lines into exports/ and into a mailbox
    export subfolder, failed (losing the entry) when CWD drifted into a
    read-only evidence mount, and but for the read-only mount would have written
    the audit log INTO evidence.
    """

    @staticmethod
    def _hook():
        import importlib.util
        from pathlib import Path
        hook_path = (Path(__file__).resolve().parents[2]
                     / "claude" / "hooks" / "forensic_audit.py")
        spec = importlib.util.spec_from_file_location("trudi_forensic_audit_hook", hook_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def _beacon(self, tmp_path, trace_path, case_id="CASE-X"):
        import json
        b = tmp_path / "session.json"
        b.write_text(json.dumps({"case_id": case_id, "path": str(trace_path)}))
        return b

    def test_resolves_canonical_analysis_dir(self, tmp_path):
        h = self._hook()
        analysis = tmp_path / "cases" / "case-x" / "analysis"
        analysis.mkdir(parents=True)
        beacon = self._beacon(tmp_path, analysis / "CASE-X_trace.json")
        assert h.resolve_audit_log(session_file=beacon) == analysis / "forensic_audit.log"

    def test_ignores_cwd_drift(self, tmp_path, monkeypatch):
        # The whole bug: location must not depend on where the shell last cd'd.
        h = self._hook()
        analysis = tmp_path / "cases" / "case-x" / "analysis"
        analysis.mkdir(parents=True)
        beacon = self._beacon(tmp_path, analysis / "CASE-X_trace.json")
        drift = tmp_path / "exports" / "jean_pst.export" / "Message00016"
        drift.mkdir(parents=True)
        monkeypatch.chdir(drift)
        assert h.resolve_audit_log(session_file=beacon) == analysis / "forensic_audit.log"

    def test_refuses_evidence_beacon(self, tmp_path):
        h = self._hook()
        bad = tmp_path / "cases" / "case-x" / "evidence" / "analysis"
        bad.mkdir(parents=True)
        beacon = self._beacon(tmp_path, bad / "CASE-X_trace.json")
        assert h.resolve_audit_log(session_file=beacon) is None

    def test_refuses_mount_beacon(self, tmp_path):
        h = self._hook()
        bad = tmp_path / "cases" / "case-x" / "mnt" / "ntfs" / "analysis"
        bad.mkdir(parents=True)
        beacon = self._beacon(tmp_path, bad / "CASE-X_trace.json")
        assert h.resolve_audit_log(session_file=beacon) is None

    def test_no_active_session_no_write(self, tmp_path):
        h = self._hook()
        assert h.resolve_audit_log(session_file=tmp_path / "nope.json") is None

    def test_case_template_has_no_cwd_relative_stop_hook(self):
        # Regression guard for the distributable scaffold.
        from pathlib import Path
        tmpl = (Path(__file__).resolve().parents[2]
                / "case-template" / ".claude" / "settings.json")
        assert "mkdir -p ./analysis/" not in tmpl.read_text(), (
            "case-template Stop hook regressed to the CWD-relative audit one-liner"
        )
