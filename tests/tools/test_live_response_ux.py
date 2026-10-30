"""Live-response UX changes (operator feedback, 2026-10-05):
1. respond.suggest_containment works off an alert with finding_id omitted.
2. AskUserQuestion answers are captured as a user_message by the PostToolUse
   hook so the operator_text_required gate accepts a POPUP approval — without
   letting the agent self-approve (only the hook writes the entry).
"""
import importlib.util
import json
from pathlib import Path

import pytest

_HOOK = Path(__file__).resolve().parents[2] / "claude" / "hooks" / "log_narration.py"


def _load_hook():
    spec = importlib.util.spec_from_file_location("ln_test", _HOOK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestPopupCapture:
    def test_askuserquestion_answer_becomes_user_message(self):
        ln = _load_hook()
        payload = {"tool_name": "AskUserQuestion", "tool_use_id": "t1",
                   "tool_response": {"answers": {"Approve destructive action?": "Approve ACT-2"}}}
        e = ln._extract_popup_user_message(payload)
        assert e["type"] == "user_message"
        assert e["role"] == "user"
        assert e["source"] == "claude_code_popup_answer"
        assert e["content"] == "Approve ACT-2"          # carries the ACT-N id
        assert e["_source_tool_use_id"] == "t1"

    def test_decline_option_has_no_actid(self):
        ln = _load_hook()
        e = ln._extract_popup_user_message(
            {"tool_name": "AskUserQuestion", "tool_response": {"answers": {"q": "Skip"}}})
        assert "ACT-" not in e["content"]               # gate will not match → stays queued

    def test_non_popup_tool_ignored(self):
        ln = _load_hook()
        assert ln._extract_popup_user_message({"tool_name": "Bash"}) is None
        assert ln._extract_popup_user_message({"tool_name": "Read"}) is None

    def test_dict_valued_answer(self):
        ln = _load_hook()
        e = ln._extract_popup_user_message(
            {"tool_name": "AskUserQuestion",
             "tool_response": {"answers": {"q": {"label": "Approve ACT-7"}}}})
        assert e and "ACT-7" in e["content"]


class TestGateAcceptsPopup:
    def test_popup_user_message_satisfies_operator_text_gate(self, tmp_path, monkeypatch):
        import response.gates as gates
        import core.execution_log as el
        case = "POPUP-UX"
        monkeypatch.setattr(gates, "CASES_ROOT", tmp_path)
        (tmp_path / case / "monitoring" / "baselines").mkdir(parents=True)
        sug = tmp_path / case / "monitoring" / "response" / "suggestions"
        sug.mkdir(parents=True)
        (sug / "ACT-2.json").write_text(json.dumps({"action_id": "ACT-2"}))
        analysis = tmp_path / case / "analysis"
        analysis.mkdir(parents=True)
        trace = analysis / f"{case}_trace.json"
        trace.write_text(json.dumps({"entries": []}))
        el.log.configure(case, str(trace), save_session=False)
        # hook (separate process) appends the popup answer to the file
        data = json.loads(trace.read_text())
        data["entries"].append({"call_id": 1, "type": "user_message",
                                "content": "Approve ACT-2",
                                "source": "claude_code_popup_answer", "role": "user"})
        trace.write_text(json.dumps(data))
        with el.log.transaction():          # the refresh an MCP call performs
            pass
        # exact selected label as operator_text → accepted
        assert gates.check_operator_text(case, "ACT-2", "Approve ACT-2") is None
        # agent cannot self-approve an action with no operator entry
        (sug / "ACT-9.json").write_text(json.dumps({"action_id": "ACT-9"}))
        assert gates.check_operator_text(case, "ACT-9", "Approve ACT-9") is not None


class TestKillByImageSweep:
    def test_argv_and_irreversible(self):
        from core import ssh_exec
        argv = ssh_exec.build_argv("kill_by_image", {"image_path": "/usr/local/sbin/.trudi-rootsvc"})
        assert argv == ["/usr/bin/pkill", "-9", "-f", "^/usr/local/sbin/.trudi-rootsvc"]
        assert ssh_exec.revert_template_for("kill_by_image") is None

    def test_rejects_shell_metachars(self):
        from core import ssh_exec
        import pytest as _pt
        for bad in ("/x; rm -rf /", "/x && id", "/x`id`", "../etc/passwd"):
            with _pt.raises(ssh_exec.ParamValidationError):
                ssh_exec.build_argv("kill_by_image", {"image_path": bad})

    def test_in_recipes_and_needs_approval(self):
        import yaml
        from response import policy
        for rp in ("Custom.TRUDI.NewProcess", "Custom.TRUDI.PrivilegeEscalation"):
            doc = yaml.safe_load(open(f"response/recipes/{rp}.yaml"))
            kbi = [a for a in doc["actions"] if a["action_template"] == "kill_by_image"]
            assert kbi, f"{rp} missing kill_by_image"
            assert policy.classify(kbi[0]) == policy.NEEDS_APPROVAL


class TestSnapshotEvidence:
    def _scope(self, tmp_path, monkeypatch):
        import tools.respond as respond
        case = "SNAP"
        monkeypatch.setattr(respond, "CASES_ROOT", tmp_path)
        import response.gates as gates
        monkeypatch.setattr(gates, "CASES_ROOT", tmp_path)
        bl = tmp_path / case / "monitoring" / "baselines"; bl.mkdir(parents=True)
        (bl / "C.x.json").write_text("{}")
        monkeypatch.setattr(respond, "_resolve_host_for_case", lambda c: "trudi-victim-b")
        return respond, case

    def _fake_live(self, monkeypatch):
        import tools.live as live
        calls = {"n": 1000}

        def mk(name):
            def f(*a, **k):
                calls["n"] += 1
                return {"success": True, "_trudi_call_id": calls["n"], "tool": name}
            return f
        for n in ("live_process_details", "live_read_file",
                  "live_network_connections", "live_processes"):
            monkeypatch.setattr(live, n, mk(n))

    def test_privesc_snapshots_proc_and_table(self, tmp_path, monkeypatch):
        respond, case = self._scope(tmp_path, monkeypatch)
        self._fake_live(monkeypatch)
        r = respond.snapshot_evidence(
            case, detector="Custom.TRUDI.PrivilegeEscalation",
            evidence={"pid": "612", "image_path": "/usr/local/sbin/.trudi-rootsvc"})
        assert r["success"] is True
        assert len(r["snapshot_call_ids"]) >= 2          # process_details + process_table
        caps = {c["capture"] for c in r["captured"]}
        assert "process_details" in caps and "process_table" in caps

    def test_persistence_snapshots_file(self, tmp_path, monkeypatch):
        respond, case = self._scope(tmp_path, monkeypatch)
        self._fake_live(monkeypatch)
        r = respond.snapshot_evidence(
            case, detector="Custom.TRUDI.NewPersistence",
            evidence={"path": "/etc/cron.d/trudi-pivot"})
        caps = {c["capture"] for c in r["captured"]}
        assert "persistence_file" in caps and r["snapshot_call_ids"]

    def test_logon_snapshots_netstat(self, tmp_path, monkeypatch):
        respond, case = self._scope(tmp_path, monkeypatch)
        self._fake_live(monkeypatch)
        r = respond.snapshot_evidence(
            case, detector="Custom.TRUDI.NewLogon",
            evidence={"remote_ip": "10.73.0.3", "pid": 616})
        caps = {c["capture"] for c in r["captured"]}
        assert "network_connections" in caps and "session_proc" in caps

    def test_off_scope_refused(self, tmp_path, monkeypatch):
        import tools.respond as respond
        monkeypatch.setattr(respond, "CASES_ROOT", tmp_path)
        import response.gates as gates
        monkeypatch.setattr(gates, "CASES_ROOT", tmp_path)
        r = respond.snapshot_evidence("NOCASE", detector="Custom.TRUDI.NewProcess",
                                         evidence={"pid": "1"})
        assert r.get("success") is False


class TestSystemBinaryGuard:
    """#3/#4: image-based actions must refuse SYSTEM-path binaries (e.g. the
    held-session /usr/bin/sleep) and be flagged non-executable in suggestions."""
    def test_kill_by_image_and_quarantine_reject_system_paths(self):
        from core import ssh_exec
        import pytest as _pt
        for tmpl in ("kill_by_image", "quarantine_image"):
            for bad in ("/usr/bin/sleep", "/bin/bash", "/usr/sbin/sshd", "/lib/x"):
                with _pt.raises(ssh_exec.ParamValidationError):
                    ssh_exec.build_argv(tmpl, {"image_path": bad})
            for good in ("/tmp/.systemd-private", "/usr/local/sbin/.trudi-rootsvc", "/home/u/x"):
                assert ssh_exec.build_argv(tmpl, {"image_path": good})

    def test_suggest_flags_system_path_action_nonexecutable(self, tmp_path, monkeypatch):
        import tools.respond as respond, response.gates as gates
        case = "SYSGUARD"
        monkeypatch.setattr(respond, "CASES_ROOT", tmp_path)
        monkeypatch.setattr(gates, "CASES_ROOT", tmp_path)
        bl = tmp_path / case / "monitoring" / "baselines"; bl.mkdir(parents=True)
        (bl / "C.x.json").write_text("{}")
        # NewProcess alert on the held-session /usr/bin/sleep
        r = respond.suggest_containment(
            case, detector="Custom.TRUDI.NewProcess",
            evidence={"pid": "916", "image_path": "/usr/bin/sleep"})
        by_t = {s["action_template"]: s for s in r["suggestions"]}
        # quarantine + kill_by_image on a system binary → non-executable + reason
        assert by_t["quarantine_image"]["executable"] is False
        assert by_t["quarantine_image"]["blocked_reason"]
        assert by_t["kill_by_image"]["executable"] is False
        # kill_pid (by pid) is still fine
        assert by_t["kill_pid"]["executable"] is True


class TestDetectorDedup:
    """#7: the NewLogon / PrivilegeEscalation detectors must dedup like the rest
    (they re-fire every poll otherwise — ~40 events -> ~270 alerts)."""
    def _watcher(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "w_dedup", str(_HOOK.parents[2] / "bin" / "trudi-velo-watcher.py"))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m

    def test_new_detectors_have_signatures_and_dedup(self):
        w = self._watcher()
        cases = [
            ("Custom.TRUDI.PrivilegeEscalation", {"image_path": "/x", "pid": "612"}),
            ("Custom.TRUDI.NewLogon", {"remote_ip": "10.73.0.3", "remote_port": 1, "pid": 616}),
        ]
        for det, row in cases:
            assert w._row_signature(det, row)              # non-empty signature
            assert w._should_emit(det, row) is True        # first time
            assert w._should_emit(det, row) is False       # deduped thereafter
        # a genuinely new pid (respawned sibling) still emits
        assert w._should_emit("Custom.TRUDI.PrivilegeEscalation",
                              {"image_path": "/x", "pid": "999"}) is True


class TestHostAwareRouting:
    """#1: snapshot/containment must route to the host the ALERT came from
    (its client_id), not a single hard-wired response host."""
    def test_policy_client_map_roundtrip_and_fallback(self, tmp_path):
        from response import policy
        case = "ROUTE"
        (tmp_path / case / "monitoring").mkdir(parents=True)
        policy.record_client_host(case, "C.aaa", "trudi-victim-a", cases_root=tmp_path)
        policy.record_client_host(case, "C.bbb", "trudi-victim-b", cases_root=tmp_path)
        assert policy.host_for_client(case, "C.aaa", cases_root=tmp_path) == "trudi-victim-a"
        assert policy.host_for_client(case, "C.bbb", cases_root=tmp_path) == "trudi-victim-b"
        # unmapped client / no client → None (caller ORs the single-host fallback)
        assert policy.host_for_client(case, "C.zzz", cases_root=tmp_path) is None
        assert policy.host_for_client(case, None, cases_root=tmp_path) is None
        # record_client_host must not clobber the other config keys
        import json
        cfg = json.loads((tmp_path / case / "monitoring" / "config.json").read_text())
        assert set(cfg["client_map"]) == {"C.aaa", "C.bbb"}

    def test_suggestion_stamped_with_alerting_host(self, tmp_path, monkeypatch):
        import tools.respond as respond
        from response import policy, gates
        case = "ROUTE2"
        monkeypatch.setattr(respond, "CASES_ROOT", tmp_path)
        monkeypatch.setattr(policy, "CASES_ROOT", tmp_path)
        monkeypatch.setattr(gates, "CASES_ROOT", tmp_path)
        bl = tmp_path / case / "monitoring" / "baselines"
        bl.mkdir(parents=True)
        (bl / "C.va.json").write_text("{}")
        policy.record_client_host(case, "C.va", "trudi-victim-a", cases_root=tmp_path)
        r = respond.suggest_containment(
            case, detector="Custom.TRUDI.NewProcess",
            evidence={"pid": "999", "image_path": "/tmp/.x"}, client_id="C.va")
        assert r["suggestions"]
        for s in r["suggestions"]:
            assert s["host"] == "trudi-victim-a"      # routed to the alerting host
            assert s["client_id"] == "C.va"


class TestApprovalBatchedMatch:
    """#2: the approval gate must accept a batched/popup approval, not demand
    exact string-equality with the per-action operator_text."""
    def _setup(self, tmp_path, monkeypatch, content, source="claude_code_user_prompt"):
        import response.gates as gates, core.execution_log as el, json
        (tmp_path / "C" / "monitoring" / "response" / "suggestions").mkdir(parents=True)
        (tmp_path / "C" / "monitoring" / "response" / "suggestions" / "ACT-7.json").write_text("{}")
        (tmp_path / "C" / "monitoring" / "response" / "suggestions" / "ACT-9.json").write_text("{}")
        monkeypatch.setattr(gates, "CASES_ROOT", tmp_path)
        trace = tmp_path / "trace.json"
        trace.write_text(json.dumps({"entries": [
            {"type": "user_message", "source": source, "content": content}]}))
        class FakeLog:
            _path = str(trace)
            def last_n_window(self, n): return []
        monkeypatch.setattr(el, "log", FakeLog())
        return gates

    def test_batched_typed_approval_accepted(self, tmp_path, monkeypatch):
        gates = self._setup(tmp_path, monkeypatch, "Approve ACT-7; Approve ACT-10; Approve ACT-13")
        assert gates.check_operator_text("C", "ACT-7", "Approve ACT-7") is None

    def test_popup_phrasing_accepted(self, tmp_path, monkeypatch):
        gates = self._setup(tmp_path, monkeypatch, "Approve ACT-7 and ACT-9",
                            source="claude_code_popup_answer")
        assert gates.check_operator_text("C", "ACT-9", "approve ACT-9") is None

    def test_mention_without_approval_cue_refused(self, tmp_path, monkeypatch):
        # a task-notification that merely NAMES the action id must not count
        gates = self._setup(tmp_path, monkeypatch, "task-notification: ACT-7 finished")
        assert gates.check_operator_text("C", "ACT-7", "approve ACT-7") is not None

    def test_unapproved_action_refused(self, tmp_path, monkeypatch):
        gates = self._setup(tmp_path, monkeypatch, "Approve ACT-7")
        assert gates.check_operator_text("C", "ACT-9", "approve ACT-9") is not None


class TestLiveSessionTier:
    """#3: a live ESTABLISHED inbound SSH session is a session artifact that
    reaches LIKELY for lateral_movement and logon."""
    def test_live_session_class_and_tier(self):
        from tools._gates import _tiering
        ss = {"type": "tool_call", "success": True, "cmd": "ssh h -- ss -tnlpa",
              "stdout_excerpt": "ESTAB 0 0 10.73.0.2:22 10.73.0.3:43374"}
        assert "live_session" in _tiering.classify_entry(ss)
        # a plain process table (no session) must NOT be a live_session
        plain = {"type": "tool_call", "success": True, "cmd": "ssh h -- ps",
                 "stdout_excerpt": "1 0 root /sbin/docker-init"}
        assert "live_session" not in _tiering.classify_entry(plain)
        assert _tiering.tier_for({"act": "lateral_movement"}, {"live_session"}).tier == "LIKELY"
        assert _tiering.tier_for({"act": "logon"}, {"live_session"}).tier == "LIKELY"
