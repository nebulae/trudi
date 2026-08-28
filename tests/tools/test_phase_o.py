"""Phase O — DAIR phase discipline (O-A) + disposition batching (O-B).

O-B2: an engaged (wrote-to / chat / roster) correspondent cannot be labelled
      noise — single-target AND batch inherit the guard.
O-B1: the batch-form hint renders.
O-A3: open_scoping_leads surfaces unresolved pivots / flagged IOCs.
"""
from unittest.mock import patch

import pytest

from core.execution_log import ExecutionLog


@pytest.fixture
def log_with_corr(tmp_path):
    l = ExecutionLog()
    l.configure("PHASE-O", str(tmp_path / "trace.json"), save_session=False)
    for cur, nxt in (("Triage", "Collect"), ("Collect", "Analyze")):
        l.record_dair_call(cur, "", True, nxt, "", "push", "")
    l.record_dair_call("Analyze", "", False, "", "", "stay", "")
    cid = l.record_tool_call("misc.readpst_extract -o exports/mail", True, False, 0, 0)
    l.annotate_tool_call(
        cid,
        observed_correspondents=["wrote2@ext.example", "inbound@spam.example",
                                 "jdoe@corp.example"],
        observed_correspondent_stats={
            "wrote2@ext.example": {"from": 1, "to": 3},     # engaged: subject wrote TO
            "inbound@spam.example": {"from": 9, "to": 0},   # inbound-only: noise-eligible
            "jdoe@corp.example": {"from": 1, "to": 0}},     # roster-matched (below)
        correspondents_partial=False)
    rc = l.record_tool_call("misc.knowns_pattern_generate person_username", True, False, 0, 0)
    l.annotate_tool_call(rc, knowns_roster=["jdoe"], knowns_derivation="person_username")
    return l


def _disp(log, **kw):
    from tools.misc import record_disposition
    with patch("core.execution_log.log", log):
        return record_disposition(**kw)


class TestEngagedCorrespondentNotNoise:          # O-B2
    def test_wrote_to_refused_as_noise(self, log_with_corr):
        r = _disp(log_with_corr, target_kind="correspondent",
                  target_id="wrote2@ext.example", reason="noise", input_call_ids=[4])
        assert r["success"] is False
        assert r["detail_gate"] == "engaged_correspondent_not_noise"

    def test_wrote_to_ok_as_out_of_scope(self, log_with_corr):
        r = _disp(log_with_corr, target_kind="correspondent",
                  target_id="wrote2@ext.example", reason="out_of_scope", input_call_ids=[4])
        assert r["success"] is True

    def test_roster_matched_refused_as_noise(self, log_with_corr):
        r = _disp(log_with_corr, target_kind="correspondent",
                  target_id="jdoe@corp.example", reason="noise", input_call_ids=[4])
        assert r["success"] is False
        assert r["detail_gate"] == "engaged_correspondent_not_noise"

    def test_inbound_only_noise_ok(self, log_with_corr):
        r = _disp(log_with_corr, target_kind="correspondent",
                  target_id="inbound@spam.example", reason="noise", input_call_ids=[4])
        assert r["success"] is True


class TestBatchDispositionHint:                  # O-B1
    def test_hint_text(self):
        from tools._gates._dispositions import disposition_batch_hint
        t = disposition_batch_hint("correspondent", "noise")
        assert "record_agent_message" in t and "dispositions=[" in t

    def test_batch_inherits_engaged_guard(self, log_with_corr):
        from tools.misc import record_agent_message
        with patch("core.execution_log.log", log_with_corr):
            r = record_agent_message(
                "clearing noise", input_call_ids=[4],
                dispositions=[
                    {"target_kind": "correspondent", "target_id": "inbound@spam.example",
                     "reason": "noise"},
                    {"target_kind": "correspondent", "target_id": "wrote2@ext.example",
                     "reason": "noise"},
                ])
        assert r["any_disposition_refused"] is True
        outs = r["dispositions"]
        assert outs[0]["success"] is True                          # inbound noise ok
        assert outs[1]["success"] is False                         # engaged refused
        assert outs[1]["detail_gate"] == "engaged_correspondent_not_noise"


class TestOpenScopingLeads:                      # O-A3
    def _entries(self, pivots=None, findings=None, dispositions=None,
                 injector=False, payload_tasks=None):
        es, n = [], [0]

        def nx():
            n[0] += 1
            return n[0]

        es.append({"type": "dair_call", "call_id": nx(),
                   "candidate_pivots": pivots or []})
        for f in (findings or []):
            es.append({"type": "finding", "call_id": nx(), "claim": f})
        for d in (dispositions or []):
            es.append({"type": "disposition", "call_id": nx(), **d})
        if injector:
            es.append({"type": "tool_call", "call_id": nx(), "success": True,
                       "cmd": "misc.device_install_inventory setupapi",
                       "device_install_inventory": True, "flagged_count": 1})
        if payload_tasks:
            es.append({"type": "tool_call", "call_id": nx(), "success": True,
                       "cmd": "misc.parse_scheduled_tasks",
                       "injector_payload_tasks": payload_tasks})
        return es

    def _leads(self, **kw):
        from tools._gates._scoping import open_scoping_leads
        return open_scoping_leads(self._entries(**kw))

    def test_forced_principal_is_a_lead(self):
        leads = self._leads(pivots=[{"kind": "principal", "value": "defaultprinter",
                                     "cue": "forced"}])
        assert any(l["kind"] == "principal" and l["value"] == "defaultprinter" for l in leads)

    def test_forced_principal_in_finding_not_a_lead(self):
        leads = self._leads(
            pivots=[{"kind": "principal", "value": "defaultprinter", "cue": "forced"}],
            findings=[{"principal": "defaultprinter", "principal_norm": "defaultprinter"}])
        assert not any(l["value"] == "defaultprinter" for l in leads)

    def test_forced_principal_dispositioned_not_a_lead(self):
        leads = self._leads(
            pivots=[{"kind": "principal", "value": "defaultprinter", "cue": "forced"}],
            dispositions=[{"target_kind": "principal", "target_norm": "defaultprinter",
                           "reason": "controller_unknown"}])
        assert not any(l["value"] == "defaultprinter" for l in leads)

    def test_appearance_principal_not_a_lead(self):
        leads = self._leads(pivots=[{"kind": "principal", "value": "someguy",
                                     "cue": "appearance"}])
        assert not any(l["value"] == "someguy" for l in leads)

    def test_host_pivot_is_a_lead(self):
        leads = self._leads(pivots=[{"kind": "host", "value": "10.0.0.9"}])
        assert any(l["kind"] == "host" and l["value"] == "10.0.0.9" for l in leads)

    def test_flagged_injector_device_is_a_lead(self):
        leads = self._leads(injector=True)
        assert any(l["kind"] == "device" for l in leads)

    def test_flagged_injector_dispositioned_not_a_lead(self):
        leads = self._leads(injector=True,
                            dispositions=[{"target_kind": "device",
                                           "target_norm": "atmel:ducky",
                                           "reason": "ruled_out"}])
        assert not any(l["kind"] == "device" for l in leads)

    def test_payload_task_is_a_lead(self):
        leads = self._leads(payload_tasks=["/filetree"])
        assert any(l["kind"] == "task" and l["value"] == "/filetree" for l in leads)

    def test_payload_task_in_finding_not_a_lead(self):
        leads = self._leads(payload_tasks=["/filetree"],
                            findings=[{"entities": ["/filetree"],
                                       "entities_norm": ["filetree"]}])
        assert not any(l["value"] == "/filetree" for l in leads)

    def test_empty_trace_no_leads(self):
        from tools._gates._scoping import open_scoping_leads
        assert open_scoping_leads([]) == []
