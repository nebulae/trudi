"""Schema tests for the new `input_call_ids` field on every record_* method.

`input_call_ids` is the agent-declared upstream lineage — a list of
_trudi_call_id values pointing back to the trace entries that informed this
call. After G1+G2+G4, the field is:
  * accepted by every record_* method on ExecutionLog
  * forwarded through every agent-facing MCP wrapper
  * enforced (after genesis grace) by the lineage_required gate
  * the primary wire source for the chain view (G3)

These tests cover the schema-only piece — that the field gets stored
correctly on each entry type and that empty/None values are omitted.
"""
import pytest


@pytest.fixture
def log(tmp_path):
    from core.execution_log import ExecutionLog
    l = ExecutionLog()
    l.configure("INPUT-CIDS", str(tmp_path / "trace.json"))
    return l


def test_record_tool_call_stores_input_call_ids(log):
    log.record_tool_call("vol psscan", True, False, 0, 0, input_call_ids=[1, 2])
    entry = [e for e in log._entries if e.get("type") == "tool_call"][-1]
    assert entry["input_call_ids"] == [1, 2]


def test_record_reason_call_stores_input_call_ids(log):
    log.record_reason_call(
        tool="reason_plan", success=True, conclusion="ok", directives={},
        input_call_ids=[3, 4, 5],
    )
    entry = [e for e in log._entries if e.get("type") == "reason_call"][-1]
    assert entry["input_call_ids"] == [3, 4, 5]


def test_record_finding_with_input_call_ids(log, tmp_path):
    """A finding can carry both linked_call_id (1:1 primary evidence) and
    input_call_ids (N:M complete lineage) on the same entry — they're
    complementary, not alternatives."""
    log.record_dair_call("Triage", "", False, "", "", "stay", "")
    tid = log.record_tool_call("vol psscan", True, False, 0, 0,
                                input_call_ids=[1])
    log.record_finding(
        "CONFIRMED beacon", "CONFIRMED", source="vol.psscan",
        linked_call_id=tid,
        input_call_ids=[tid, 1, 2],
    )
    entry = [e for e in log._entries if e.get("type") == "finding"][-1]
    assert entry["linked_call_id"] == tid
    assert entry["input_call_ids"] == [tid, 1, 2]


def test_record_self_correction_stores_input_call_ids(log):
    log.record_self_correction(
        trigger="evaluate_challenged",
        prior_belief="x",
        new_belief="y",
        linked_call_id=1,
        input_call_ids=[1, 2, 3],
    )
    entry = [e for e in log._entries if e.get("type") == "self_correction"][-1]
    assert entry["input_call_ids"] == [1, 2, 3]


def test_record_dair_call_stores_input_call_ids(log):
    log.record_dair_call(
        current_phase="Triage", phase_rationale="", transition_recommended=False,
        next_phase="", transition_rationale="", stack_action="stay",
        investigation_focus="", input_call_ids=[1, 2, 3, 4, 5],
    )
    entry = [e for e in log._entries if e.get("type") == "dair_call"][-1]
    assert entry["input_call_ids"] == [1, 2, 3, 4, 5]


def test_record_call_initiated_stores_input_call_ids(log):
    log.record_call_initiated(
        tool="reason_plan", backend="claude", inputs={"model": "x"},
        input_call_ids=[1, 2],
    )
    entry = [e for e in log._entries if e.get("type") == "call_initiated"][-1]
    assert entry["input_call_ids"] == [1, 2]


def test_empty_input_call_ids_not_stored(log):
    """Passing None or [] should not write the field — keeps entries small
    and consistent with how other optional fields (tested_hypothesis_id,
    validated_techniques) are handled."""
    log.record_tool_call("a", True, False, 0, 0, input_call_ids=None)
    log.record_tool_call("b", True, False, 0, 0, input_call_ids=[])
    log.record_tool_call("c", True, False, 0, 0)  # not passed at all
    for entry in log._entries:
        assert "input_call_ids" not in entry, (
            f"unexpectedly stored input_call_ids on {entry!r}"
        )


def test_input_call_ids_coerced_to_ints(log):
    """Strings or other numeric types should coerce to int via the helper —
    the model occasionally returns strings, don't reject — coerce."""
    log.record_tool_call("a", True, False, 0, 0, input_call_ids=["1", "2", 3])
    entry = log._entries[-1]
    assert entry["input_call_ids"] == [1, 2, 3]
