"""agent_authored_source — a finding may not rest on a file the agent wrote
(laundering path: an exports/ file via Write → read.read_output →
SUPPORTED → CONFIRMED finding)."""
from types import SimpleNamespace
from unittest.mock import MagicMock

from tools._gates import GateContext, agent_authored_source as G
from tools._gates._evidence_calls import agent_authored_paths, authored_source_of, read_target_path


def _entries():
    return [
        {"call_id": 112, "type": "tool_call", "source": None,
         "cmd": "read.read_mail -o /case/exports/mbox_gmail/Inbox.mbox", "success": True},
        {"call_id": 127, "type": "tool_call", "source": "claude_code_write",
         "cmd": "write /case/exports/titan_thread.txt", "success": True},
        {"call_id": 128, "type": "tool_call", "source": None,
         "cmd": "read.read_output --output /case/exports/titan_thread.txt", "success": True},
        {"call_id": 129, "type": "tool_call", "source": "claude_code_bash",
         "cmd": "grep -i bulgakov x | tee exports/curated.txt", "success": True},
        {"call_id": 130, "type": "reason_call", "tool": "reason_evaluate_finding", "verdict": "SUPPORTED",
         "evidence_requests": [{"call_id": 112, "rows_returned": 5}, {"call_id": 128, "rows_returned": 14}]},
    ]


def _ctx(linked, inputs, claim=None):
    ents = _entries()
    idx = SimpleNamespace(by_call_id={e["call_id"]: e for e in ents},
                          by_type={"tool_call": [e for e in ents if e["type"] == "tool_call"]})
    return GateContext(description="Vanko disseminated research to Titan", confidence="Confirmed",
                       tier="CONFIRMED", source="read.read_mail", linked_call_id=linked,
                       tested_hypothesis_id="", log=MagicMock(), idx=idx, window=ents,
                       input_call_ids=inputs, supporting_evidence="x", claim=claim or {})


def test_helpers_find_authored_paths_and_reads():
    paths = agent_authored_paths(_entries())
    assert "/case/exports/titan_thread.txt" in paths and "exports/curated.txt" in paths
    assert read_target_path(_entries()[2]) == "/case/exports/titan_thread.txt"
    assert authored_source_of(_entries()[2], paths) == "/case/exports/titan_thread.txt"
    assert authored_source_of(_entries()[0], paths) == ""


def test_finding_on_the_authored_read_is_refused():
    out = G.check(_ctx(linked=128, inputs=[112, 128]))
    assert out and out["gate"] == "agent_authored_source" and 128 in out["tainted_call_ids"]
    assert "AGENT-AUTHORED" in out["error"]


def test_finding_whose_evaluate_fetched_from_the_authored_file_is_refused():
    out = G.check(_ctx(linked=112, inputs=[112, 130]))
    assert out and 128 in out["tainted_call_ids"]


def test_clean_lineage_passes():
    assert G.check(_ctx(linked=112, inputs=[112])) is None


def test_registered_after_mcp_routing():
    from tools._gates import GATES
    names = [n for n, _ in GATES]
    assert names.index("agent_authored_source") == names.index("mcp_routing") + 1
