"""Tests for the warn-early lineage content check (#3): a cited call_id should
CONTAIN the artifact value the finding quotes, not merely exist. Fully synthetic.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock

from tools._gates import GateContext
from tools._gates.lineage_content import lineage_content_note


def _ctx(description, *, supporting_evidence="", linked_call_id=0,
         input_call_ids=None, by_call_id=None):
    return GateContext(
        description=description, confidence="CONFIRMED", tier="CONFIRMED",
        source="test", linked_call_id=linked_call_id, tested_hypothesis_id="",
        log=MagicMock(), idx=SimpleNamespace(by_call_id=by_call_id or {}, by_type={}),
        window=[], input_call_ids=input_call_ids or [],
        supporting_evidence=supporting_evidence,
    )


_HASH_A = "a" * 64   # a valid-length sha256
_HASH_B = "b" * 64   # a different one


def test_value_present_in_cited_entry_no_note():
    by_id = {7: {"cmd": "hash_file", "stdout_excerpt": f"sha256={_HASH_A}"}}
    ctx = _ctx(f"The dropper hashes to {_HASH_A}", linked_call_id=7, by_call_id=by_id)
    assert lineage_content_note(ctx) is None


def test_value_absent_from_all_cited_entries_warns():
    # The cited call produced a DIFFERENT hash than the one quoted → mis-citation.
    by_id = {7: {"cmd": "hash_file", "stdout_excerpt": f"sha256={_HASH_B}"}}
    ctx = _ctx(f"The dropper hashes to {_HASH_A}", linked_call_id=7, by_call_id=by_id)
    note = lineage_content_note(ctx)
    assert note is not None and _HASH_A in note


def test_value_present_in_supporting_evidence_no_note():
    ctx = _ctx("C2 beacon to 203.0.113.10",
               supporting_evidence="netscan: 203.0.113.10:8080 ESTABLISHED")
    assert lineage_content_note(ctx) is None


def test_ip_mis_cited_warns():
    ctx = _ctx("C2 beacon to 203.0.113.10",
               supporting_evidence="netscan shows 198.51.100.5:443 only")
    assert lineage_content_note(ctx) is not None


def test_prose_only_finding_no_note():
    ctx = _ctx("The account was created interactively",
               supporting_evidence="Security 4720 account creation event")
    assert lineage_content_note(ctx) is None


def test_no_cited_evidence_no_note():
    # Nothing to check against — a different check owns "no evidence".
    ctx = _ctx("Path C:\\Windows\\Temp\\x.exe was dropped")
    assert lineage_content_note(ctx) is None


def test_input_call_ids_are_searched():
    by_id = {3: {"stdout_excerpt": "irrelevant"},
             9: {"stdout_excerpt": "found HKLM\\Software\\Acme\\Config here"}}
    ctx = _ctx("Persistence key HKLM\\Software\\Acme\\Config was set",
               input_call_ids=[3, 9], by_call_id=by_id)
    assert lineage_content_note(ctx) is None
