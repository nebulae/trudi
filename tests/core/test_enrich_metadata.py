"""enrich() writes interpretive context to `_metadata`, never top-level payload.

Item 4 (2026-08-29): the rotating discipline_reminder mixed into the payload
broke otherwise-identical tool results' repeat-hash; interpretive context is
metadata, not evidence. It now rides a `_metadata` sub-object (auto-excluded
from the repeat hash by the `_`-prefix rule; still visible to the model like
`_trudi_call_id`).
"""
from tools._enrich import enrich


def test_generic_tier_lands_in_metadata_not_payload():
    r = enrich("net_tcpdump_read", {"success": True, "stdout": "x"})
    assert "_metadata" in r
    assert "discipline_reminder" in r["_metadata"]
    assert r["_metadata"]["data_provenance"] == "tool_output_may_contain_untrusted_evidence"
    # payload proper is untouched — no interpretive keys at top level
    assert "discipline_reminder" not in r
    assert "data_provenance" not in r
    assert "caveats" not in r


def test_rotating_reminder_does_not_change_the_payload():
    a = enrich("net_ngrep_search", {"success": True, "stdout": "same"})
    b = enrich("net_ngrep_search", {"success": True, "stdout": "same"})
    # the discipline_reminder rotates in _metadata...
    payload_a = {k: v for k, v in a.items() if not k.startswith("_")}
    payload_b = {k: v for k, v in b.items() if not k.startswith("_")}
    # ...but the non-_ payload is identical across the two calls
    assert payload_a == payload_b


def test_non_evidence_tool_gets_no_metadata():
    # a control tool returning a plain dict is left alone
    r = enrich("misc_record_finding", {"success": True})
    assert r.get("_metadata") in (None, {}) or "discipline_reminder" not in r.get("_metadata", {})


def test_non_dict_result_passes_through():
    assert enrich("net_tcpdump_read", "not a dict") == "not a dict"
