"""Tests for the atomicity advisory (tools/_gates/atomicity).

Non-blocking nudge: a description bundling multiple distinct claims (multiple
ATT&CK IDs, or multiple claim verbs joined by a connector) returns a note;
a single atomic claim returns None. Synthetic strings, no scenario data.
"""
from tools._gates.atomicity import atomicity_note


class TestFlagsBundles:
    def test_two_att_ck_ids_flagged(self):
        note = atomicity_note("Beacon established (T1071.001) and persistence set (T1547.001)")
        assert note and "ATT&CK" in note

    def test_two_verbs_with_connector_flagged(self):
        note = atomicity_note("The service was created and executed on the host")
        assert note and "multiple actions" in note

    def test_semicolon_connector_flagged(self):
        assert atomicity_note("Data was exfiltrated; the account was deleted") is not None

    def test_then_connector_flagged(self):
        assert atomicity_note("The archive was staged then uploaded to the server") is not None


class TestDoesNotFlagAtomic:
    def test_single_claim_no_note(self):
        assert atomicity_note("PerfSvc.exe executed on the host") is None

    def test_single_verb_with_and_modifier_no_note(self):
        # one claim verb, "and" joins non-claim modifiers only
        assert atomicity_note("The file executed from Temp and AppData paths") is None

    def test_single_att_ck_id_no_note(self):
        assert atomicity_note("Credential dumping observed (T1003)") is None

    def test_two_verbs_without_connector_no_note(self):
        # no connector between them -> not treated as a bundle
        assert atomicity_note("An executed installer") is None

    def test_empty_no_note(self):
        assert atomicity_note("") is None
