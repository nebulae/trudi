"""Tests for affirmative coverage completeness (tools/_gates/affirmative_coverage).

Mirror of negative_completeness for positive verdicts. Everything keys on the
TYPED CLAIM and on tool COMMANDS; source waivers are typed dispositions.
Synthetic traces exercise the real logic against the real _manifests source set.
"""
from tools._gates import affirmative_coverage as ac
from tools._gates._claims import normalize_claim


def _f(desc, conf="CONFIRMED", **claim):
    e = {"type": "finding", "confidence": conf, "description": desc, "call_id": 42}
    if claim:
        e["claim"] = normalize_claim(**claim)
    return e


def _egress(desc="data left the host", conf="CONFIRMED", channel="removable"):
    return _f(desc, conf, claim_kind="positive", category="exfil", act="egress", channel=channel)


def _t(cmd):
    return {"type": "tool_call", "cmd": cmd}


def _disp(kind, target, reason):
    from tools._gates._dispositions import normalize_target
    return {"type": "disposition", "call_id": 7, "target_kind": kind, "target_id": target,
            "target_norm": normalize_target(kind, target), "reason": reason}


# cmds that satisfy each EXFIL manifest channel (removable / cloud / mail / srum-ftp / chat)
_ALL_CHANNELS = [
    _t("dotnet /opt/zimmermantools/LECmd.dll -d /Recent"),   # removable (lecmd)
    _t("/usr/local/bin/hindsight.py -i /Dropbox"),           # cloud (hindsight)
    _t("/usr/bin/readpst -o /out /x.pst"),                   # mail_web (readpst)
    _t("python srum SRUDB.dat"),                             # srum_ftp (srum)
    _t("misc.chat_db_export /img/Users/x/AppData/Roaming/Skype/main.db"),  # chat_messenger
]


class TestExfilChannelCoverage:
    def test_exfil_verdict_no_channels_blocks(self):
        issues = ac.coverage_gaps([_egress()])
        assert len(issues) == 1 and "egress-channel" in issues[0]
        assert "record_disposition" in issues[0]

    def test_exfil_verdict_all_channels_clears(self):
        assert ac.coverage_gaps(_ALL_CHANNELS + [_egress()]) == []

    def test_one_missing_channel_blocks_and_names_it(self):
        entries = _ALL_CHANNELS[:3] + _ALL_CHANNELS[4:] + [_egress()]
        issues = ac.coverage_gaps(entries)
        assert len(issues) == 1 and "srum_ftp" in issues[0]

    def test_missing_channel_typed_disposition_clears(self):
        entries = _ALL_CHANNELS[:3] + _ALL_CHANNELS[4:] + [
            _egress(), _disp("source", "srum_ftp", "absent_from_evidence")]
        assert ac.coverage_gaps(entries) == []

    def test_prose_disposition_no_longer_clears(self):
        entries = _ALL_CHANNELS[:3] + _ALL_CHANNELS[4:] + [
            _egress(),
            {"type": "investigation_narration",
             "content": "No FTP/SRUM egress artifacts — SRUM absent from evidence."},
        ]
        assert len(ac.coverage_gaps(entries)) == 1

    def test_suspected_exfil_verdict_not_gated(self):
        assert ac.coverage_gaps([_egress(conf="SUSPECTED")]) == []

    def test_wording_not_read(self):
        # Egress wording without act="egress" is not a verdict here.
        assert ac.coverage_gaps([_f("Data was exfiltrated from the host")]) == []
        assert ac.coverage_gaps([_f("Data was exfiltrated", claim_kind="positive",
                                    category="exfil", act="presence")]) == []

    def test_partial_channel_enumeration_blocks(self):
        entries = [_t("/usr/bin/readpst -o /out /mailbox.pst"),
                   _t("strings /Users/x/transfers.log"), _egress(channel="ftp")]
        issues = ac.coverage_gaps(entries)
        assert len(issues) == 1
        assert "removable" in issues[0] and "cloud" in issues[0] and "chat_messenger" in issues[0]


class TestRecipientExhaustion:
    def _recip(self, cmds):
        return cmds + [_f("the buyer received the data", claim_kind="positive", category="delivery",
                          act="delivery", recipients=["buyer@x.org"])]

    def test_named_recipient_without_comms_enum_blocks(self):
        issues = ac.coverage_gaps(self._recip([]))
        assert any("correspondent enumeration" in i for i in issues)

    def test_named_recipient_with_readpst_clears(self):
        assert not any("correspondent enumeration" in i
                       for i in ac.coverage_gaps(self._recip(_ALL_CHANNELS)))

    def test_read_mail_counts(self):
        assert not any("correspondent enumeration" in i
                       for i in ac.coverage_gaps(self._recip([_t("read.mail --output /x/mbox")])))

    def test_recipient_wording_without_claim_not_gated(self):
        assert not any("correspondent enumeration" in i
                       for i in ac.coverage_gaps([_f("the buyer who received the data is Acme Corp")]))


class TestDestructionImpact:
    def _wiper(self, conf="CONFIRMED"):
        return _f("sdelete.exe was executed", conf, claim_kind="positive",
                  category="destruction", act="destruction")

    def test_wiper_without_impact_blocks(self):
        issues = ac.coverage_gaps([self._wiper()])
        assert any("destruction-impact" in i and "record_disposition" in i for i in issues)

    def test_suspected_wiper_also_gated(self):
        assert any("destruction-impact" in i for i in ac.coverage_gaps([self._wiper("SUSPECTED")]))

    def test_wiper_with_usn_gaps_clears(self):
        entries = [self._wiper(), _t("af.usn_gaps --journal /out/usn.csv")]
        assert not any("destruction-impact" in i for i in ac.coverage_gaps(entries))

    def test_wiper_with_carving_clears(self):
        entries = [self._wiper(), _t("/usr/bin/foremost -i /dev/loop0 -o /out")]
        assert not any("destruction-impact" in i for i in ac.coverage_gaps(entries))

    def test_narrated_impact_no_longer_clears(self):
        entries = [self._wiper(),
                   {"type": "investigation_narration",
                    "content": "USN $J gap analysis shows 40 deleted entries in the window."}]
        assert any("destruction-impact" in i for i in ac.coverage_gaps(entries))

    def test_typed_scope_disposition_clears(self):
        entries = [self._wiper(), _disp("destruction_scope", "42", "undetermined")]
        assert not any("destruction-impact" in i for i in ac.coverage_gaps(entries))

    def test_wiper_wording_without_claim_not_gated(self):
        assert not any("destruction-impact" in i
                       for i in ac.coverage_gaps([_f("sdelete.exe was executed on 2020-01-02")]))
