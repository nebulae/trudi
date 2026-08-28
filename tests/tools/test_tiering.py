"""Deterministic tier contract (Phase J-1): tools/_gates/_tiering.py +
tools/_gates/tier_contract.py + data/fk/tiering.yaml.

The tier a CONFIRMED/LIKELY finding may carry is arithmetic over the artifact
classes its cited calls carry — never wording, never a reviewer opinion. The
tests are table-driven from the contract itself so a YAML edit that breaks
the invariants (SUSPECTED floor, monotone tiers, every group member is a
known class, every act reachable) fails here.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from tools._gates import GateContext, tier_contract
from tools._gates import _tiering as T
from tools._gates._claims import normalize_claim


def _e(cid, cmd, **kw):
    d = {"type": "tool_call", "call_id": cid, "success": True, "cmd": cmd}
    d.update(kw)
    return d


EVTX_SEC = _e(61, "dotnet EvtxECmd.dll -f /mnt/c/Windows/System32/winevt/Logs/Security.evtx --csv /out",
              session_artifact=True, session_event_ids=[4624])
EVTX_TS = _e(64, "dotnet EvtxECmd.dll -f /mnt/c/.../Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx --csv /out")
SETUPAPI = _e(62, "misc.device_install_inventory /mnt/c/Windows/INF/setupapi.dev.log",
              device_install_inventory=True)
SAM = _e(63, "rip.pl -r /mnt/c/Windows/System32/config/SAM -p samparse")
NTUSER_UA = _e(71, "rip.pl -r /mnt/c/Users/PC User/NTUSER.DAT -p userassist",
               stdout_excerpt="smallftpd.exe (3) 2016-07-01")
PECMD = _e(80, "dotnet PECmd.dll -d /mnt/c/Windows/Prefetch --csv /out")
ICAT_FTP = _e(5, "icat -o 2048 /cases/x.E01 1234 > /case/exports/ftp/transfers.log")
READ_FTP = _e(70, "read.read_output --output /case/exports/ftp/transfers.log --query temp.zip",
              stdout_excerpt="2016-07-01 12:01 temp.zip 4120 bytes sent 173.73.166.249")
RECMD_SYS = _e(90, "dotnet RECmd.dll -f /mnt/c/Windows/System32/config/SYSTEM --bn BatchMostPlugins.reb --csv /out",
               stdout_excerpt="USBSTOR\\Disk&Ven_SanDisk MountedDevices")
MAIL = _e(95, "read.read_mail -o /case/exports/mail/Inbox.mbox", transfer_artifact=True)
MAIL_RCPT = _e(96, "read.read_mail -o /case/exports/mail/Sent.mbox", receipt_artifact=True)
NARRATION = {"type": "investigation_narration", "call_id": 99, "content": "prefetch shows smallftpd"}
WRITE = _e(100, "Write /case/analysis/notes.txt", source="claude_code_write")

BY = {e["call_id"]: e for e in (EVTX_SEC, EVTX_TS, SETUPAPI, SAM, NTUSER_UA, PECMD, ICAT_FTP,
                                READ_FTP, RECMD_SYS, MAIL, MAIL_RCPT, NARRATION, WRITE)}


def _tier(cids, **claim):
    classes, origins = T.artifact_classes(BY, cids, with_origins=True)
    return T.tier_for(claim, classes, origins)


# ── contract invariants (table-driven from the YAML) ─────────────────────────

class TestContractInvariants:
    def test_every_group_member_is_a_known_class(self):
        c = T.load_contract()
        for g, members in c["groups"].items():
            for m in members:
                assert m in c["classes"], f"group {g} names unknown class {m}"

    def test_every_clause_names_a_known_group_or_class(self):
        c = T.load_contract()

        def walk(rules, where):
            for tier in ("CONFIRMED", "LIKELY", "SUSPECTED"):
                for alt in T._alternatives(rules.get(tier)):
                    for clause in alt:
                        g = clause["group"]
                        assert g in c["groups"] or g in c["classes"], f"{where}/{tier}: {g}"
                        assert int(clause.get("min") or 1) >= 1
        for act, rules in c["acts"].items():
            if "channels" in rules:
                for ch, r in rules["channels"].items():
                    walk(r, f"{act}/{ch}")
            else:
                walk(rules, act)

    @pytest.mark.parametrize("act", sorted(T.load_contract()["acts"]))
    def test_confirmed_reachable_and_tiers_monotone(self, act):
        """With EVERY class present (each from its own call) CONFIRMED is
        reachable; with nothing cited the floor is SUSPECTED."""
        c = T.load_contract()
        classes = {k: [i] for i, k in enumerate(c["classes"], 1)}
        origins = {k: {i} for i, k in enumerate(c["classes"], 1)}
        chan = "ftp" if act == "egress" else ""
        res = T.tier_for({"act": act, "channel": chan}, classes, origins)
        assert res.tier == "CONFIRMED", (act, res.missing)
        floor = T.tier_for({"act": act, "channel": chan}, {}, {})
        assert floor.tier == "SUSPECTED" and floor.next_tier == "LIKELY"
        assert floor.missing and T.tier_path(floor)

    def test_every_egress_channel_has_a_default(self):
        chans = T.load_contract()["acts"]["egress"]["channels"]
        assert "default" in chans
        for ch in ("ftp", "removable", "email", "chat", "cloud", "web", "bogus"):
            rules, key = T._rules_for("egress", ch)
            assert rules and key.startswith("egress/")

    def test_unknown_act_is_not_tiered(self):
        assert T.tier_for({"act": "bogus"}, {}).tier == ""
        assert T.tier_for({}, {}).tier == ""


# ── classification ───────────────────────────────────────────────────────────

class TestArtifactClasses:
    def test_cmd_signature_marker_and_text(self):
        assert {"event_logs_security", "logon_session"} <= T.classify_entry(EVTX_SEC)
        assert "terminalservices" in T.classify_entry(EVTX_TS)
        assert "device_install" in T.classify_entry(SETUPAPI)
        assert {"sam_account", "registry"} <= T.classify_entry(SAM)
        assert {"userassist", "registry"} <= T.classify_entry(NTUSER_UA)
        assert "prefetch" in T.classify_entry(PECMD)
        assert {"usb_storage", "registry"} <= T.classify_entry(RECMD_SYS)
        assert "transfer" in T.classify_entry(MAIL) and "receipt" in T.classify_entry(MAIL_RCPT)

    def test_non_evidence_entries_have_no_class(self):
        assert T.classify_entry(NARRATION) == set()
        assert T.classify_entry(WRITE) == set()          # agent-authored: no cmd signature counts
        assert T.classify_entry(_e(7, "<py>:misc_record_finding x")) == set()
        assert T.classify_entry({**PECMD, "success": False}) == set()

    def test_read_inherits_its_producer_and_keeps_text_markers(self):
        classes, origins = T.artifact_classes(BY, [70], with_origins=True)
        assert "transfer" in classes                     # "4120 bytes sent" in what it returned
        assert "file_content" not in classes             # inherited icat, not a generic read
        assert origins["transfer"] == {5}                # counted as the producer's run

    def test_sidecar_text_is_scanned(self, tmp_path):
        side = tmp_path / "77.txt"
        side.write_text("x" * 700 + "\n2016-07-01 temp.zip 4120 bytes sent\n")
        e = _e(77, "read.read_output --output /case/exports/ftp/transfers.log",
               stdout_excerpt="x" * 600, stdout_path=str(side))
        assert "transfer" in T.classify_entry(e)


# ── tier arithmetic on realistic evidence shapes ─────────────────────────────

class TestTierArithmetic:
    def test_account_creation_confirmed_needs_an_independent_corroborator(self):
        # 4720 (Security) + setupapi device inventory + SAM → CONFIRMED
        assert _tier([61, 62, 63], act="account_creation").tier == "CONFIRMED"
        # Security.evtx alone carries creation_event AND logon_session — same
        # run, one artifact → LIKELY, and the path says why.
        r = _tier([61], act="account_creation")
        assert r.tier == "LIKELY" and r.next_tier == "CONFIRMED"
        assert "SAME tool run" in T.tier_path(r)
        assert _tier([], act="account_creation").tier == "SUSPECTED"

    def test_attribution(self):
        assert _tier([61, 71], act="attribution").tier == "CONFIRMED"     # session + documentary
        assert _tier([61], act="attribution").tier == "LIKELY"            # session alone
        assert _tier([71, 90], act="attribution").tier == "LIKELY"        # two documentary
        assert _tier([71], act="attribution").tier == "SUSPECTED"

    def test_logon_rdp(self):
        assert _tier([61, 64], act="logon").tier == "CONFIRMED"           # 4624 + TS channel
        assert _tier([61], act="logon").tier == "LIKELY"
        assert _tier([64], act="logon").tier == "SUSPECTED"               # TS without session marker

    def test_execution(self):
        assert _tier([71, 80], act="execution").tier == "CONFIRMED"       # UserAssist + Prefetch
        assert _tier([71], act="execution").tier == "LIKELY"
        assert _tier([90], act="execution").tier == "SUSPECTED"           # registry only

    def test_egress_ftp(self):
        assert _tier([70, 71], act="egress", channel="ftp").tier == "CONFIRMED"   # transfers.log + UserAssist
        r = _tier([70], act="egress", channel="ftp")
        assert r.tier == "LIKELY" and "ftp_context" in T.tier_path(r)
        assert _tier([5, 70], act="egress", channel="ftp").tier == "LIKELY"       # same run twice
        assert _tier([71], act="egress", channel="ftp").tier == "SUSPECTED"       # staging only

    def test_egress_removable_and_email(self):
        usn = _e(73, "misc.usnparser_parse /case/exports/$J.csv", stdout_excerpt="vacation photos.7z FileCreate DataExtend")
        by = {**BY, 73: usn}
        c, o = T.artifact_classes(by, [73, 90], with_origins=True)
        assert T.tier_for({"act": "egress", "channel": "removable"}, c, o).tier == "CONFIRMED"
        c, o = T.artifact_classes(by, [73], with_origins=True)
        assert T.tier_for({"act": "egress", "channel": "removable"}, c, o).tier == "LIKELY"
        assert _tier([95, 96], act="egress", channel="email").tier == "CONFIRMED"
        assert _tier([95], act="egress", channel="email").tier == "LIKELY"

    def test_delivery_needs_receipt(self):
        assert _tier([95, 96], act="delivery").tier == "CONFIRMED"
        assert _tier([96], act="delivery").tier == "LIKELY"
        assert _tier([95], act="delivery").tier == "SUSPECTED"

    def test_other_counts_any_two_independent_classes(self):
        assert _tier([80, 71], act="other").tier == "CONFIRMED"
        assert _tier([80], act="other").tier == "LIKELY"
        assert _tier([], act="other").tier == "SUSPECTED"

    def test_tier_path_names_tools(self):
        r = _tier([71], act="execution")
        p = T.tier_path(r)
        assert "CONFIRMED for act=execution" in p and "ez.pecmd" in p and "userassist" in p.lower()
        assert T.tier_path(_tier([71, 80], act="execution")) == ""


# ── the gate ─────────────────────────────────────────────────────────────────

def _ctx(tier, claim, cids, linked=0):
    return GateContext(
        description="d", confidence=tier.capitalize(), tier=tier, source="t",
        linked_call_id=linked, tested_hypothesis_id="", log=MagicMock(),
        idx=SimpleNamespace(by_call_id=BY, by_type={}), window=[],
        input_call_ids=list(cids), supporting_evidence="", claim=claim)


class TestTierContractGate:
    def test_asking_above_the_evidence_is_refused_with_the_path(self):
        claim = normalize_claim(claim_kind="positive", category="execution", act="execution")
        out = tier_contract.check(_ctx("CONFIRMED", claim, [71]))
        assert out and out["gate"] == "tier_contract"
        assert out["tier_achievable"] == "LIKELY" and out["tier_rule"] == "execution"
        assert "ez.pecmd" in out["tier_path"] and out["artifact_classes"]["userassist"] == [71]

    def test_asking_at_or_below_the_evidence_passes_and_stamps(self):
        claim = normalize_claim(claim_kind="positive", category="execution", act="execution")
        ctx = _ctx("LIKELY", claim, [71])
        assert tier_contract.check(ctx) is None
        assert ctx.tier_achievable == "LIKELY"
        ctx = _ctx("LIKELY", claim, [71, 80])
        assert tier_contract.check(ctx) is None and ctx.tier_achievable == "CONFIRMED"

    def test_typed_cid_lists_count(self):
        claim = normalize_claim(claim_kind="positive", category="exfil", act="egress",
                                channel="ftp", transfer_call_ids=[70])
        assert tier_contract.check(_ctx("CONFIRMED", claim, [71])) is None
        claim = normalize_claim(claim_kind="positive", category="identity", act="attribution",
                                session_binding_call_ids=[61])
        assert tier_contract.check(_ctx("CONFIRMED", claim, [71])) is None

    def test_negatives_suspected_and_untyped_are_not_tiered(self):
        neg = normalize_claim(claim_kind="negative", category="persistence", act="persistence_install")
        assert tier_contract.check(_ctx("CONFIRMED", neg, [])) is None
        assert tier_contract.check(_ctx("SUSPECTED", {}, [])) is None
        assert tier_contract.check(_ctx("CONFIRMED", {"claim_kind": "positive"}, [])) is None


def test_record_finding_end_to_end_stamps_and_reports_headroom(tmp_path):
    """record_finding: refused above the contract with `gate=tier_contract`;
    accepted at it with tier_achievable stamped; below it with tier_headroom."""
    from unittest.mock import patch
    from core.execution_log import ExecutionLog
    from tools.misc import record_finding
    l = ExecutionLog()
    l.configure("TIER-E2E", str(tmp_path / "trace.json"))
    l.record_dair_call("Analyze", "", False, "", "", "stay", "")
    ua = l.record_tool_call("rip.pl -r NTUSER.DAT -p userassist", True, False, 0, 0,
                            stdout_excerpt="smallftpd.exe (3)")
    pf = l.record_tool_call("dotnet PECmd.dll -d Prefetch --csv /out", True, False, 0, 0,
                            stdout_excerpt="SMALLFTPD.EXE-1A2B.pf")
    claim = {"kind": "positive", "category": "execution", "act": "execution",
             "entities": ["smallftpd.exe"], "entities_norm": ["smallftpdexe"]}
    l.record_reason_call("reason_hypothesize", True, "H", {}, hypothesis_id="H0001",
                         inputs={"user_message": "smallftpd.exe ran"})
    l.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED", {},
                         inputs={"user_message": "FINDING:\nsmallftpd.exe executed"},
                         extra={"claim": claim, "verdict": "SUPPORTED"})
    kw = dict(source="ez.recmd", supporting_evidence="UserAssist smallftpd.exe (3); SMALLFTPD.EXE-1A2B.pf",
              claim_kind="positive", category="execution", act="execution",
              entities=["smallftpd.exe"], tested_hypothesis_id="H0001")
    with patch("core.execution_log.log", l):
        r1 = record_finding("smallftpd.exe executed", "CONFIRMED", linked_call_id=ua,
                            input_call_ids=[ua], **kw)
        assert r1["success"] is False and r1["gate"] == "tier_contract", r1
        assert r1["tier_achievable"] == "LIKELY" and "ez.pecmd" in r1["tier_path"]
        r2 = record_finding("smallftpd.exe executed", "CONFIRMED", linked_call_id=ua,
                            input_call_ids=[ua, pf], **kw)
        assert r2["success"] is True, r2
        assert r2["tier_achievable"] == "CONFIRMED" and "tier_headroom" not in r2
        r3 = record_finding("smallftpd.exe executed", "LIKELY", linked_call_id=ua,
                            input_call_ids=[ua, pf], supersedes=0, **kw)
    # r3 may hit the refusal/evaluate single-use gates — headroom is asserted
    # when the record succeeded, the stamp when it did.
    if r3.get("success"):
        assert "reach CONFIRMED" in r3["tier_headroom"]
    f = [e for e in l._entries if e.get("type") == "finding"][0]
    assert f["tier_achievable"] == "CONFIRMED" and f["tier_rule"] == "execution"
    assert set(f["artifact_classes"]) >= {"userassist", "prefetch"}
    refused = [e for e in l._entries if e.get("type") == "finding_refused"]
    assert refused and refused[0]["gate"] == "tier_contract"


class TestStructuralTransferClasses:
    """A3: transfer/receipt classes come from STRUCTURAL tokens only —
    vocabulary ("attachment", "removable", "packets") must never inflate a
    class, in either direction."""

    def test_vocabulary_does_not_classify(self):
        for text in ("we discussed the attachment", "a removable drive existed",
                     "packets were mentioned", "see attached file"):
            e = _e(300, "strings -a /mnt/x/notes.txt", stdout_excerpt=text)
            assert "transfer" not in T.classify_entry(e), text
        e = _e(301, "strings -a /mnt/x/mail.txt",
               stdout_excerpt="we acknowledge the confirmation of receipt")
        assert "receipt" not in T.classify_entry(e)

    def test_structural_tokens_still_classify(self):
        cases = {"transfer": ["4,120 bytes sent to host", "MountedDevices key",
                              "Content-Disposition: attachment; filename=x.7z",
                              "FileCreate DataExtend", "transfers.log"],
                 "receipt": ["250 2.0.0 OK queued", "delivery status notification",
                             "HTTP/1.1 200", "Diagnostic-Code: smtp"]}
        for cls, texts in cases.items():
            for t in texts:
                e = _e(302, "strings -a /mnt/x/f", stdout_excerpt=t)
                assert cls in T.classify_entry(e), (cls, t)

    def test_failure_code_is_not_a_receipt(self):
        e = _e(303, "read.read_mail -o /x/mail",
               stdout_excerpt="552 5.3.4 Message size exceeds fixed limit")
        assert "receipt" not in T.classify_entry(e)


class TestCrossPlatformClasses:
    """A5: non-Windows cases must be able to reach CONFIRMED — unix/macOS
    artifact classes exist and feed the per-act groups."""

    def test_linux_logon_and_execution_reach_confirmed(self):
        by = {
            1: _e(1, "read.read_output --output /case/exports/auth.log --query sshd",
                  session_artifact=True),
            2: _e(2, "strings -a /mnt/img/var/log/wtmp"),
            3: _e(3, "read.read_output --output /case/exports/home_user_bash_history.txt"),
        }
        c, o = T.artifact_classes(by, [1, 2], with_origins=True)
        assert T.tier_for({"act": "logon"}, c, o).tier == "CONFIRMED"
        c, o = T.artifact_classes(by, [1, 3], with_origins=True)
        assert T.tier_for({"act": "execution"}, c, o).tier == "CONFIRMED"

    def test_unix_persistence_classes(self):
        assert "unix_persistence" in T.classify_entry(
            _e(4, "read.read_output --output /case/exports/crontab_root.txt"))
        assert "unix_persistence" in T.classify_entry(
            _e(5, "ls /mnt/img/Library/LaunchAgents"))
        assert "unix_persistence" in T.classify_entry(
            _e(6, "strings -a /mnt/img/etc/cron.d/backdoor"))


class TestAnchoredClassRegexes:
    """A7: loose words no longer classify — artifact context required."""

    def test_loose_words_do_not_classify(self):
        assert "sam_account" not in T.classify_entry(_e(310, "strings -a '/mnt/c/Users/sam/notes.txt'"))
        assert "services" not in T.classify_entry(_e(311, "strings -a /mnt/x/services_overview.txt"))
        e = _e(312, "strings -a /mnt/x/doc.txt", stdout_excerpt="a removable feast; bam went the door")
        got = T.classify_entry(e)
        assert "usb_storage" not in got and "bam" not in got

    def test_anchored_forms_still_classify(self):
        assert "sam_account" in T.classify_entry(_e(313, "dotnet RECmd.dll -f /mnt/c/Windows/System32/config/SAM --csv /o"))
        assert "services" in T.classify_entry(_e(314, "dotnet RECmd.dll -f SYSTEM --csv /o ControlSet001/Services"))
        e = _e(315, "dotnet RECmd.dll -f SYSTEM --csv /o", stdout_excerpt="USBSTOR Disk&Ven_SanDisk")
        assert "usb_storage" in T.classify_entry(e)
