"""Relevance-scoped exhaustion (Phase J-3).

A registry identity is MANDATORY (blocks Report until settled) only when it
is (a) a forced DAIR candidate / declared created-or-interactive principal,
(b) a match against the case roster the operator declared through
misc.knowns_pattern_generate (server-stamped `knowns_roster`), or (c) an
engaged correspondent. Everything else the registries hold is rendered into
the report as an inventory by write_final_report — shown, never a blocker.
"""
from unittest.mock import patch

import pytest

from core.execution_log import ExecutionLog
from tools._gates._claims import normalize_claim


@pytest.fixture
def base_log(tmp_path):
    l = ExecutionLog()
    l.configure("REL-SCOPE", str(tmp_path / "trace.json"), save_session=False)
    for cur, nxt in (("Triage", "Collect"), ("Collect", "Analyze")):
        l.record_dair_call(cur, "", True, nxt, "", "push", "")
    l.record_dair_call("Analyze", "", False, "", "", "stay", "")
    l.record_reason_call("reason_plan", True, "plan", {})
    l.record_reason_call("reason_synthesize", True, "ok", {})
    return l


def _hyp_reviewer_listed(log, hid, ents, tier="MEDIUM"):
    cid = log.record_reason_call("reason_hypothesize", True, "h", {}, hypothesis_id=hid,
                                 inputs={"user_message": "OBSERVATION: who controls the account?"})
    log.update_reason_call(cid, sub_hypotheses=[
        {"label": "H1", "title": "alt", "likelihood_tier": tier, "entities": list(ents),
         "sub_id": f"{hid}.1"}])
    return cid


def _roster(log, terms):
    cid = log.record_tool_call("misc.knowns_pattern_generate person_username n=1", True, False, 0, 0)
    log.annotate_tool_call(cid, knowns_roster=list(terms), knowns_derivation="person_username")
    return cid


def _pre(log):
    from tools.reasoning import reason_pre_report_check
    with patch("core.execution_log.log", log):
        return reason_pre_report_check()


def _pre_entry(log):
    return [e for e in log._entries if e.get("tool") == "reason_pre_report_check"][-1]


class TestRosterStamping:
    def test_knowns_pattern_generate_stamps_the_roster(self, base_log):
        from tools.misc import knowns_pattern_generate
        with patch("core.execution_log.log", base_log):
            r = knowns_pattern_generate(["Anthony Vanko", "Nina Bulgakov"], "person_username")
        assert r["success"] and r["_trudi_call_id"]
        e = base_log.index().by_call_id[r["_trudi_call_id"]]
        assert e["knowns_derivation"] == "person_username"
        assert "vanko" in e["knowns_roster"] and "nina.bulgakov" in e["knowns_roster"]
        assert e["knowns_reference_set"] == ["Anthony Vanko", "Nina Bulgakov"]
        assert "vanko" in base_log.index().roster


class TestContestedPrincipalRelevance:
    def test_reviewer_listed_principal_is_inventory_not_blocker(self, base_log):
        _hyp_reviewer_listed(base_log, "H0004", ["svc_backup"])
        r = _pre(base_log)
        assert not any("svcbackup" in i for i in r["blocking_issues"])
        assert any("svcbackup" in w and "report inventory" in w for w in r["warnings"])
        inv = _pre_entry(base_log)["registry_inventory"]
        assert {"value": "svcbackup", "how": "reviewer-listed (hypothesis H1)", "status": "inventory"} in inv["principals"]

    def test_reviewer_listed_principal_on_the_roster_blocks(self, base_log):
        _roster(base_log, ["svc_backup", "jdoe"])
        _hyp_reviewer_listed(base_log, "H0004", ["svc_backup"])
        r = _pre(base_log)
        assert any("svcbackup" in i and "never driven to a verdict" in i for i in r["blocking_issues"])

    def test_reviewer_listed_principal_that_is_forced_blocks(self, base_log):
        base_log.record_dair_call(
            current_phase="Analyze", phase_rationale="", transition_recommended=False,
            next_phase="", transition_rationale="", stack_action="stay", investigation_focus="",
            candidate_pivots=[{"kind": "principal", "value": "svc_backup", "phase": "Triage", "cue": "forced"}])
        _hyp_reviewer_listed(base_log, "H0004", ["svc_backup"])
        r = _pre(base_log)
        assert any("svcbackup" in i and "never driven to a verdict" in i for i in r["blocking_issues"])
        inv = _pre_entry(base_log)["registry_inventory"]
        assert any(p["value"] == "svc_backup" and p["status"] == "open" for p in inv["principals"])

    def test_agent_typed_contested_principal_still_blocks(self, base_log):
        cid = base_log.record_reason_call("reason_hypothesize", True, "h", {}, hypothesis_id="H0005",
                                          inputs={"user_message": "OBSERVATION: x"})
        base_log.update_reason_call(cid, hypothesis_kind="distinct_principal",
                                    contested_principals=["svc_rdp"])
        r = _pre(base_log)
        assert any("svcrdp" in i and "never driven to a verdict" in i for i in r["blocking_issues"])


class TestCorrespondentRelevance:
    def _recipient_trace(self, log):
        log.record_tool_call("vol.psscan", True, False, 0, 0)
        log.record_reason_call("reason_hypothesize", True, "hyp", {})
        log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        log.record_finding("research data was exfiltrated; the recipient is contact-a@ext.example",
                           "CONFIRMED", "ez.mftecmd",
                           claim=normalize_claim(claim_kind="positive", category="delivery",
                                                 act="delivery", recipients=["contact-a@ext.example"]))
        cid = log.record_tool_call("read.read_mail -o /x/mail", True, False, 0, 0)
        log.annotate_tool_call(
            cid,
            observed_correspondents=["contact-a@ext.example", "nina.bulgakov@titan.example",
                                     "news@apple.example"],
            observed_correspondent_stats={"contact-a@ext.example": {"from": 1, "to": 2},
                                          "nina.bulgakov@titan.example": {"from": 1, "to": 0},
                                          "news@apple.example": {"from": 1, "to": 0}},
            correspondents_partial=False)

    def test_roster_matched_one_shot_sender_is_mandatory(self, base_log):
        self._recipient_trace(base_log)
        r0 = _pre(base_log)
        assert not any("nina.bulgakov" in i for i in r0["blocking_issues"])   # not yet on a roster
        _roster(base_log, ["nina.bulgakov", "bulgakov", "vanko"])
        r = _pre(base_log)
        blocking = " ".join(r["blocking_issues"])
        assert "nina.bulgakov@titan.example" in blocking
        assert "news@apple.example" not in blocking
        inv = _pre_entry(base_log)["registry_inventory"]
        by = {c["address"]: c["status"] for c in inv["correspondents"]}
        assert by["contact-a@ext.example"] == "referenced"
        assert by["nina.bulgakov@titan.example"] == "roster-match (open)"
        assert by["news@apple.example"] == "inventory"
        assert inv["roster"] == ["nina.bulgakov", "bulgakov", "vanko"]


class TestInventoryInReport:
    def test_write_final_report_appends_the_registry_inventory(self, base_log, tmp_path):
        from tools.misc import write_final_report
        base_log.record_tool_call("vol.psscan", True, False, 0, 0)
        base_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        base_log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        base_log.record_finding("STUN.exe present", "CONFIRMED", "ez.mftecmd",
                                claim=normalize_claim(claim_kind="positive", category="other",
                                                      act="presence", entities=["STUN.exe"]))
        cid = base_log.record_tool_call("read.read_mail -o /x/mail", True, False, 0, 0)
        base_log.annotate_tool_call(cid, observed_correspondents=["news@apple.example"],
                                    observed_correspondent_stats={"news@apple.example": {"from": 1, "to": 0}},
                                    correspondents_partial=False)
        pc = base_log.record_tool_call("net.pcap_identity_timeline x.pcap", True, False, 0, 0)
        base_log.annotate_tool_call(pc, observed_identities=["findme69@hotmail.example"])
        r = _pre(base_log)
        assert r["ready_to_report"] is True, r["blocking_issues"]
        inv = _pre_entry(base_log)["registry_inventory"]
        assert inv["correspondents"][0]["status"] == "inventory"
        assert inv["identities"][0]["value"] == "findme69@hotmail.example"
        out = tmp_path / "reports" / "report.md"
        with patch("core.execution_log.log", base_log):
            w = write_final_report(str(out), "# Report\n")
        assert w["success"] and w["inventory_rows_appended"] == 2
        text = out.read_text()
        assert "## Evidence registry inventory" in text
        assert "| news@apple.example | 1 | 0 | read.read_mail | inventory |" in text
        assert "| findme69@hotmail.example |" in text


class TestClaimClassExhaustion:
    """K-3b: the correspondent exhaustion engages on the CLAIM CLASS at any
    tier — a SUSPECTED delivery claim can no longer switch it off."""

    def test_suspected_delivery_claim_engages_check3(self, base_log):
        log = base_log
        log.record_tool_call("vol.psscan", True, False, 0, 0)
        log.record_reason_call("reason_hypothesize", True, "hyp", {})
        log.record_finding("data was delivered to contact-a@ext.example",
                           "SUSPECTED", "read.read_mail",
                           claim=normalize_claim(claim_kind="positive", category="delivery",
                                                 act="delivery", recipients=["contact-a@ext.example"]))
        cid = log.record_tool_call("read.read_mail -o /x/mail mode=senders field=any", True, False, 0, 0)
        log.annotate_tool_call(
            cid, observed_correspondents=["contact-a@ext.example", "handler-b@far.example"],
            observed_correspondent_stats={"contact-a@ext.example": {"from": 1, "to": 2},
                                          "handler-b@far.example": {"from": 1, "to": 1}},
            correspondents_partial=False)
        r = _pre(log)
        assert any("handler-b@far.example" in i for i in r["blocking_issues"])
        # K-6b: recipient claim without a queried body read → warning
        assert any("BODY read" in w for w in r["warnings"])
        log.record_tool_call("read.read_mail -o /x/mail mode=messages field=any q=handler", True, False, 0, 0)
        r2 = _pre(log)
        assert not any("BODY read" in w for w in r2["warnings"])


class TestAliasLeads:
    """K-3c: near-alias addresses are surfaced as a typed lead — never merged."""

    def test_one_char_same_domain_pair_is_surfaced(self, base_log):
        log = base_log
        log.record_tool_call("vol.psscan", True, False, 0, 0)
        log.record_reason_call("reason_hypothesize", True, "hyp", {})
        log.record_finding("x present", "SUSPECTED", "t")
        cid = log.record_tool_call("read.read_mail -o /x/mail mode=senders field=any", True, False, 0, 0)
        log.annotate_tool_call(
            cid, observed_correspondents=["nina_kwa1@qq.example", "nina_kwai@qq.example",
                                          "other@else.example"],
            observed_correspondent_stats={"nina_kwa1@qq.example": {"from": 0, "to": 2},
                                          "nina_kwai@qq.example": {"from": 6, "to": 7},
                                          "other@else.example": {"from": 1, "to": 0}},
            correspondents_partial=False)
        r = _pre(log)
        assert any("near-alias" in w and "nina_kwa1@qq.example" in w for w in r["warnings"])
        inv = _pre_entry(log)["registry_inventory"]
        assert {"a": "nina_kwa1@qq.example", "b": "nina_kwai@qq.example"} in inv["alias_leads"]
        # both stay separate rows — no merge
        addrs = {c["address"] for c in inv["correspondents"]}
        assert {"nina_kwa1@qq.example", "nina_kwai@qq.example"} <= addrs


class TestCommsPresence:
    """K-7: a comms-store family the collected evidence itself shows must be
    parsed or typed-dispositioned when a delivery/egress question exists."""

    def _seed(self, log):
        log.record_tool_call("vol.psscan", True, False, 0, 0)
        log.record_reason_call("reason_hypothesize", True, "hyp", {})
        log.record_finding("data was delivered", "SUSPECTED", "read.read_mail",
                           claim=normalize_claim(claim_kind="positive", category="delivery",
                                                 act="delivery", recipients=["x@ext.example"]))
        # evidence output shows a WhatsApp store; only Skype was parsed
        log.record_tool_call("ls /mnt/c/Users/U/AppData/Roaming", True, False, 0, 0,
                             stdout_excerpt="Skype\nWhatsApp\nMozilla")
        log.record_tool_call("misc.chat_db_export /mnt/c/Users/U/AppData/Roaming/Skype/main.db",
                             True, False, 0, 0)

    def test_present_unparsed_family_blocks(self, base_log):
        self._seed(base_log)
        r = _pre(base_log)
        assert any("whatsapp" in i and "never parsed" in i for i in r["blocking_issues"])
        assert not any("'skype'" in i for i in r["blocking_issues"])       # parsed

    def test_source_disposition_clears(self, base_log):
        self._seed(base_log)
        base_log.record_disposition("source", "whatsapp", "inapplicable")
        r = _pre(base_log)
        assert not any("whatsapp" in i for i in r["blocking_issues"])

    def test_no_comms_claim_no_duty(self, base_log):
        base_log.record_tool_call("ls /x", True, False, 0, 0, stdout_excerpt="WhatsApp")
        base_log.record_finding("x present", "SUSPECTED", "t")
        r = _pre(base_log)
        assert not any("whatsapp" in i for i in r["blocking_issues"])


class TestTierConcordance:
    """K-9: symmetric audit note when a recorded tier sits below what the
    deterministic contract computed — never an instruction to strengthen."""

    def test_under_recorded_finding_draws_the_note(self, base_log):
        log = base_log
        log.record_tool_call("vol.psscan", True, False, 0, 0)
        log.record_reason_call("reason_hypothesize", True, "hyp", {})
        log.record_finding("smallftpd executed", "LIKELY", "ez.pecmd",
                           claim=normalize_claim(claim_kind="positive", category="execution",
                                                 act="execution"),
                           gate_metadata={"tier_achievable": "CONFIRMED",
                                          "tier_rule": "execution"})
        r = _pre(log)
        w = [x for x in r["warnings"] if "concordance" in x]
        assert w and "recorded LIKELY" in w[0] and "reach CONFIRMED" in w[0]
        assert "not an instruction to strengthen" in w[0]

    def test_matching_tier_no_note(self, base_log):
        log = base_log
        log.record_finding("smallftpd executed", "CONFIRMED", "ez.pecmd",
                           gate_metadata={"tier_achievable": "CONFIRMED"})
        r = _pre(log)
        assert not any("concordance" in x for x in r["warnings"])


class TestBulkClassRegistry:
    """A4: bulk-pattern addresses (bounce daemons, no-reply) are kept in the
    registry FLAGGED — inventoried, never a mandatory disposition, never
    silently dropped (a bounce daemon can carry decisive DSN evidence)."""

    def test_bulk_rows_kept_flagged_and_never_block(self, base_log):
        log = base_log
        log.record_tool_call("vol.psscan", True, False, 0, 0)
        log.record_reason_call("reason_hypothesize", True, "hyp", {})
        log.record_finding("delivered to contact-a@ext.example", "CONFIRMED", "read.read_mail",
                           claim=normalize_claim(claim_kind="positive", category="delivery",
                                                 act="delivery", recipients=["contact-a@ext.example"]))
        cid = log.record_tool_call("read.read_mail -o /x/mail mode=senders field=any", True, False, 0, 0)
        log.annotate_tool_call(
            cid,
            observed_correspondents=["contact-a@ext.example", "mailer-daemon@x.example",
                                     "no-reply@shop.example"],
            observed_correspondent_stats={"contact-a@ext.example": {"from": 1, "to": 2},
                                          "mailer-daemon@x.example": {"from": 5, "to": 0},
                                          "no-reply@shop.example": {"from": 3, "to": 0}},
            correspondents_partial=False)
        idx = log.index()
        assert idx.correspondents["mailer-daemon@x.example"]["bulk"] is True
        assert idx.correspondents["mailer-daemon@x.example"]["from"] == 5   # stats kept
        r = _pre(log)
        blocking = " ".join(r["blocking_issues"])
        # a repeat bulk sender would previously have been "engaged" — never blocks
        assert "mailer-daemon" not in blocking and "no-reply" not in blocking
        inv = _pre_entry(log)["registry_inventory"]
        by = {c["address"]: c["status"] for c in inv["correspondents"]}
        assert by["mailer-daemon@x.example"] == "noise-class (address pattern)"
        assert by["no-reply@shop.example"] == "noise-class (address pattern)"

    def test_rfc_bulk_header_sender_flagged_and_never_blocks(self, base_log):
        # A2: an ESP/newsletter sender whose address carries no no-reply token
        # (so _IDENTITY_NOISE_RE misses it) but whose messages carry the
        # RFC bulk headers (List-Unsubscribe/List-Id/Precedence). High inbound
        # volume must not read as "engaged repeat correspondent".
        log = base_log
        log.record_tool_call("vol.psscan", True, False, 0, 0)
        log.record_reason_call("reason_hypothesize", True, "hyp", {})
        log.record_finding("delivered to contact-a@ext.example", "CONFIRMED", "read.read_mail",
                           claim=normalize_claim(claim_kind="positive", category="delivery",
                                                 act="delivery", recipients=["contact-a@ext.example"]))
        cid = log.record_tool_call("read.read_mail -o /x/mail mode=senders field=any", True, False, 0, 0)
        log.annotate_tool_call(
            cid,
            observed_correspondents=["contact-a@ext.example", "promo8x2k@esp.example"],
            observed_correspondent_stats={"contact-a@ext.example": {"from": 1, "to": 2},
                                          "promo8x2k@esp.example": {"from": 9, "to": 0}},
            observed_correspondent_bulk=["promo8x2k@esp.example"],
            correspondents_partial=False)
        idx = log.index()
        assert idx.correspondents["promo8x2k@esp.example"]["bulk"] is True
        assert idx.correspondents["promo8x2k@esp.example"]["from"] == 9   # stats kept
        r = _pre(log)
        blocking = " ".join(r["blocking_issues"])
        assert "1lxwip7emb" not in blocking   # inventoried, not a blocking leftover
        # a genuinely engaged correspondent (subject wrote TO them) still blocks
        cid2 = log.record_tool_call("read.read_mail -o /x/mail2 mode=senders field=any", True, False, 0, 0)
        log.annotate_tool_call(
            cid2, observed_correspondents=["handler-b@far.example"],
            observed_correspondent_stats={"handler-b@far.example": {"from": 1, "to": 1}},
            correspondents_partial=False)
        assert "handler-b@far.example" in " ".join(_pre(log)["blocking_issues"])


class TestDeviceInventoryDuty:
    """A11: an account-creation/persistence claim at ANY tier with removable
    media in evidence requires the device-install inventory (or a typed
    source disposition) — it may equally exonerate."""

    def _seed(self, log, with_inventory=False):
        log.record_tool_call("vol.psscan", True, False, 0, 0)
        log.record_tool_call("dotnet LECmd.dll -d /mnt/x/Users/Recent --csv /o", True,
                             False, 0, 0)          # removable media in scope (LNK parse ran)
        log.record_reason_call("reason_hypothesize", True, "hyp", {})
        log.record_finding("account svc_x created in an interactive session", "SUSPECTED", "ez.evtxecmd",
                           claim=normalize_claim(claim_kind="positive", category="persistence",
                                                 act="account_creation", session_type="interactive",
                                                 principal="svc_x"))
        if with_inventory:
            log.record_tool_call("misc.device_install_inventory /mnt/x/setupapi.dev.log",
                                 True, False, 0, 0)

    def test_suspected_claim_with_removable_blocks_without_inventory(self, base_log):
        self._seed(base_log)
        r = _pre(base_log)
        assert any("device_install_inventory never ran" in i for i in r["blocking_issues"])

    def test_inventory_or_disposition_clears(self, base_log):
        self._seed(base_log, with_inventory=True)
        r = _pre(base_log)
        assert not any("device_install_inventory" in i for i in r["blocking_issues"])


class TestChatFamiliesDataDriven:
    """A6: the comms-presence duty covers the data-driven family table
    (incl. QQ/WeChat), not a hardcoded inline list."""

    def test_qq_and_wechat_presence_block(self, base_log):
        from tools._gates._manifests import CHAT_FAMILIES
        assert {"qq", "wechat", "discord"} <= set(CHAT_FAMILIES)
        log = base_log
        log.record_tool_call("vol.psscan", True, False, 0, 0)
        log.record_reason_call("reason_hypothesize", True, "hyp", {})
        log.record_finding("delivered to x", "SUSPECTED", "read.read_mail",
                           claim=normalize_claim(claim_kind="positive", category="delivery",
                                                 act="delivery", recipients=["x@ext.example"]))
        log.record_tool_call("ls '/mnt/c/Users/U/AppData/Roaming/Tencent'", True, False, 0, 0,
                             stdout_excerpt="QQ\\nWeChat Files")
        r = _pre(log)
        blocking = " ".join(r["blocking_issues"])
        assert "qq" in blocking and "wechat" in blocking
        log.record_disposition("source", "qq", "absent_from_evidence")
        log.record_disposition("source", "wechat", "absent_from_evidence")
        r2 = _pre(log)
        assert "wechat" not in " ".join(r2["blocking_issues"])


class TestA2v2InboundVolumeNotEngaged:
    """A2-v2: inbound volume is NOT engagement. A repeat inbound-only sender
    (no wrote-to, no roster, no chat) goes to the report inventory, never blocks
    — only two-way / roster / chat correspondents block."""

    def test_repeat_inbound_only_does_not_block(self, base_log):
        base_log.record_tool_call("vol.psscan", True, False, 0, 0)
        base_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        base_log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        base_log.record_finding("delivered to contact-a@ext.example", "CONFIRMED", "read.read_mail",
                                claim=normalize_claim(claim_kind="positive", category="delivery",
                                                      act="delivery", recipients=["contact-a@ext.example"]))
        cid = base_log.record_tool_call("read.read_mail -o /x/mail mode=senders field=any", True, False, 0, 0)
        base_log.annotate_tool_call(
            cid,
            observed_correspondents=["contact-a@ext.example", "spamco@promo.example", "handler-b@far.example"],
            observed_correspondent_stats={"contact-a@ext.example": {"from": 1, "to": 2},   # two-way -> block
                                          "spamco@promo.example": {"from": 9, "to": 0},     # repeat inbound -> inventory
                                          "handler-b@far.example": {"from": 1, "to": 1}},   # wrote-to -> block
            correspondents_partial=False)
        r = _pre(base_log)
        blocking = " ".join(r["blocking_issues"])
        assert "spamco@promo.example" not in blocking          # repeat inbound NOT blocking
        assert "handler-b@far.example" in blocking             # wrote-to still blocks
        assert any("inbound-only correspondent" in w and "spamco" in w for w in r["warnings"])
        inv = _pre_entry(base_log)["registry_inventory"]
        by = {c["address"]: c["status"] for c in inv["correspondents"]}
        assert by["spamco@promo.example"] == "inventory"

    def test_roster_inbound_still_blocks(self, base_log):
        base_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        base_log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        base_log.record_finding("delivered to contact-a@ext.example", "CONFIRMED", "read.read_mail",
                                claim=normalize_claim(claim_kind="positive", category="delivery",
                                                      act="delivery", recipients=["contact-a@ext.example"]))
        cid = base_log.record_tool_call("read.read_mail -o /x/mail mode=senders field=any", True, False, 0, 0)
        base_log.annotate_tool_call(cid, observed_correspondents=["suspect@ext.example"],
                                    observed_correspondent_stats={"suspect@ext.example": {"from": 3, "to": 0}},
                                    correspondents_partial=False)
        _roster(base_log, ["suspect", "suspect.ext"])
        assert "suspect@ext.example" in " ".join(_pre(base_log)["blocking_issues"])
