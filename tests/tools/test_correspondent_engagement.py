"""Correspondent exhaustion keys on ENGAGEMENT by the subject, not inbox volume.

A correspondent blocks Report (until referenced by a finding or settled with a
typed disposition) only when the mailbox owner WROTE TO it, it is a chat
partner, or it matches the case roster. Header-field labels parsed out of
pffexport trees are not correspondents at all; inbound-only senders and
third-party To: lists (spam, newsletters, mass mail) are report inventory.
"""
import mailbox
from email.message import EmailMessage
from unittest.mock import patch

import pytest

from core.execution_log import ExecutionLog
from core import mail_roster as MR
from tools._gates._claims import normalize_claim

OWNER = "subject@case.example"


@pytest.fixture
def base_log(tmp_path):
    l = ExecutionLog()
    l.configure("CORR-ENG", str(tmp_path / "trace.json"), save_session=False)
    for cur, nxt in (("Triage", "Collect"), ("Collect", "Analyze"), ("Analyze", "Report")):
        l.record_dair_call(cur, "", True, nxt, "", "push", "")
    l.record_dair_call("Analyze", "", False, "", "", "stay", "")
    l.record_reason_call("reason_plan", True, "plan", {})
    l.record_reason_call("reason_synthesize", True, "ok", {})
    return l


def _pre(log):
    from tools.reasoning import reason_pre_report_check
    if log._current_phase != "Report":
        log.record_phase_transition("Report", "follow_up_done", trigger="test")
    with patch("core.execution_log.log", log):
        return reason_pre_report_check()


def _recipient_finding(log, recipient="buyer@ext.example"):
    log.record_tool_call("vol.psscan", True, False, 0, 0)
    log.record_reason_call("reason_hypothesize", True, "hyp", {})
    log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
    log.record_finding(f"data delivered to {recipient}", "CONFIRMED", "read.mail",
                       claim=normalize_claim(claim_kind="positive", category="delivery",
                                             act="delivery", recipients=[recipient]))


def _mail_stamp(log, stats, owners=(OWNER,), store="/x/exports/mail", v2=True, bulk=()):
    cid = log.record_tool_call(f"read.mail -o {store} mode=senders field=any", True, False, 0, 0)
    kw = dict(observed_correspondents=sorted(stats),
              observed_correspondent_stats=stats,
              observed_correspondent_bulk=list(bulk),
              correspondents_partial=False)
    if v2:
        kw.update(mailbox_owners=list(owners), correspondent_direction=True)
    log.annotate_tool_call(cid, **kw)
    return cid


def _blocking(r):
    return " ".join(i for i in r["blocking_issues"] if "engaged correspondent" in i)


# ── parsing: header labels are never correspondents ─────────────────────────

class TestLabelJunkRejected:
    def test_recipients_txt_labels_are_field_names(self):
        rc = MR._parse_recipients_txt(
            "Display name:\t\t'S. A. Carlito'\nEmail address:\t\tsa.ed2@outlook.example\n"
            "Address type:\t\tSMTP\nRecipient type:\t\tTo\n\n"
            "Display name:\t\tBob\nEmail address:\t\tbob@ext.example\n"
            "Address type:\t\tSMTP\nRecipient type:\t\tCC\n")
        assert rc["to"] == ['"S. A. Carlito" <sa.ed2@outlook.example>']
        assert rc["cc"] == ['"Bob" <bob@ext.example>']

    @pytest.mark.parametrize("junk", ["address type", "recipient type", "recipients",
                                      "email address", "kylie", "kylie normandy", "smtp"])
    def test_validator_rejects_labels_and_bare_names(self, junk):
        assert not MR.is_valid_email(junk)

    def test_pff_outlook_fallback_yields_only_addresses(self, tmp_path):
        d = tmp_path / "Sent Items" / "Message00001"
        d.mkdir(parents=True)
        (d / "InternetHeaders.txt").write_text("")
        (d / "OutlookHeaders.txt").write_text(
            f"Sender name:\tSubject\nSender email address:\t{OWNER}\nSubject:\thi\n")
        (d / "Recipients.txt").write_text(
            "Display name:\tNina\nEmail address:\tnina@qq.example\n"
            "Address type:\tSMTP\nRecipient type:\tTo\n")
        r = MR.roster_for_store(str(tmp_path))
        assert r["observed"] == sorted([OWNER, "nina@qq.example"])
        assert r["owners"] == [OWNER]
        assert r["stats"]["nina@qq.example"]["owner_to"] == 1

    def test_legacy_stamp_labels_never_enter_the_registry(self, base_log):
        _mail_stamp(base_log, {"address type": {"from": 0, "to": 18},
                               "recipient type": {"from": 0, "to": 18},
                               "pal@ext.example": {"from": 1, "to": 1}}, v2=False)
        corr = base_log.index().correspondents
        assert "address type" not in corr and "recipient type" not in corr
        assert "pal@ext.example" in corr

    def test_tracking_suffix_unwrapped(self):
        assert MR.addresses("x <adcapfire@gmail.com.readnotify.com>") == ["adcapfire@gmail.com"]


# ── owner derivation + owner_to from a real mbox store ──────────────────────

def _msg(frm, to, subj="s", **hdrs):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = frm, to, subj
    for k, v in hdrs.items():
        m[k.replace("_", "-")] = v
    m.set_content("body")
    return m


class TestOwnerDirection:
    def _store(self, tmp_path):
        store = tmp_path / "exports" / "mbox"
        store.mkdir(parents=True)
        sent = mailbox.mbox(str(store / "Sent Mail.mbox"))
        sent.add(_msg(OWNER, "Buyer <buyer@ext.example>"))
        sent.add(_msg(OWNER, "friend@ext.example, subject.alt@other.example"))
        sent.add(_msg(OWNER, OWNER))                                   # note-to-self
        sent.close()
        inbox = mailbox.mbox(str(store / "Inbox.mbox"))
        inbox.add(_msg("spammer@spam.example", "a@x.example, b@y.example, " + OWNER))
        inbox.add(_msg("news@shop.example", OWNER, List_Unsubscribe="<mailto:u@shop.example>"))
        inbox.add(_msg("stranger@ext.example", OWNER))
        inbox.close()
        return store

    def test_roster_owner_and_direction(self, tmp_path):
        r = MR.roster_for_store(str(self._store(tmp_path)))
        assert r["owners"] == [OWNER]
        st = r["stats"]
        assert st["buyer@ext.example"]["owner_to"] == 1
        assert st["subject.alt@other.example"]["owner_to"] == 1
        assert st["a@x.example"] == {"from": 0, "to": 1, "owner_to": 0}   # spam To: list
        assert st["stranger@ext.example"]["owner_to"] == 0
        assert st[OWNER]["owner_to"] == 0                                   # self-send
        assert "news@shop.example" in r["bulk"]

    def test_read_mail_stamps_owner_direction(self, tmp_path, base_log):
        from tools.read_output import read_mail
        store = self._store(tmp_path)
        fn = getattr(read_mail, "fn", read_mail)
        with patch("core.execution_log.log", base_log), \
                patch("tools.read_output._selflog",
                      lambda cmd, out: base_log.record_tool_call(cmd, True, False, 0, 0)):
            r = fn(str(store), mode="senders")
        e = base_log.index().by_call_id[r["_trudi_call_id"]]
        assert e["correspondent_direction"] is True
        assert e["mailbox_owners"] == [OWNER]
        assert e["observed_correspondent_stats"]["buyer@ext.example"]["owner_to"] == 1


# ── pre-report check ────────────────────────────────────────────────────────

class TestPreReportEngagement:
    STATS = {
        OWNER: {"from": 3, "to": 5, "owner_to": 0},
        "buyer@ext.example": {"from": 1, "to": 1, "owner_to": 1},      # referenced
        "contact@ext.example": {"from": 2, "to": 3, "owner_to": 2},    # owner wrote to
        "spammer@spam.example": {"from": 1, "to": 1, "owner_to": 0},   # self-addressed spam
        "a@x.example": {"from": 0, "to": 4, "owner_to": 0},            # third-party To: list
        "stranger@ext.example": {"from": 9, "to": 0, "owner_to": 0},   # inbound only
    }

    def test_inbound_only_and_third_party_lists_do_not_block(self, base_log):
        _recipient_finding(base_log)
        _mail_stamp(base_log, self.STATS)
        r = _pre(base_log)
        b = _blocking(r)
        for a in ("spammer@spam.example", "a@x.example", "stranger@ext.example", OWNER):
            assert a not in b
            assert a in r["correspondents_auto_noise"]

    def test_owner_sent_contact_blocks_until_referenced(self, base_log):
        _recipient_finding(base_log)
        _mail_stamp(base_log, self.STATS)
        r = _pre(base_log)
        assert "contact@ext.example" in _blocking(r)
        assert "1 engaged correspondent" in _blocking(r)
        # referencing it in a finding settles it
        base_log.record_finding("contact@ext.example also received the file", "SUSPECTED", "read.mail",
                                claim=normalize_claim(claim_kind="positive", category="delivery",
                                                      act="delivery",
                                                      recipients=["contact@ext.example"]))
        assert _blocking(_pre(base_log)) == ""

    def test_owner_sent_contact_blocks_until_dispositioned(self, base_log):
        _recipient_finding(base_log)
        cid = _mail_stamp(base_log, self.STATS)
        assert "contact@ext.example" in _blocking(_pre(base_log))
        base_log.record_disposition("correspondent", "contact@ext.example", "out_of_scope",
                                    evidence_call_ids=[cid])
        assert _blocking(_pre(base_log)) == ""

    def test_noise_label_refused_for_owner_sent_contact(self, base_log):
        from tools.misc import record_disposition
        _recipient_finding(base_log)
        cid = _mail_stamp(base_log, self.STATS)
        fn = getattr(record_disposition, "fn", record_disposition)
        with patch("core.execution_log.log", base_log), patch("tools.misc.log", base_log, create=True):
            r = fn("correspondent", "contact@ext.example", "noise", evidence_call_ids=[cid],
                   input_call_ids=[cid])
            ok = fn("correspondent", "stranger@ext.example", "noise", evidence_call_ids=[cid],
                    input_call_ids=[cid])
        assert r["success"] is False and r.get("detail_gate") == "engaged_correspondent_not_noise"
        assert ok["success"] is True

    def test_inventory_statuses(self, base_log):
        _recipient_finding(base_log)
        _mail_stamp(base_log, self.STATS)
        _pre(base_log)
        pre = [e for e in base_log._entries if e.get("tool") == "reason_pre_report_check"][-1]
        by = {c["address"]: c["status"] for c in pre["registry_inventory"]["correspondents"]}
        assert by["buyer@ext.example"] == "referenced"
        assert by["contact@ext.example"] == "engaged (open)"
        assert by["a@x.example"] == "inventory"
        assert by["stranger@ext.example"] == "inventory"

    def test_near_alias_still_surfaced(self, base_log):
        _recipient_finding(base_log)
        _mail_stamp(base_log, {"nina_kwai@qq.example": {"from": 6, "to": 7, "owner_to": 6},
                               "nina_kwa1@qq.example": {"from": 0, "to": 2, "owner_to": 2}})
        r = _pre(base_log)
        assert any("near-alias" in w and "nina_kwa1@qq.example" in w for w in r["warnings"])
        b = _blocking(r)
        assert "nina_kwa1@qq.example" in b and "nina_kwai@qq.example" in b

    def test_v2_stamp_supersedes_legacy_stamp_of_same_store(self, base_log):
        _recipient_finding(base_log)
        # legacy: the spammer looks two-way; the re-stamp shows the owner never wrote to it
        _mail_stamp(base_log, {"spammer@spam.example": {"from": 1, "to": 1}}, v2=False)
        assert "spammer@spam.example" in _blocking(_pre(base_log))   # conservative fallback
        assert any("older read.mail" in w for w in _pre(base_log)["warnings"])
        _mail_stamp(base_log, {"spammer@spam.example": {"from": 1, "to": 1, "owner_to": 0}})
        r = _pre(base_log)
        assert "spammer@spam.example" not in _blocking(r)
        assert not any("older read.mail" in w for w in r["warnings"])

    def test_legacy_inbound_only_does_not_block(self, base_log):
        _recipient_finding(base_log)
        _mail_stamp(base_log, {"a@x.example": {"from": 0, "to": 4}}, v2=False)
        assert "a@x.example" not in _blocking(_pre(base_log))


class TestChatEngagement:
    def _chat(self, log, participants, engaged=None, owners=None,
              path="/mnt/c/Users/U/AppData/Roaming/Skype/live#3asubject/main.db"):
        cid = log.record_tool_call(f"misc.chat_db_export {path}", True, False, 0, 0)
        kw = dict(chat_db_export=True, observed_correspondents=participants,
                  correspondents_partial=False)
        if engaged is not None:
            kw.update(chat_engaged=engaged, chat_owners=owners or [])
        log.annotate_tool_call(cid, **kw)
        return cid

    def test_chat_partner_counts_system_and_owner_do_not(self, base_log):
        _recipient_finding(base_log)
        self._chat(base_log, ["echo123", "live:subject", "k.partner", "contact_only"],
                   engaged=["k.partner"], owners=["live:subject"])
        b = _blocking(_pre(base_log))
        assert "k.partner" in b
        for h in ("echo123", "live:subject", "contact_only"):
            assert h not in b

    def test_legacy_chat_stamp_excludes_system_and_path_owner(self, base_log):
        _recipient_finding(base_log)
        self._chat(base_log, ["echo123", "live:subject", "k.partner", "kylie normandy"])
        corr = base_log.index().correspondents
        assert "kylie normandy" not in corr                  # display name, not a handle
        b = _blocking(_pre(base_log))
        assert "k.partner" in b
        assert "echo123" not in b and "live:subject" not in b


class TestSkypeParserEngagement:
    def test_contacts_only_and_owner_not_engaged(self, tmp_path):
        import sqlite3
        from core.chat_db import parse_chat_db
        db = tmp_path / "main.db"
        c = sqlite3.connect(db)
        c.executescript("""
            CREATE TABLE Messages(timestamp INT, author TEXT, from_dispname TEXT, chatname TEXT,
                                  dialog_partner TEXT, body_xml TEXT);
            CREATE TABLE Contacts(skypename TEXT);
            CREATE TABLE Chats(dialog_partner TEXT);
            CREATE TABLE Accounts(skypename TEXT);
            CREATE TABLE Transfers(starttime INT, partner_handle TEXT);
            INSERT INTO Accounts VALUES('live:subject');
            INSERT INTO Messages VALUES(1466000000,'live:subject','S','c','k.partner','hi');
            INSERT INTO Messages VALUES(1466000100,'k.partner','K','c','','yo');
            INSERT INTO Contacts VALUES('echo123');
            INSERT INTO Contacts VALUES('contact_only');
        """)
        c.commit(); c.close()
        r = parse_chat_db(str(db))
        assert r["success"]
        assert r["owners"] == ["live:subject"]
        assert r["engaged"] == ["k.partner"]
        assert {"echo123", "contact_only"} <= set(r["participants"])
