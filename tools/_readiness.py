"""Shared deterministic readiness policy; no model calls or trace mutations."""
import os
import re
from core.findings import active_findings, current_entries, finding_view
from core.readiness import issue_records, state_fingerprint

# Recorded synthesis rounds after which open reviewer objections are carried
# into the report as stated limitations instead of blocking it.
SYNTH_ROUND_CAP = int(os.environ.get("TRUDI_SYNTH_ROUND_CAP") or "2")


def assess_readiness(log, include_synthesis=True):
    from tools.reasoning import (_split_tier_blockers, _is_undertier_blocker,
                                 _has_unnegated_blocker, _is_builtin, _is_placeholder)
    entries = current_entries(log._entries)

    has_plan = any(
        e["type"] == "reason_call" and e.get("tool") == "reason_plan"
        for e in entries
    )
    has_synthesize = any(
        e["type"] == "reason_call" and e.get("tool") == "reason_synthesize" and e.get("success") is not False
        for e in entries
    )
    has_hypothesize = any(
        e["type"] == "reason_call" and e.get("tool") == "reason_hypothesize"
        for e in entries
    )
    evaluate_calls = sum(
        1 for e in entries
        if e["type"] == "reason_call" and e.get("tool") == "reason_evaluate_finding"
    )
    confirmed_findings = sum(
        1 for e in entries
        if e["type"] == "finding" and e.get("confidence", "").upper() == "CONFIRMED"
    )
    tool_calls = sum(1 for e in entries if e["type"] == "tool_call")
    total_input_tokens = sum(e.get("input_tokens", 0) for e in entries if e["type"] == "reason_call")
    total_output_tokens = sum(e.get("output_tokens", 0) for e in entries if e["type"] == "reason_call")

    issues: list[str] = [f"Finding lifecycle anomaly: {a}" for a in finding_view(log._entries).anomalies]
    warnings: list[str] = []

    if len(entries) == 0:
        issues.append("Execution trace is empty — start_execution_log was not called before tool runs")
    if not has_plan:
        issues.append("reason.plan was not called — mandatory before tool selection")
    if include_synthesis and not has_synthesize:
        issues.append("reason.synthesize was not called — mandatory before writing report")

    latest_synth = None
    synth_unresolved: list = []
    correspondents_auto_noise: list = []
    for e in reversed(entries):
        if e.get("type") == "reason_call" and e.get("tool") == "reason_synthesize":
            latest_synth = e
            break
    if include_synthesis and latest_synth is not None:
        structured = ([] if "review_issues" in latest_synth else latest_synth.get("blockers"))  # list | None (absent on legacy traces)
        if structured is not None:
            # Tier opinions (either direction) are advisories: the recorded tier
            # was set by the evaluate reviewer's cap and the record gates; a
            # later synthesize disagreeing cannot be closed with evidence.
            # Every factual blocker remains open until explicitly resolved.
            tier_items = set(_split_tier_blockers(structured)[1])
            undertier = [b for b in structured if _is_undertier_blocker(b) or b in tier_items]
            real = [b for b in structured if b not in undertier]
            if real:
                issues.append(
                    "Latest reason.synthesize lists unresolved BLOCKERS: "
                    + "; ".join(real)
                    + ". Resolve them (run the tools or record why they are "
                    "inapplicable), then re-run reason.synthesize before Report."
                )
            if undertier:
                warnings.append(
                    "reason.synthesize judges these findings UNDER-tiered (safe to "
                    "report as-is): " + "; ".join(undertier)
                    + ". To upgrade, re-run reason.evaluate_finding on the finding "
                    "with the new corroborating input_call_ids; on SUPPORTED, "
                    "re-record via record_finding(confidence=CONFIRMED, "
                    "supersedes=<old finding call_id>). Not required for Report."
                )
        else:
            # Legacy fallback for pre-structured traces: parse the prose conclusion.
            latest_synthesize = latest_synth.get("conclusion") or ""
            m = re.search(
                r"(?:^|\n)\s*BLOCKERS?(?:\s*\([^)]*\))?\s*:\s*(.*?)(?=\n\s*[A-Z][A-Z _-]{2,}(?:\s*\([^)]*\))?\s*:|\Z)",
                latest_synthesize,
                re.IGNORECASE | re.DOTALL,
            )
            if m:
                blocker_text = m.group(1).strip()
                if blocker_text and not re.fullmatch(
                    r"(?:none|no blockers?|n/a|not applicable|0)[.\s-]*",
                    blocker_text,
                    re.IGNORECASE,
                ):
                    issues.append(
                        "Latest reason.synthesize still lists BLOCKERS. Resolve the "
                        "blockers, run the requested tools or record why they are "
                        "inapplicable, then re-run reason.synthesize before Report."
                    )
            elif _has_unnegated_blocker(latest_synthesize):
                issues.append(
                    "Latest reason.synthesize still labels one or more gaps as "
                    "BLOCKER. Return to Triage/Collect/Analyze as needed, run the "
                    "missing evidence work, then re-run reason.synthesize before "
                    "Report. Do not try to satisfy this by rewording findings."
                )

    if include_synthesis:
        from core.review_issues import review_state, completed_rounds
        # Bounded review: after SYNTH_ROUND_CAP recorded rounds the reviewer's
        # remaining objections no longer block — they are carried into the
        # report as stated, unresolved objections. A model reviewer that is
        # never satisfied must not prevent an honest report.
        rounds = completed_rounds(log._entries)
        capped = rounds >= SYNTH_ROUND_CAP

        def _block_or_carry(msg: str) -> None:
            if capped:
                synth_unresolved.append(f"UNRESOLVED after {rounds} review rounds — {msg}")
            else:
                issues.append(msg)

        for issue in review_state(log._entries):
            if issue['status'] == 'open' and issue['kind'] != 'advisory':
                _block_or_carry(f"{issue['issue_id']} [{issue['kind']}]: {issue['message']}")
            elif issue['status'] == 'limitation':
                synth_unresolved.append(f"{issue['issue_id']}: {issue['message']} — "
                                        f"{issue['resolution']['reason']}")
        latest_attempt = next((e for e in reversed(log._entries)
                               if e.get('tool') == 'reason_synthesize'), None)
        if latest_attempt and latest_attempt.get('success') is False:
            if capped:
                warnings.append("Latest synthesis attempt failed; the report rests on the "
                                f"last recorded review (round {rounds}).")
            else:
                issues.append("Latest synthesis failed; repair review before reporting")
        last_review = next((e for e in reversed(log._entries)
                            if e.get('tool') == 'reason_synthesize'
                            and e.get('synthesis_fingerprint')), None)
        if last_review:
            current = state_fingerprint(log._entries, log._case_id, include_synthesis=False,
                                        scope='claims')
            if current != last_review['synthesis_fingerprint']:
                changed = sorted(e['call_id'] for e in active_findings(log._entries)
                                 if int(e['call_id']) > int(last_review['call_id']))
                _block_or_carry("Synthesis snapshot is stale; findings/dispositions changed "
                                "after the last cross-finding review"
                                + (f" (findings not cross-reviewed: {changed})" if changed else ""))

    # Case-question gate (typed). The question is DECLARED — reason.plan(
    # case_question=…) or dair_assess(case_question=…) — and a CONFIRMED/LIKELY
    # finding answers it by declaring answers_case_question=True. Nothing here
    # parses "CASE_QUESTION:" out of prose or bag-of-words-matches descriptions.
    case_question = ""
    for e in reversed(entries):
        cq = e.get("case_question")
        if isinstance(cq, str) and cq.strip():
            case_question = cq.strip()
            break
    if case_question:
        addressed = any(
            e.get("type") == "finding"
            and (e.get("confidence") or "").upper() in {"CONFIRMED", "LIKELY"}
            and bool((e.get("claim") or {}).get("answers_case_question"))
            for e in entries
        )
        if not addressed:
            issues.append(
                f"Case question \"{case_question}\" is not answered by any CONFIRMED or "
                f"LIKELY finding that declares answers_case_question=True. Record the "
                f"finding that answers it (pass answers_case_question=True) before Report."
            )
        else:
            # Competing-recipient coherence (warning). When the answer is a
            # delivery/dissemination finding but OTHER delivery findings name
            # DIFFERENT recipients, the single answer may have resolved one
            # thread while an equally-live one stands. Symmetric: it names the
            # fork, never which side is right. Warning only.
            _acq_recips: set = set()
            _other_recips: set = set()
            for e in entries:
                if e.get("type") != "finding":
                    continue
                c = e.get("claim") or {}
                if c.get("act") not in ("delivery", "possession"):
                    continue
                rset = {str(r).lower() for r in (c.get("recipients") or []) if r}
                if c.get("answers_case_question"):
                    _acq_recips |= rset
                else:
                    _other_recips |= rset
            _extra = _other_recips - _acq_recips
            if _acq_recips and _extra:
                warnings.append(
                    f"The case-question answer names recipient(s) "
                    f"{sorted(_acq_recips)[:3]}, but other delivery findings name "
                    f"different recipient(s) {sorted(_extra)[:3]} that the answer does not. "
                    f"Confirm the answer resolves the right dissemination thread — fold the "
                    f"other recipient in if it is also live, or disposition it."
                )

    if evaluate_calls < confirmed_findings:
        warnings.append(
            f"{confirmed_findings} CONFIRMED finding(s) but only {evaluate_calls} "
            "reason.evaluate_finding call(s) — each CONFIRMED finding requires evaluation"
        )
    if not has_hypothesize:
        warnings.append(
            "reason.hypothesize was never called — required for any unusual artifact, "
            "orphaned process, or unexpected network connection"
        )

    # Cross-host correlation gate (warning, not blocking). When findings span
    # multiple hosts but no correlate.process_to_file / correlate.network_to_process
    # call was made, per-host findings will land in synthesis as isolated slices
    # rather than a coherent cross-host timeline. Warning-level keeps single-host
    # cases unaffected and lets the agent recover by running the missing call.
    try:
        from tools.dair import _norm_host
        finding_hosts: set[str] = set()
        for e in entries:
            if e.get("type") == "dair_call":
                for h in e.get("observed_hosts") or []:
                    finding_hosts.add(_norm_host(h))
                for pv in e.get("candidate_pivots") or []:
                    if isinstance(pv, dict) and pv.get("kind") == "host" and pv.get("value"):
                        finding_hosts.add(_norm_host(pv["value"]))
        finding_hosts.discard("")
        if len(finding_hosts) >= 2:
            has_correlate = any(
                e.get("type") == "tool_call"
                and isinstance(e.get("cmd"), str)
                and (
                    "correlate_process_to_file" in e["cmd"]
                    or "correlate_network_to_process" in e["cmd"]
                )
                for e in entries
            )
            if not has_correlate:
                hosts_str = ", ".join(sorted(finding_hosts)[:5])
                warnings.append(
                    f"Findings span {len(finding_hosts)} hosts ({hosts_str}"
                    f"{'…' if len(finding_hosts) > 5 else ''}) but no "
                    f"correlate.process_to_file or correlate.network_to_process "
                    f"call was made. Call them (with no PID/IP/path filter) "
                    f"before reason.synthesize so the timeline reflects "
                    f"cross-host joins, not isolated per-host slices."
                )
    except Exception as _e:
        import sys as _sys
        print(f"[TRUDI WARN] cross-host correlation check failed: {_e}",
              file=_sys.stderr)

    # Narration auditing is explicit and cached, never an implicit model call.
    audit_summary = {}
    audit = next((e for e in reversed(log._entries)
                  if e.get("tool") == "reason_audit_findings" and e.get("audit_result")), None)
    if audit:
        audit_summary = audit["audit_result"].get("summary", {})
        candidates = audit["audit_result"].get("candidates", [])
        if candidates:
            warnings.append(f"{len(candidates)} narration audit candidate(s) need adjudication; "
                            "run reason.audit_findings after relevant finding changes.")

    # ── Structural-integrity checks (typed) ─────────────────────────────────
    # Catch the loose ends that let a verdict ship structurally wrong even when
    # every individual finding passed its record-time gates. Every check keys on
    # the DECLARED shape of findings / hypotheses / dispositions and on
    # server-stamped registries — never on the wording of a description:
    #   #1 (blocking) a created account whose controller was never
    #       established and was never parked by a typed disposition;
    #   #2 (warning) multiple exfil channel families; (blocking) a declared
    #       channel whose source set was never examined;
    #   #3 (blocking) observed correspondents referenced by no finding/disposition;
    #   #4 (blocking) a contested principal never driven to a verdict;
    #   #5 (blocking) a human/account attribution without a logon inventory;
    #   #6 (blocking) a surfaced principal candidate left undispositioned.
    #
    # Each check runs under its OWN guard — a single bare except here used to
    # silently void all six checks whenever any one of them raised.
    def _guarded_check(_n, _fn):
        try:
            _fn()
        except Exception as _e:
            import sys as _sys
            print(f"[TRUDI WARN] pre_report structural check #{_n} failed: {_e}",
                  file=_sys.stderr)

    from tools._gates._entities import norm_entity, entity_matches
    from tools._gates._dispositions import (find_disposition, disposition_call,
                                            disposition_batch_hint,
                                            PARKING, SOURCE_WAIVER_REASONS_ALL)
    from tools._gates._session import has_logon_enumeration
    from tools._gates._claims import CORE_ACTS

    idx_all = log.index()
    s_findings = [e for e in entries if e.get("type") == "finding"]
    _PRINCIPAL_SETTLED = ("excluded", "not_a_principal", "controller_unknown",
                          "evidence_unavailable", "refuted", "same_as")

    def _ftier(e):
        return (e.get("confidence") or "").upper()

    def _claim(e) -> dict:
        c = e.get("claim")
        return c if isinstance(c, dict) else {}

    def _principal_norms(e) -> set:
        c = _claim(e)
        out = set(c.get("entities_norm") or [])
        if c.get("principal_norm"):
            out.add(c["principal_norm"])
        return out

    def _established(p_norm: str) -> bool:
        """A CONFIRMED/LIKELY finding binds this principal to an actor — its
        record-time gate already required the session artifact."""
        for e in s_findings:
            if _ftier(e) not in {"CONFIRMED", "LIKELY"}:
                continue
            c = _claim(e)
            if c.get("principal_norm") == p_norm and c.get("actor_kind") in ("human", "account"):
                return True
            if c.get("session_binding_call_ids") and p_norm in _principal_norms(e):
                return True
        return False

    def _settled(p_norm: str, reasons) -> bool:
        return find_disposition(idx_all, "principal", p_norm, reasons=reasons) is not None

    # ── Relevance model ──────────────────────────────────────────────────
    # A registry identity is MANDATORY (must be settled before Report) only
    # when it is (a) a forced DAIR candidate / a principal the agent declared
    # created or interactively logged on, (b) a match against the case roster
    # the operator declared (misc.knowns_pattern_generate, server-stamped), or
    # (c) engaged (the mailbox owner wrote to it / chat exchange — check #3).
    # Everything else the registries hold is rendered into the report as an
    # inventory, never a blocker and never a disposition.
    _roster_terms = list((getattr(idx_all, "roster", None) or {}).keys())

    def _roster_match(name: str) -> bool:
        return bool(name) and any(entity_matches(name, t) for t in _roster_terms)

    from core.mail_roster import registry_record_engaged as _corr_engaged

    _forced: dict = {}          # norm → (display, how)
    for _e in entries:
        if _e.get("type") != "dair_call":
            continue
        for _pv in _e.get("candidate_pivots") or []:
            if (isinstance(_pv, dict) and str(_pv.get("kind") or "").lower() == "principal"
                    and str(_pv.get("cue") or "").lower() == "forced"):
                _v = str(_pv.get("value") or "")
                if norm_entity(_v):
                    _forced.setdefault(norm_entity(_v), (_v, "forced principal candidate"))
        for _op in _e.get("observed_principals") or []:
            if isinstance(_op, dict) and str(_op.get("cue") or "").lower() in ("created", "interactive_logon"):
                _v = str(_op.get("name") or "")
                if norm_entity(_v) and "@" not in _v:
                    _forced.setdefault(norm_entity(_v), (_v, f"declared {_op.get('cue')} principal"))

    registry_inventory: dict = {"correspondents": [], "identities": [], "principals": [],
                                "roster": _roster_terms[:200]}

    def _check_1():
        # #1 — accounts DECLARED as created (claim.act=account_creation) in
        # CONFIRMED/LIKELY findings must have a controller established or be
        # parked / excluded by a typed disposition.
        created: dict = {}          # norm → display name
        for e in s_findings:
            if _ftier(e) in {"CONFIRMED", "LIKELY"} and _claim(e).get("act") == "account_creation":
                c = _claim(e)
                # The created account is the declared `principal`. Only when
                # none was declared do the entities stand in — minus built-in
                # groups and placeholders, which must never be demanded as
                # "created accounts".
                if c.get("principal"):
                    raws = [c.get("principal")]
                else:
                    raws = [r for r in (c.get("entities") or [])
                            if not _is_builtin(r) and not _is_placeholder(r)]
                for raw in raws:
                    n = norm_entity(raw)
                    if n:
                        created.setdefault(n, str(raw))
        for p, shown in sorted(created.items()):
            if _established(p) or _settled(p, _PRINCIPAL_SETTLED):
                continue
            issues.append(
                f"Created account '{shown}' (controller unestablished) is declared in a CONFIRMED/LIKELY "
                f"finding but no finding establishes who controls it (a CONFIRMED/LIKELY "
                f"finding with principal='{shown}' and a session binding) and no typed "
                f"disposition parks or excludes it. Pull the authentication artifact "
                f"(Security 4624/4625 logon type + source address) and attribute it, "
                f"or record {disposition_call('principal', shown, 'controller_unknown')} "
                f"before Report."
            )

    def _check_2():
        # #2 — channel families across CONFIRMED/LIKELY egress findings (warning),
        # and the declared-channel arithmetic (blocking): a declared channel's
        # manifest source set must have been examined or dispositioned.
        channels = {_claim(e).get("channel") for e in s_findings
                    if _ftier(e) in {"CONFIRMED", "LIKELY"} and _claim(e).get("act") == "egress"}
        channels.discard("") ; channels.discard(None)
        if len(channels) >= 2:
            warnings.append(
                f"{len(channels)} distinct exfiltration channels appear in "
                f"CONFIRMED/LIKELY findings ({', '.join(sorted(channels))}). "
                f"Enumerate ALL candidate channels and ensure the verdict "
                f"headlines the strongest-evidenced one — a transfer artifact "
                f"beats tool/folder presence; do not over-weight a channel that "
                f"lacks a transfer record."
            )
        _chan_src = {"removable": "removable", "cloud": "cloud", "email": "mail_web",
                     "web": "mail_web", "ftp": "srum_ftp", "chat": "chat_messenger",
                     "c2": "mail_web"}
        from tools._gates._manifests import MANIFESTS as _MFST
        _src_rx = {sid: r for sid, r, _ in _MFST["EXFIL"]["required"]}
        cmds2 = [e.get("cmd", "") for e in entries
                 if e.get("type") == "tool_call" and e.get("cmd")]
        for e in s_findings:
            if _claim(e).get("act") != "egress":
                continue          # duty attaches to the claim class, any tier
            ch = (_claim(e).get("channel") or "").lower()
            src = _chan_src.get(ch)
            rx2 = _src_rx.get(src) if src else None
            if rx2 and not any(rx2.search(c) for c in cmds2) \
                    and find_disposition(idx_all, "source", src, reasons=SOURCE_WAIVER_REASONS_ALL) is None:
                issues.append(
                    f"A finding declares egress channel '{ch}' but the {src} "
                    f"source set was never touched by any tool — a declared "
                    f"channel requires its transfer-artifact sources to be examined "
                    f"(or settled with {disposition_call('source', src, 'absent_from_evidence')}) "
                    f"before Report."
                )

    def _check_3():
        # #3 — a recipient DECLARED in a CONFIRMED/LIKELY finding: every
        # correspondent the parsed comms stores actually contain (server-stamped
        # registry) must be referenced by some finding's typed entities /
        # recipients / principal, or settled by a typed correspondent disposition.
        # K-3b: the completeness duty attaches to the CLAIM CLASS, not the
        # tier — a delivery/dissemination/egress claim at ANY tier engages the
        # correspondent exhaustion (under-claiming must not switch it off).
        recipient_findings = [e for e in s_findings
                              if _claim(e).get("recipients")
                              or _claim(e).get("act") in ("delivery", "possession", "egress")]
        if not recipient_findings:
            return
        corr = getattr(idx_all, "correspondents", {}) or {}
        complete = bool(getattr(idx_all, "correspondents_complete", False))
        if corr and complete:
            referenced: list = []
            for e in s_findings:
                c = _claim(e)
                referenced += list(c.get("entities") or []) + list(c.get("recipients") or [])
                if c.get("principal"):
                    referenced.append(c["principal"])
            leftovers = []          # engaged correspondents: must be settled
            inbound_only = []       # inbound-only senders: report inventory (warned), never blocking
            for full, meta in sorted(corr.items()):
                if any(entity_matches(full, r) for r in referenced):
                    continue
                if find_disposition(idx_all, "correspondent", full,
                                    reasons=("noise", "out_of_scope", "excluded")) is not None:
                    continue
                meta = meta or {}
                if meta.get("bulk"):
                    continue          # bulk-class: inventoried, never mandatory
                # "Engaged" (blocking) requires POSITIVE evidence that the
                # SUBJECT engaged: the mailbox owner wrote to it, a chat
                # exchange, or a roster match. Inbound volume and third-party
                # To: lists (spam, newsletters, mass mail) are inbox clutter:
                # they route to the report inventory (shown, warned, never
                # silently dropped) rather than blocking.
                if not (_corr_engaged(meta) or _roster_match(full)):
                    inbound_only.append(full)
                    continue
                leftovers.append((full, meta.get("first_cid")))
            _legacy = sorted(getattr(idx_all, "correspondent_legacy_stores", set()) or ())
            if _legacy:
                warnings.append(
                    f"{len(_legacy)} mail store(s) were read only by an older read.mail "
                    f"that did not record which addresses the mailbox owner wrote to: "
                    f"{'; '.join(_legacy[:4])}{' …' if len(_legacy) > 4 else ''}. Their "
                    f"correspondents fall back to a conservative two-way rule (sent AND "
                    f"received mail). Re-run read.mail once over each store to stamp "
                    f"owner-direction counts."
                )
            if inbound_only:
                correspondents_auto_noise.extend(inbound_only)
                shown = ", ".join(inbound_only[:8])
                warnings.append(
                    f"{len(inbound_only)} inbound-only correspondent(s) in the parsed mail "
                    f"stores (the subject never wrote to them; no roster or chat match) are "
                    f"listed in the report's correspondent inventory, not blocking: {shown}"
                    f"{' …' if len(inbound_only) > 8 else ''}. Disposition any explicitly only "
                    f"if evidence ties one to the case."
                )
            if leftovers:
                shown = "; ".join(f"{v} (first seen call {c})" for v, c in leftovers[:10])
                issues.append(
                    f"{len(leftovers)} engaged correspondent(s) observed in the parsed comms "
                    f"stores are referenced by NO finding: {shown}"
                    f"{' …' if len(leftovers) > 10 else ''}. A recipient verdict "
                    f"cannot stand while correspondents the subject WROTE TO (or a roster / "
                    f"chat match) are un-dispositioned — reference each in a finding's "
                    f"entities/recipients, or settle it with "
                    f"{disposition_call('correspondent', '<address>', 'noise')} "
                    f"(reason noise|out_of_scope|excluded), before Report. "
                    f"To settle many at once in ONE round-trip instead of a "
                    f"call-per-address grind, pass them together: "
                    f"{disposition_batch_hint('correspondent', 'noise')} — each entry "
                    f"still runs the same per-target gates (an engaged/roster address "
                    f"cannot be labelled noise; use out_of_scope/excluded there)."
                )
            return
        # No complete registry: warn unless a roster / mail read ran (by COMMAND).
        xref_seen = any(
            e.get("type") == "tool_call" and isinstance(e.get("cmd"), str)
            and re.search(r"knowns_pattern_generate|read[._]mail|readpst|pff_export|chat_db_export",
                          e["cmd"], re.IGNORECASE)
            for e in entries
        )
        if not xref_seen:
            warnings.append(
                f"{len(recipient_findings)} finding(s) declare a recipient but no roster "
                f"sweep or comms-store read is evident in the trace (misc.knowns_pattern_generate, "
                f"read.mail, readpst/pff_export, chat_db_export). Inventory all "
                f"correspondents and cross-reference the recipient against the case roster "
                f"before Report."
            )

    def _check_4():
        # #4 — per-hypothesis exhaustion. Every principal a hypothesis CONTESTS
        # (RESULT.hypotheses[].principals, the legacy header parse, or the typed
        # contested_principals argument) at MEDIUM+ likelihood must be driven to a
        # verdict: its controller established (a session-bound CONFIRMED/LIKELY
        # finding), the alternative refuted (a finding with tested_hypothesis_id
        # and resolves='refuted', or a typed principal/hypothesis disposition).
        # Parking (controller_unknown) does NOT count here.
        _rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
        hyps = [e for e in entries if e.get("type") == "reason_call" and e.get("tool") == "reason_hypothesize"]
        ent_tier: dict = {}
        ent_labels: dict = {}
        ent_hids: dict = {}
        # Built-in accounts (Guest, Administrator, SYSTEM …) listed as contested
        # are tracked only when some finding actually names them; otherwise a
        # reviewer's boilerplate "Guest" forces a pointless disposition.
        _named_norms = {p for fe in s_findings for p in _principal_norms(fe)}

        def _skip_contested(ent, n) -> bool:
            # Hosts/IPs and mail addresses are not principals (they are hosts
            # and correspondents, tracked by their own checks); placeholders
            # and unnamed built-ins never need a controller verdict.
            s = str(ent or "").strip()
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", s) or "@" in s:
                return True
            return (not n or _is_placeholder(ent)
                    or (_is_builtin(ent) and n not in _named_norms))

        # Who asked: a principal the AGENT typed (contested_principals) is
        # mandatory; one only the REVIEWER listed (RESULT.hypotheses[].
        # principals) is mandatory only when forced or on the roster —
        # otherwise it is a warning and report inventory.
        ent_mandatory: dict = {}
        for h in hyps:
            hid = str(h.get("hypothesis_id") or "")
            for sub in (h.get("sub_hypotheses") or []):
                t = sub.get("likelihood_tier", "MEDIUM")
                for ent in sub.get("entities") or []:
                    n = norm_entity(ent)
                    if _skip_contested(ent, n):
                        continue
                    if _rank.get(t, 1) >= _rank.get(ent_tier.get(n, "LOW"), 0):
                        ent_tier[n] = t
                    ent_labels.setdefault(n, set()).add(sub.get("label") or "?")
                    ent_hids.setdefault(n, set()).update({hid, str(sub.get("sub_id") or "")})
                    if n in _forced or _roster_match(str(ent)):
                        ent_mandatory[n] = True
                    else:
                        ent_mandatory.setdefault(n, False)
            for ent in (h.get("contested_principals") or []):
                n = norm_entity(ent)
                if _skip_contested(ent, n):
                    continue
                if _rank.get(ent_tier.get(n, "LOW"), 0) < 1:
                    ent_tier[n] = "MEDIUM"
                ent_labels.setdefault(n, set()).add(hid or "?")
                ent_hids.setdefault(n, set()).add(hid)
                ent_mandatory[n] = True

        def _refuted(n: str) -> bool:
            for fe in s_findings:
                c = _claim(fe)
                if c.get("resolves") == "refuted" and (
                        str(fe.get("tested_hypothesis_id") or "") in ent_hids.get(n, set())
                        or n in _principal_norms(fe)):
                    return True
            if _settled(n, ("refuted", "excluded", "not_a_principal", "same_as")):
                return True
            for hid in ent_hids.get(n, set()):
                if hid and find_disposition(idx_all, "hypothesis", hid,
                                            reasons=("refuted", "excluded", "evidence_unavailable")):
                    return True
            return False

        _logon_source_re = re.compile(r"security|logon|terminalservices|wtmp|auth|4624")

        def _parked_with_logon_waiver(n: str) -> bool:
            """evidence_unavailable is honest — not a dodge — when a typed SOURCE
            disposition says the logon/session sources are absent from the
            evidence (XP with auditing off, a triage set without Security.evtx).
            Then the principal stays parked with a report caveat (warning)
            instead of forcing a backwards 'refuted' on the prime subject."""
            if find_disposition(idx_all, "principal", n, reasons=("evidence_unavailable",)) is None:
                return False
            for (kind, norm), rows in (getattr(idx_all, "dispositions", None) or {}).items():
                if kind != "source" or not _logon_source_re.search(str(norm or "")):
                    continue
                if any(str(d.get("reason") or "").lower() in ("absent_from_evidence", "inapplicable")
                       for d in rows):
                    return True
            return False

        for n in sorted(ent_tier):
            if _established(n) or _refuted(n):
                continue
            labels = ", ".join(sorted(ent_labels.get(n, set())))
            tier = ent_tier[n]
            if _parked_with_logon_waiver(n):
                warnings.append(
                    f"Contested principal '{n}' (hypothesis {labels}) is parked as "
                    f"evidence_unavailable with the logon/session sources dispositioned "
                    f"absent from evidence — the report MUST carry this caveat: the "
                    f"controller binding rests on documentary artifacts, not on a logon "
                    f"session, and a second operator of the account cannot be excluded "
                    f"from session evidence."
                )
                continue
            msg = (
                f"Contested principal '{n}' (raised as hypothesis {labels}, likelihood "
                f"{tier}) was never driven to a verdict: no CONFIRMED/LIKELY finding "
                f"establishes its controller with a session binding (principal='{n}' + "
                f"session_binding_call_ids), and nothing refutes the alternative (a finding "
                f"with resolves='refuted', or {disposition_call('principal', n, 'refuted', evidence=True)}). "
                f"'Controller unknown'/parked does not count — a sole-actor verdict cannot "
                f"stand while '{n}' is unresolved. Resolve it (run the discriminators) before Report."
            )
            if _rank.get(tier, 1) >= 1 and ent_mandatory.get(n, True):
                issues.append(msg)
                registry_inventory["principals"].append(
                    {"value": n, "how": f"contested (hypothesis {labels})", "status": "open"})
            else:
                if not ent_mandatory.get(n, True):
                    msg = (f"Reviewer-listed principal '{n}' (hypothesis {labels}) was not driven "
                           f"to a verdict; it is not a forced candidate and matches no roster "
                           f"term, so it is carried as report inventory, not a blocker.")
                    registry_inventory["principals"].append(
                        {"value": n, "how": f"reviewer-listed (hypothesis {labels})",
                         "status": "inventory"})
                warnings.append(msg)

        # Hypotheses with no contested principals: a distinct_principal kind that
        # no finding resolves (tested_hypothesis_id) and no disposition settles
        # BLOCKS; other unresolved kinds warn.
        resolved_ids: set = set()
        for e in s_findings:
            tid = (e.get("tested_hypothesis_id") or "").strip()
            if tid:
                resolved_ids.add(tid)
            gh = e.get("gated_by_hypothesize_call_id")
            if gh:
                ghid = ((idx_all.by_call_id.get(gh) or {}).get("hypothesis_id") or "").strip()
                if ghid:
                    resolved_ids.add(ghid)
        open_generic: list = []
        for hid, hyp in sorted(idx_all.hypotheses_by_id.items()):
            if not hid or hid in resolved_ids:
                continue
            if find_disposition(idx_all, "hypothesis", hid,
                                reasons=("refuted", "excluded", "evidence_unavailable")):
                continue
            if hyp.get("contested_principals") or hyp.get("sub_hypotheses"):
                continue        # tracked per principal above
            if str(hyp.get("hypothesis_kind") or "") == "distinct_principal":
                issues.append(
                    f"Hypothesis {hid} was declared hypothesis_kind='distinct_principal' "
                    f"but was never resolved: no finding carries it as tested_hypothesis_id "
                    f"and no typed hypothesis disposition settles it. A competing-principal "
                    f"hypothesis cannot be silently dropped — record the finding that resolves "
                    f"it (with a session binding, or resolves='refuted'), or "
                    f"{disposition_call('hypothesis', hid, 'evidence_unavailable')}, before Report."
                )
            else:
                open_generic.append(hid)
        if open_generic:
            warnings.append(
                f"{len(open_generic)} hypothesis/es raised but never resolved "
                f"({', '.join(open_generic[:5])}{'…' if len(open_generic) > 5 else ''}) — no "
                f"finding cites them as tested_hypothesis_id. Resolve or disposition each "
                f"before Report."
            )

    def _check_5():
        # #5 (blocking) — attribution closure (i): a human/account attribution
        # verdict (DECLARED actor_kind human|account on a core act) cannot ship
        # without a logon/RDP session inventory that could rule out a second
        # principal operating the host.
        _VERDICT_ACTS = CORE_ACTS | {"attribution", "logon"}
        has_verdict = any(
            _ftier(e) in {"CONFIRMED", "LIKELY"}
            and _claim(e).get("actor_kind") in ("human", "account")
            and _claim(e).get("act") in _VERDICT_ACTS
            for e in s_findings
        )
        has_pcap_activity = any(
            e.get("type") == "tool_call" and isinstance(e.get("cmd"), str)
            and re.search(r"\b(?:tcpdump|ngrep)\b|http_session_inventory|pcap_identity_timeline",
                          e["cmd"], re.IGNORECASE)
            for e in entries
        )
        has_pcap_identity_closure = any(
            e.get("type") == "tool_call" and isinstance(e.get("cmd"), str)
            and re.search(r"http_session_inventory|pcap_identity_timeline", e["cmd"], re.IGNORECASE)
            for e in entries
        ) or any(
            e.get("type") == "finding"
            and re.search(r"net\.http_session_inventory|net\.pcap_identity_timeline",
                          e.get("source") or "", re.IGNORECASE)
            for e in entries
        )
        has_knowns_sweep = any(
            e.get("type") == "tool_call" and isinstance(e.get("cmd"), str)
            and re.search(r"knowns_pattern_generate|roster", e["cmd"], re.IGNORECASE)
            for e in entries
        )
        has_logon_enum = has_logon_enumeration(entries)
        if has_verdict and has_pcap_activity and not has_pcap_identity_closure:
            issues.append(
                "A human/account attribution verdict was recorded from PCAP "
                "evidence, but no structured PCAP identity inventory appears "
                "in the trace (net.http_session_inventory or "
                "net.pcap_identity_timeline). Run one of those tools, compare "
                "all identities on the sender host/session, and disposition "
                "competing accounts before Report."
            )
        if has_verdict and has_pcap_activity and not has_knowns_sweep:
            issues.append(
                "A human/account attribution verdict was recorded from PCAP "
                "evidence, but no roster/knowns sweep is evident. Generate "
                "person-username variants with misc.knowns_pattern_generate and "
                "sweep the PCAP or pass the roster to net.pcap_identity_timeline "
                "before Report."
            )
        if has_verdict and not has_pcap_activity and not has_logon_enum:
            issues.append(
                "A human/account attribution verdict was recorded but no "
                "logon/RDP session-enumeration appears anywhere in the trace "
                "(no ez.evtxecmd / misc.chainsaw_hunt / misc.evtx_filter on "
                "4624/4625/4778/4779, and no Linux last/wtmp). A sole-actor "
                "verdict cannot stand without a logon-session inventory that "
                "rules out a second principal operating the host — run it and "
                "disposition every session before Report."
            )

    def _check_6():
        # #6 (blocking) — attribution closure (ii): every principal DAIR surfaced
        # as a forced candidate (candidate_pivots, typed) or that the agent
        # declared as created / interactively logged on (dair_assess
        # observed_principals) must be dispositioned: attributed-with-session,
        # or settled by a typed principal disposition.
        surfaced: dict = {}
        for e in entries:
            if e.get("type") != "dair_call":
                continue
            for pivot in e.get("candidate_pivots") or []:
                if (isinstance(pivot, dict) and str(pivot.get("kind") or "").lower() == "principal"
                        and str(pivot.get("cue") or "").lower() == "forced"):
                    v = str(pivot.get("value") or "")
                    if norm_entity(v):
                        surfaced.setdefault(norm_entity(v), (v, "forced principal candidate"))
            for op in e.get("observed_principals") or []:
                if isinstance(op, dict) and str(op.get("cue") or "").lower() in ("created", "interactive_logon"):
                    v = str(op.get("name") or "")
                    n = norm_entity(v)
                    if not n:
                        continue
                    # A mail address is a correspondent, not a logon principal;
                    # a built-in (Guest, Administrator) needs a controller only
                    # when a finding actually names it.
                    if "@" in v:
                        continue
                    if _is_builtin(v) and n not in {p for fe in s_findings for p in _principal_norms(fe)}:
                        continue
                    surfaced.setdefault(n, (v, f"declared {op.get('cue')} principal"))
        for p_norm, (shown, how) in sorted(surfaced.items()):
            if p_norm.startswith("rid") or p_norm.startswith("s-1-"):
                continue
            if _established(p_norm):
                registry_inventory["principals"].append({"value": shown, "how": how, "status": "bound"})
                continue
            if _settled(p_norm, _PRINCIPAL_SETTLED):
                registry_inventory["principals"].append({"value": shown, "how": how, "status": "dispositioned"})
                continue
            registry_inventory["principals"].append({"value": shown, "how": how, "status": "open"})
            issues.append(
                f"Previously-unseen identity '{shown}' surfaced during the investigation "
                f"({how}) but nothing dispositions it: no CONFIRMED/LIKELY finding binds it "
                f"to an actor with a session artifact, and no typed disposition settles it. "
                f"Disposition '{shown}' before Report — "
                f"{disposition_call('principal', shown, 'not_a_principal', evidence=True)} "
                f"(reason excluded|not_a_principal|controller_unknown|evidence_unavailable)."
            )

    for _n, _fn in ((1, _check_1), (2, _check_2), (3, _check_3),
                    (4, _check_4), (5, _check_5), (6, _check_6)):
        _guarded_check(_n, _fn)

    # Registry inventory: every correspondent / identity the
    # server-stamped registries hold, with its status — rendered into the
    # report by write_final_report. Nothing here blocks.
    try:
        _referenced: list = []
        for _fe in s_findings:
            _c = _claim(_fe)
            _referenced += list(_c.get("entities") or []) + list(_c.get("recipients") or [])
            if _c.get("principal"):
                _referenced.append(_c["principal"])
        for _addr, _meta in sorted((getattr(idx_all, "correspondents", {}) or {}).items()):
            _meta = _meta or {}
            if any(entity_matches(_addr, r) for r in _referenced):
                _st = "referenced"
            elif find_disposition(idx_all, "correspondent", _addr,
                                  reasons=("noise", "out_of_scope", "excluded")) is not None:
                _st = "dispositioned"
            elif _meta.get("bulk"):
                _st = "noise-class (address pattern)"
            elif _roster_match(_addr):
                _st = "roster-match (open)"
            elif _meta.get("store_owner"):
                _st = "store owner"
            elif _corr_engaged(_meta):
                _st = "engaged (open)"          # owner wrote to it / chat, not inbound volume
            else:
                _st = "inventory"
            registry_inventory["correspondents"].append(
                {"address": _addr, "from": _meta.get("from", ""), "to": _meta.get("to", ""),
                 "owner_to": _meta.get("owner_to", ""),
                 "sources": list(_meta.get("sources") or []), "status": _st})
        for _idv, _meta in sorted((getattr(idx_all, "identities", {}) or {}).items()):
            if any(entity_matches(_idv, r) for r in _referenced):
                _st = "referenced"
            elif (_meta or {}).get("bulk"):
                _st = "noise-class (address pattern)"
            elif _roster_match(_idv):
                _st = "roster-match"
            else:
                _st = "inventory"
            registry_inventory["identities"].append(
                {"value": _idv, "first_cid": (_meta or {}).get("first_cid", ""), "status": _st})
        _all_corr = list(registry_inventory["correspondents"])
        registry_inventory["correspondents"] = registry_inventory["correspondents"][:400]
        registry_inventory["identities"] = registry_inventory["identities"][:400]
        # K-3c: near-alias addresses are SURFACED as a typed lead — same
        # domain, same-length local parts differing in exactly one character.
        # Never auto-merged: whether they are one correspondent or two distinct
        # people is a finding to establish with evidence, in either direction.
        _addrs = sorted({r["address"] for r in _all_corr
                         if "@" in str(r.get("address") or "")})
        _leads = []
        for _i in range(len(_addrs)):
            for _j in range(_i + 1, len(_addrs)):
                a, b = _addrs[_i], _addrs[_j]
                la, da = a.rsplit("@", 1)
                lb, db = b.rsplit("@", 1)
                if da != db or len(la) != len(lb) or la == lb:
                    continue
                if sum(1 for x, y in zip(la, lb) if x != y) == 1:
                    _leads.append({"a": a, "b": b})
        if _leads:
            registry_inventory["alias_leads"] = _leads[:20]
            shown = "; ".join(f"{p['a']} ~ {p['b']}" for p in _leads[:5])
            warnings.append(
                f"{len(_leads)} near-alias correspondent pair(s) in the parsed stores "
                f"(same domain, one-character difference): {shown}"
                f"{' …' if len(_leads) > 5 else ''}. Resolve with evidence whether each "
                f"pair is one correspondent or two distinct people — do not assume "
                f"either; the registry keeps them separate until a finding settles it."
            )
    except Exception as _e:
        import sys as _sys
        print(f"[TRUDI WARN] registry inventory failed: {_e}", file=_sys.stderr)

    # Comms-store completeness fires on PRESENCE. When a delivery /
    # dissemination / egress question is in the case, every chat/mail store
    # FAMILY that the collected evidence itself shows (a family token in a
    # successful tool call's cmd or stored output — evidence-derived, never
    # prose) must be parsed or typed-dispositioned. Symmetric: parsing the
    # store may equally exonerate.
    try:
        _comms_claim = any(
            (e.get("claim") or {}).get("recipients")
            or (e.get("claim") or {}).get("act") in ("delivery", "possession", "egress")
            for e in entries if e.get("type") == "finding")
        if _comms_claim:
            from tools._gates._manifests import CHAT_FAMILIES as _FAMILIES
            _PARSE_RE = re.compile(r"chat_db_export|sqlecmd|read\.(?:read_)?mail|readpst|pff_export", re.I)
            from tools._gates._dispositions import find_disposition as _fd7
            _ev_calls7 = [e for e in entries if e.get("type") == "tool_call" and e.get("success")]
            for fam, frx in _FAMILIES.items():
                present_cids = [int(e.get("call_id") or 0) for e in _ev_calls7
                                if frx.search(str(e.get("cmd") or "") + " "
                                              + str(e.get("stdout_excerpt") or ""))]
                if not present_cids:
                    continue
                parsed = any(_PARSE_RE.search(str(e.get("cmd") or "")) and frx.search(str(e.get("cmd") or ""))
                             for e in _ev_calls7)
                # present_unparseable is the honest closure for a store that
                # is on the image but that no available tool reads.
                from tools._gates._dispositions import SOURCE_WAIVER_REASONS_ALL as _W7
                waived7 = any(_fd7(idx_all, "source", t, reasons=_W7)
                              for t in (fam, f"chat_{fam}", "chat_messenger"))
                if not parsed and not waived7:
                    issues.append(
                        f"Comms store family '{fam}' appears in the collected evidence "
                        f"(e.g. call {present_cids[0]}) but was never parsed and no typed "
                        f"source disposition covers it. With a delivery/dissemination/"
                        f"egress question in the case, every comms store present in "
                        f"evidence must be examined (it may equally exonerate) — parse it "
                        f"(misc.chat_db_export / read.mail), or record "
                        f"misc.record_disposition(target_kind=\"source\", "
                        f"target_id=\"{fam}\", reason=\"absent_from_evidence\"|"
                        f"\"inapplicable\") before Report."
                    )
    except Exception as _e:
        import sys as _sys
        print(f"[TRUDI WARN] comms-presence check failed: {_e}", file=_sys.stderr)

    # A11: with an interactive (or undeclared-session) account-creation /
    # persistence claim at ANY tier and removable media in evidence, the
    # complete device-install inventory must have run or the source be
    # typed-dispositioned — symmetric: the inventory may equally exonerate.
    try:
        from tools._gates.interactive_injection_grounding import _REMOVABLE_IN_EVIDENCE_RE
        _ii = [e for e in s_findings
               if _claim(e).get("act") in ("account_creation", "persistence_install")
               and str(_claim(e).get("session_type") or "") in ("", "interactive")]
        if _ii:
            _cmds11 = [str(e.get("cmd") or "") for e in entries
                       if e.get("type") == "tool_call" and e.get("success")]
            _removable11 = any(_REMOVABLE_IN_EVIDENCE_RE.search(c) for c in _cmds11)
            _inv_ran11 = any("device_install_inventory" in c for c in _cmds11)
            _waived11 = find_disposition(idx_all, "source", "device_inventory",
                                         reasons=SOURCE_WAIVER_REASONS_ALL) is not None
            if _removable11 and not _inv_ran11 and not _waived11:
                issues.append(
                    "An account-creation/persistence claim exists (any tier) with "
                    "removable media in evidence, but misc.device_install_inventory "
                    "never ran. The complete device table can implicate a keystroke "
                    "injector or exonerate one — run it over setupapi.dev.log, or "
                    "record misc.record_disposition(target_kind=\"source\", "
                    "target_id=\"device_inventory\", reason=\"absent_from_evidence\") "
                    "before Report."
                )
    except Exception as _e:
        import sys as _sys
        print(f"[TRUDI WARN] device-inventory duty check failed: {_e}", file=_sys.stderr)

    # Persistence/creation enumeration duty. A finding with
    # act in {account_creation, persistence_install} or
    # category=device_initial_access — at ANY tier — must show a scheduled-task
    # enumeration (\Windows\System32\Tasks + TaskCache) or a typed source
    # disposition. With task-auditing off there is no 4698 event, so an
    # event-log-only look silently misses an injected task. Symmetric:
    # enumerating may equally exonerate.
    try:
        from tools._gates._scheduled_tasks import tasks_examined
        _needs_tasks = any(
            (e.get("claim") or {}).get("act") in ("account_creation", "persistence_install")
            or (e.get("claim") or {}).get("category") == "device_initial_access"
            for e in entries if e.get("type") == "finding")
        if _needs_tasks and not tasks_examined(entries, idx_all):
            issues.append(
                "A account-creation / persistence / device-initial-access finding exists "
                "but no scheduled-task enumeration appears in the trace. A keystroke "
                "injector (or any persistence) commonly plants a scheduled task, and with "
                "task-auditing off there is NO event — it lives only on disk. Enumerate "
                "\\Windows\\System32\\Tasks and the SOFTWARE TaskCache "
                "(misc.parse_scheduled_tasks / vol.scheduled_tasks), or record "
                "misc.record_disposition(target_kind=\"source\", "
                "target_id=\"scheduled_tasks\", reason=\"absent_from_evidence\"|"
                "\"inapplicable\") before Report."
            )
    except Exception as _e:
        import sys as _sys
        print(f"[TRUDI WARN] scheduled-task duty check failed: {_e}", file=_sys.stderr)

    # A FLAGGED injector-payload task is direct evidence injection ran —
    # enumerating it is not investigating it. The task must be referenced by a
    # finding (or the source dispositioned), and a human/account attribution of
    # the account's creation or ownership cannot stand while that proof of
    # injection is unreckoned — it needs an injector rule-out. Symmetric: reading
    # the task may equally show it benign; the finding then says so.
    try:
        from tools._gates._scheduled_tasks import flagged_payload_tasks
        _payload_tasks = flagged_payload_tasks(entries)
        if _payload_tasks:
            _finds = [e for e in entries if e.get("type") == "finding"]

            def _task_ref(task):
                tnorm = task.strip("/\\").lower()
                if not tnorm:
                    return True
                for e in _finds:
                    c = e.get("claim") or {}
                    blob = (str(e.get("description", "")) + " "
                            + " ".join(map(str, c.get("entities") or [])) + " "
                            + " ".join(map(str, c.get("artifacts") or []))).lower()
                    if tnorm in blob:
                        return True
                return False

            _unref = sorted({t for t in _payload_tasks if not _task_ref(t)})
            if _unref and find_disposition(idx_all, "source", "scheduled_tasks",
                                           reasons=("inapplicable", "absent_from_evidence",
                                                    "out_of_scope")) is None:
                issues.append(
                    f"A scheduled-task enumeration FLAGGED injector-payload task(s) "
                    f"({', '.join(_unref)}) but no finding examines them. A keystroke-"
                    f"injector payload task is direct evidence of the injection mechanism "
                    f"— read the task and record a finding on what it does (or, if it "
                    f"proves benign, a finding saying so); enumerating is not investigating."
                )
            # With injection proven by a flagged payload task, a human/account
            # attribution of the covert account's creation/ownership needs a rule-out.
            def _has_ruleout():
                for e in _finds:
                    for ro in (e.get("claim") or {}).get("rule_outs") or []:
                        if str(ro.get("what") or "").lower() == "injector" and ro.get("call_ids"):
                            return True
                from tools._gates._dispositions import any_disposition
                return any_disposition(idx_all, "device", reasons=["ruled_out"]) is not None

            _human_attrib = [
                e for e in _finds
                if str(e.get("confidence") or "").upper() in ("CONFIRMED", "LIKELY")
                and (e.get("claim") or {}).get("act") in ("account_creation",
                                                          "persistence_install", "attribution")
                and (e.get("claim") or {}).get("actor_kind") in ("human", "account")]
            if _human_attrib and not _has_ruleout():
                issues.append(
                    f"A flagged injector-payload task ({', '.join(_unref or _payload_tasks)}) "
                    f"proves keystroke injection ran, yet a CONFIRMED/LIKELY finding "
                    f"attributes the account's creation/ownership to a human/account with "
                    f"no injector rule-out. A device that injects the account creation is "
                    f"the author at the keystroke level — rule the injector out with "
                    f"evidence (rule_outs / a device ruled_out disposition) or downgrade "
                    f"and frame the injection alternative before Report."
                )
    except Exception as _e:
        import sys as _sys
        print(f"[TRUDI WARN] injector-payload reconciliation check failed: {_e}", file=_sys.stderr)

    # Tier–evidence concordance (symmetric, audit-only). Over-asking is
    # refused at record time by the tier contract; a finding recorded BELOW
    # what its cited classes reach is surfaced as an audit note — the tier
    # must match the evidence in both directions. No nudging: the note states
    # the arithmetic, nothing else.
    try:
        _RANK9 = {"CONFIRMED": 3, "LIKELY": 2, "SUSPECTED": 1, "UNCONFIRMED": 0}
        _disc = []
        for e in s_findings:
            ach = str(e.get("tier_achievable") or "").upper()
            rec = str(e.get("confidence") or "").upper()
            if ach and rec and _RANK9.get(rec, 0) < _RANK9.get(ach, 0):
                _disc.append(f"finding #{e.get('call_id')} recorded {rec}, cited classes reach "
                             f"{ach} (rule {e.get('tier_rule') or '?'})")
        if _disc:
            warnings.append(
                "Tier–evidence concordance: " + "; ".join(_disc[:6])
                + (" …" if len(_disc) > 6 else "")
                + ". The deterministic tier contract computed a higher reachable tier "
                  "than was recorded — the tier must match the evidence in both "
                  "directions; re-examine and re-record (supersedes=<cid>) or leave a "
                  "documented reason. This is an audit note, not an instruction to "
                  "strengthen a conclusion."
            )
    except Exception as _e:
        import sys as _sys
        print(f"[TRUDI WARN] tier-concordance check failed: {_e}", file=_sys.stderr)

    # K-5b: a principal settled by same_as / excluded / refuted / not_a_principal
    # while the trace holds SESSION artifacts naming that principal that the
    # disposition does not cite — the settlement may not cover who OPERATED the
    # account (creation-subject ≠ controller). Symmetric flag, never a block:
    # the uncited sessions may equally confirm the settlement once examined.
    try:
        from tools._gates._entities import norm_entity as _ne5
        _sess_calls = [e for e in entries if e.get("type") == "tool_call"
                       and e.get("success") and e.get("session_artifact")]
        for (kind, pnorm), rows in (getattr(idx_all, "dispositions", None) or {}).items():
            if kind != "principal" or not pnorm:
                continue
            for d in rows:
                if str(d.get("reason") or "").lower() not in ("same_as", "excluded",
                                                              "refuted", "not_a_principal"):
                    continue
                cited = {int(c) for c in (d.get("evidence_call_ids") or []) if c}
                uncited = []
                for e in _sess_calls:
                    if int(e.get("call_id") or 0) in cited:
                        continue
                    hay = (str(e.get("stdout_excerpt") or "") + " " + str(e.get("cmd") or "")).lower()
                    if pnorm and pnorm in _ne5(hay) or pnorm in hay.replace(" ", ""):
                        uncited.append(int(e.get("call_id") or 0))
                if uncited:
                    warnings.append(
                        f"Principal '{pnorm}' was settled by a "
                        f"{str(d.get('reason'))} disposition citing calls "
                        f"{sorted(cited) or '[]'}, but session artifacts naming it exist "
                        f"un-cited (calls {sorted(uncited)[:4]}). Creation or documentary "
                        f"evidence does not by itself cover who OPERATED the account — "
                        f"verify the settlement against those sessions (they may confirm "
                        f"or refute it) and cite them either way."
                    )
                break
    except Exception as _e:
        import sys as _sys
        print(f"[TRUDI WARN] principal-settlement session check failed: {_e}", file=_sys.stderr)

    # A recipient/correspondent claim at any tier should rest on message
    # BODIES, not a roster listing. The read_mail cmd now records mode/field/
    # query, so this is checkable from tool COMMANDS (never prose).
    try:
        _has_recipient_claim = any(
            (e.get("claim") or {}).get("recipients")
            or (e.get("claim") or {}).get("act") in ("delivery", "possession")
            for e in entries if e.get("type") == "finding")
        if _has_recipient_claim:
            _body_read = any(
                e.get("type") == "tool_call" and isinstance(e.get("cmd"), str)
                and e["cmd"].startswith(("read.mail", "read.read_mail"))
                and "mode=messages" in e["cmd"] and " q=" in e["cmd"]
                for e in entries)
            if not _body_read:
                warnings.append(
                    "A recipient/delivery claim is recorded but no queried BODY read of a "
                    "mail store appears in the trace (read.mail mode=messages with a "
                    "query). Subject and sender-listing reads cannot establish or exclude "
                    "a recipient — read the thread bodies and cite that call."
                )
    except Exception as _e:
        import sys as _sys
        print(f"[TRUDI WARN] body-read check failed: {_e}", file=_sys.stderr)

    # Phase coverage (blocking): a report written without the collection/
    # analysis phases skipped the systematic enumeration they force. Trace-
    # derived (dair entries); live-monitoring investigation traces exempt.
    try:
        from tools.dair import missing_report_phases
        _mp = missing_report_phases(entries)
        if _mp:
            issues.append(
                f"Phase coverage: the investigation never entered {', '.join(_mp)} "
                f"(every dair_assess stayed in "
                f"{', '.join(sorted({str(e.get('current_phase') or '') for e in entries if e.get('type') == 'dair_call'} - {''})) or 'Triage'}). "
                f"A defensible report requires the full DAIR cycle — transition to "
                f"{_mp[0]} (dair_assess stack_action=push), run its systematic "
                f"collection, then re-synthesize before Report."
            )
    except Exception as _e:
        import sys as _sys
        print(f"[TRUDI WARN] phase-coverage check failed: {_e}", file=_sys.stderr)

    # DAIR verification challenges left verified:null and never run — the
    # max-pass cap may not override them; this is the report-time backstop.
    try:
        from tools._gates.max_pass_cap import open_challenge_issues
        issues.extend(open_challenge_issues(entries))
    except Exception as _e:
        import sys as _sys
        print(f"[TRUDI WARN] open-challenge check failed: {_e}", file=_sys.stderr)

    # FK-driven corroboration completeness (block-late). A CONFIRMED/LIKELY
    # finding grounded on a single artifact whose FK-named corroborators never
    # ran is weak — block until corroborated or downgraded. Same FK data the
    # response enricher shows and record_finding warns on: one corpus, one
    # contract. Deterministic; fail-open.
    try:
        from tools._gates.fk_corroboration import report_gaps
        for _desc, _gap in report_gaps(entries):
            issues.append(
                f"Uncorroborated {_gap['category'].replace('for_', '')} finding "
                f"(\"{_desc[:60]}…\"): {_gap['message']} Run one of "
                f"{', '.join(_gap['expected'])}, or downgrade to SUSPECTED."
            )
    except Exception as _e:
        import sys as _sys
        print(f"[TRUDI WARN] FK-corroboration check failed: {_e}", file=_sys.stderr)

    # Affirmative coverage completeness (block-late, STRICT). Mirror of
    # negative_completeness for positive verdicts: an exfil/dissemination verdict
    # must rest on a complete egress-channel enumeration, and a named recipient on
    # a full correspondent inventory. Reuses the _manifests source sets.
    try:
        from tools._gates.affirmative_coverage import coverage_gaps
        issues.extend(coverage_gaps(entries))
    except Exception as _e:
        import sys as _sys
        print(f"[TRUDI WARN] affirmative-coverage check failed: {_e}", file=_sys.stderr)

    # Work-order completion (block-late). A forensic tool that was blocked by the
    # DAIR-batch gate and then neither re-run nor dispositioned is a dropped
    # work-order item — surface it so it is closed before Report.
    try:
        from tools._gates.work_order import unretried_blocks, unrun_priority_tools
        issues.extend(unretried_blocks(entries))
        # Prescribed priority_tools must have run or been dispositioned —
        # entering a phase does not satisfy its work order.
        issues.extend(unrun_priority_tools(entries))
    except Exception as _e:
        import sys as _sys
        print(f"[TRUDI WARN] work-order check failed: {_e}", file=_sys.stderr)

    # Attack-lifecycle coverage (advisory). The five phases of the
    # cyber attack lifecycle — persistence, privilege escalation, lateral
    # movement, evidence of execution, exfiltration — are the DFIR goals an
    # investigation should establish or rule out. Surface any phase whose
    # artifact sources were never examined (a coverage gap), and stamp the full
    # per-phase coverage for the report. Warning, never a blocker: a case
    # genuinely without a phase must be free to rule it out, not invent it.
    lifecycle_coverage: dict = {}
    try:
        from tools._gates._lifecycle import coverage as _lc_coverage, uncovered_phases
        lifecycle_coverage = _lc_coverage(entries)
        _gaps = uncovered_phases(entries)
        if _gaps:
            _shown = "; ".join(f"{lbl} ({hints})" for _pid, lbl, hints in _gaps)
            warnings.append(
                f"Attack-lifecycle coverage gap — {len(_gaps)} phase(s) whose artifact "
                f"sources were never examined: {_shown}. Examine each (or record a grounded "
                f"negative / typed out-of-scope disposition) so the report states coverage "
                f"per phase — a phase left unexamined is a blind spot, not a clean bill."
            )
    except Exception as _e:
        import sys as _sys
        print(f"[TRUDI WARN] lifecycle coverage check failed: {_e}", file=_sys.stderr)

    # Open scoping leads — a candidate pivot (host / forced principal) or a
    # flagged IOC (keystroke-injector device, injector-payload scheduled task)
    # that is neither cited by a finding nor settled by a typed disposition. A
    # new IOC is followed to depth (same host or another), not ticked and
    # passed. WARN only — the lead may equally exonerate; it must be LOOKED AT.
    try:
        from tools._gates._scoping import open_scoping_leads as _osl
        _leads = _osl(entries)
        if _leads:
            _shown = "; ".join(f"{l['kind']}:{l['value']} — {l['why']}" for l in _leads[:6])
            warnings.append(
                f"{len(_leads)} open scoping lead(s) — a pivot or flagged IOC not yet driven "
                f"to a finding or settled by a typed disposition: {_shown}"
                f"{' …' if len(_leads) > 6 else ''}. Scan is scoping: pursue each to depth "
                f"(deeper on this host or another host), then cite it in a finding or record "
                f"a typed disposition (principal / host / device / source). Symmetric — "
                f"scoping may equally exonerate; a lead left un-followed is a blind spot."
            )
    except Exception as _e:
        import sys as _sys
        print(f"[TRUDI WARN] scoping-leads check failed: {_e}", file=_sys.stderr)

    # Details the reviewer could not SEE (display limit) must be verified with a
    # targeted read, not dropped. List what was never followed by a SUPPORTED
    # recording of the same submission family, so nothing disappears silently.
    unshown_details: list = []
    try:
        import re as _re2
        def _base(k):
            return _re2.sub(r"-v\d+$", "", str(k or ""))
        recorded = {_base(e.get("idempotency_key")) for e in entries
                    if e.get("type") == "finding_submission" and e.get("status") == "recorded"}
        for e in entries:
            if e.get("type") == "finding_submission" and e.get("reason") == "rows_not_shown":
                for item in e.get("unverified_items") or []:
                    unshown_details.append({"submission": e.get("idempotency_key"),
                                            "call_id": e.get("call_id"), "item": item,
                                            "later_recorded": _base(e.get("idempotency_key")) in recorded})
        if unshown_details:
            warnings.append(
                f"{len(unshown_details)} detail(s) the reviewer could not see were raised during "
                f"finding review. Each should have been verified with a targeted read and cited; "
                f"any that was instead removed from its finding is listed in the report as not "
                f"re-checked.")
    except Exception as _e:
        import sys as _sys
        print(f"[TRUDI WARN] unshown-detail audit failed: {_e}", file=_sys.stderr)

    # A background job still running or queued is unexamined scope.
    try:
        from core.jobs import active_task_jobs
        _aj = active_task_jobs()
        if _aj:
            issues.append(
                f"{len(_aj)} background job(s) not finished: "
                + "; ".join(f"{j['job_id']} ({j['tool']}, {j['status']}, {j['elapsed_seconds']}s)"
                            for j in _aj[:6])
                + ". Collect each with misc.job_status before reporting.")
    except Exception as _e:
        import sys as _sys
        print(f"[TRUDI WARN] job check failed: {_e}", file=_sys.stderr)

    # IOC coverage — warnings only. An ATT&CK detection source left unexamined
    # for a recorded IOC is a stated blind spot in the report, never a blocker.
    ioc_inventory: dict = {"iocs": [], "coverage_counts": {}, "open": []}
    try:
        from core.iocs import ioc_state, coverage as _ioc_coverage
        _iocs = list(ioc_state(entries).values())
        if _iocs:
            _cov = _ioc_coverage(entries)
            ioc_inventory = {"iocs": _iocs, "coverage_counts": _cov["counts"],
                             "open": _cov["open"][:60],
                             # settled without being examined — the report
                             # still lists them as not examined, with the reason
                             "dispositioned": [i for i in _cov["items"]
                                               if i["status"] == "dispositioned"][:60]}
            if _cov["open"]:
                _shown = "; ".join(f"{i['technique']}/{i['component']}" for i in _cov["open"][:8])
                warnings.append(
                    f"{len(_cov['open'])} ATT&CK coverage item(s) for recorded IOCs not examined: "
                    f"{_shown}{' …' if len(_cov['open']) > 8 else ''}. Examine them with the "
                    f"listed tools (misc.list_iocs) or record "
                    f"misc.record_disposition(target_kind=\"coverage\", target_id=\"<technique>:<component>\"). "
                    f"Open items are listed in the report as not examined.")
    except Exception as _e:
        import sys as _sys
        print(f"[TRUDI WARN] IOC coverage check failed: {_e}", file=_sys.stderr)

    ready = len(issues) == 0
    return {
        "ready_to_report": ready if include_synthesis else False,
        "ioc_inventory": ioc_inventory,
        "unshown_review_details": unshown_details,
        "ready_for_synthesis": ready if not include_synthesis else None,
        "issues": issue_records(issues),
        "registry_inventory": registry_inventory,
        "synthesize_blockers_unresolved": synth_unresolved,
        "correspondents_auto_noise": correspondents_auto_noise,
        "blocking_issues": issues,
        "warnings": warnings,
        "lifecycle_coverage": lifecycle_coverage,
        "trace_entries": len(entries),
        "tool_calls": tool_calls,
        "confirmed_findings": confirmed_findings,
        "evaluate_finding_calls": evaluate_calls,
        "has_plan": has_plan,
        "has_synthesize": has_synthesize,
        "has_hypothesize": has_hypothesize,
        "audit_summary": audit_summary,
        "total_input_tokens": total_input_tokens,
        "total_output_tokens": total_output_tokens,
    }
