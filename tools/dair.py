"""DAIR Director — Dynamic Approach to Incident Response phase tracking.

Runs as a parallel track alongside reason.*. Called after every tool batch to
assess which DAIR phase the investigation is in, whether to transition, and what
to focus on next. DAIR may surface candidate pivots, but candidate discovery is
advisory metadata and never mutates phase control flow by itself.

Active phases for TRUDI (read-only forensic tool):
  Triage        — confirm initial IOCs, challenge for hallucinations, produce plan
  Collect       — gather raw artifacts per plan (ez.*, vol.*, tsk.*, strings.*)
  Analyze       — reason about collected artifacts; hypothesize on suspicious findings
  Scan          — scoping: pursue each new IOC to depth — other hosts/network AND deeper on the same host (yara.*, net.*, enrich.*)
  Report        — terminal; emit Improve & Response recommendations

Detection is the assumed trigger (investigation already started). Improve &
Response actions are report recommendations only — never directed tool calls.
"""
import os
import re
import json
from fastmcp import FastMCP
from core.paths import DAIR_TIMEOUT
from tools.reasoning import _parse_directives, _cap_lines, _compat_chat
from tools._llm_parse import (parse_result_block, result_instruction, RESULT_JSON,
                              LEGACY_BLOCK, NONE as PARSE_NONE)
from tools.tool_capabilities import (
    MANIFEST_VERSION,
    annotate_directives_with_manifest,
    format_tool_manifest_for_prompt,
)

mcp = FastMCP("dair")

# ── Backend configuration ─────────────────────────────────────────────────────

DAIR_BACKEND      = os.environ.get("DAIR_BACKEND") or ""
DAIR_URL          = (os.environ.get("DAIR_URL")
                     or os.environ.get("FOUNDATION_SEC_URL") or "")
DAIR_API_KEY      = (os.environ.get("DAIR_API_KEY")
                     or os.environ.get("HF_TOKEN") or "")
DAIR_MODEL        = os.environ.get("DAIR_MODEL") or ""
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY") or ""

_DEFAULT_CLAUDE_MODEL = "claude-haiku-4-5-20251001"
_DEFAULT_COMPAT_MODEL = "fdtn-ai/Foundation-Sec-8B-Reasoning"

# Output budget for dair_assess. DAIR responses include challenges + directives
# + recommended_actions for the Report transition, so this needs headroom.
MAX_TOKENS_DAIR = int(os.environ.get("TRUDI_DAIR_MAX_TOKENS") or "4096")


def _active_backend() -> str:
    if DAIR_BACKEND:
        return DAIR_BACKEND
    if ANTHROPIC_API_KEY:
        return "claude"
    if DAIR_URL:
        return "openai-compat"
    return "claude"


# ── Candidate pivot detection (typed) ────────────────────────────────────────
# DAIR records hosts/principals worth a follow-up look, but it does not mutate
# phase transitions. Candidate pivots are audit metadata only: the model/agent
# may choose to investigate them, but code never rewrites stack_action/next_phase
# from them.
#
# The agent DECLARES what its batch observed — dair_assess(observed_hosts=[…],
# observed_principals=[{name, cue, call_ids}]) — and DAIR diffs those typed
# values against what the trace already knows. No regex runs over the
# tool_results_summary prose: a capitalised word in a sentence can no longer
# become a "principal", and a hostname naming convention needs no env var.

# Validators over a structured token space (an IPv4, a UNC host, a hostname).
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_UNC_HOST_RE = re.compile(r"^\\\\([A-Za-z0-9][\w.-]*)")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")

PRINCIPAL_CUES = ("created", "interactive_logon", "network_logon", "correspondent", "other")
FORCED_CUES = frozenset({"created", "interactive_logon"})

# Built-in accounts are never a genuine new principal.
from tools._gates._entities import BUILTIN_PRINCIPALS as _BUILTIN_PRINCIPALS  # one list


def _norm_host(v: str) -> str:
    """Canonical host key: UNC → host part; upper-case; '_' → '-'."""
    v = str(v or "").strip()
    m = _UNC_HOST_RE.match(v)
    if m:
        v = m.group(1)
    return v.upper().replace("_", "-")


def _is_external_ip(host: str) -> bool:
    """A public (globally-routable, non-private) IP — an external party, never the
    local subject host. Such a host is a genuine pivot even when surfaced during
    Triage: the Triage pivot-exclusion covers the subject host / local network,
    not an external actor connecting to it (an RDP source, C2, exfil endpoint)."""
    try:
        import ipaddress
        ip = ipaddress.ip_address(str(host or "").strip())
        return not (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    except Exception:
        return False


def _validate_hosts(observed_hosts) -> tuple[list[str], list[str]]:
    """(valid canonical hosts, rejected raw values)."""
    ok, bad = [], []
    for raw in observed_hosts or []:
        v = str(raw or "").strip()
        if not v:
            continue
        h = _norm_host(v)
        if _IPV4_RE.match(h) or _HOSTNAME_RE.match(h):
            if h not in ok:
                ok.append(h)
        else:
            bad.append(v)
    return ok, bad


def _validate_principals(observed_principals) -> tuple[list[dict], list[str]]:
    """(valid items {name, cue, call_ids, norm}, error messages)."""
    from tools._gates._entities import norm_entity
    ok, errs = [], []
    for it in observed_principals or []:
        if not isinstance(it, dict):
            errs.append(f"observed_principals item must be an object: {it!r}")
            continue
        name = str(it.get("name") or "").strip()
        cue = str(it.get("cue") or "other").strip().lower()
        if not name:
            errs.append("observed_principals item is missing name")
            continue
        if cue not in PRINCIPAL_CUES:
            errs.append(f"observed_principals cue={cue!r} for {name!r} is not valid — one of: "
                        f"{', '.join(PRINCIPAL_CUES)}")
            continue
        cids = []
        for c in (it.get("call_ids") or []):
            try:
                if int(c):
                    cids.append(int(c))
            except (TypeError, ValueError):
                pass
        ok.append({"name": name, "cue": cue, "call_ids": sorted(set(cids)), "norm": norm_entity(name)})
    return ok, errs


def _known_hosts() -> set[str]:
    """Hosts already surfaced: every prior dair_call's typed observed_hosts and
    candidate host values."""
    known: set[str] = set()
    try:
        from core.execution_log import log as _elog
        for e in _elog._entries:
            if e.get("type") != "dair_call":
                continue
            for h in e.get("observed_hosts") or []:
                known.add(_norm_host(h))
            for pv in e.get("candidate_pivots") or []:
                if isinstance(pv, dict) and pv.get("kind") == "host" and pv.get("value"):
                    known.add(_norm_host(pv["value"]))
    except Exception as _read_err:
        import sys as _sys
        print(f"[TRUDI WARN] dair host-context read failed: {_read_err!r}", file=_sys.stderr)
    return known


def _known_principals() -> set[str]:
    """Principals already known (normalized): prior typed observed_principals
    and candidate values, every finding's principal/entities, the identity
    registry (server-stamped observed_identities)."""
    from tools._gates._entities import norm_entity
    known: set[str] = set()
    try:
        from core.execution_log import log as _elog
        for e in _elog._entries:
            t = e.get("type")
            if t == "dair_call":
                for it in e.get("observed_principals") or []:
                    if isinstance(it, dict) and it.get("name"):
                        known.add(norm_entity(it["name"]))
                for pv in e.get("candidate_pivots") or []:
                    if isinstance(pv, dict) and pv.get("kind") == "principal" and pv.get("value"):
                        known.add(norm_entity(pv["value"]))
            elif t == "finding":
                c = e.get("claim") or {}
                known |= set(c.get("entities_norm") or [])
                if c.get("principal_norm"):
                    known.add(c["principal_norm"])
        if getattr(_elog, "_path", None):
            known |= {norm_entity(k) for k in _elog.index().identities.keys()}
    except Exception as _read_err:
        import sys as _sys
        print(f"[TRUDI WARN] dair principal-context read failed: {_read_err!r}", file=_sys.stderr)
    return {k for k in known if k}


# ── Output defaults ───────────────────────────────────────────────────────────

_EMPTY_ASSESSMENT: dict = {
    "current_phase": "Triage",
    "phase_rationale": "",
    "transition_recommended": False,
    "next_phase": "",
    "transition_rationale": "",
    "stack_action": "stay",
    "investigation_focus": "",
    "verification_satisfied": False,
    "verification_challenges": [],
    "recommended_actions": [],
}


# ── Parsing ───────────────────────────────────────────────────────────────────

def _parse_challenges(raw: str) -> list:
    """Extract VERIFICATION_CHALLENGES JSON array from model output."""
    if not raw:
        return []
    match = re.search(
        r"VERIFICATION_CHALLENGES:\s*(\[.*?\])\s*(?:DAIR_ASSESSMENT:|$)",
        raw,
        re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return []
    text = re.sub(r"\s*//[^\n]*", "", match.group(1))
    try:
        result = json.loads(text)
        return result if isinstance(result, list) else []
    except (json.JSONDecodeError, ValueError):
        return []


def _parse_dair_assessment(raw: str) -> dict:
    """Extract DAIR_ASSESSMENT JSON block from model output.

    Returns _EMPTY_ASSESSMENT on any parse failure so callers always have the
    expected keys. Missing keys in a successful parse are filled from the template.
    """
    if not raw:
        return _EMPTY_ASSESSMENT.copy()
    match = re.search(
        r"\*{0,2}DAIR_ASSESSMENT\*{0,2}\s*:?\*{0,2}\s*(?:```json\s*)?(\{.*\})\s*(?:```)?",
        raw,
        re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return _EMPTY_ASSESSMENT.copy()
    text = re.sub(r"\s*//[^\n]*", "", match.group(1))
    try:
        parsed = json.loads(text)
        return {**_EMPTY_ASSESSMENT, **parsed}
    except (json.JSONDecodeError, ValueError):
        return _EMPTY_ASSESSMENT.copy()


# Candidate-detection allow-list. Hosts/principals surfaced from these phases
# are eligible for candidate_pivots; Triage is excluded because Triage is
# *about* the host/principal already under investigation.
_PIVOT_ELIGIBLE_PHASES = frozenset({"Scan", "Analyze", "Collect"})


def _strip_blocks(text: str) -> str:
    """Remove VERIFICATION_CHALLENGES and DAIR_ASSESSMENT blocks from text."""
    text = re.sub(
        r"\*{0,2}VERIFICATION_CHALLENGES\*{0,2}\s*:?\*{0,2}.*",
        "", text, flags=re.DOTALL | re.IGNORECASE,
    )
    text = re.sub(
        r"\*{0,2}DAIR_ASSESSMENT\*{0,2}\s*:?\*{0,2}.*",
        "", text, flags=re.DOTALL | re.IGNORECASE,
    )
    return text.rstrip()


# ── Backend implementations ───────────────────────────────────────────────────

def _ask_claude(system: str, user: str, max_tokens: int = 2048) -> dict:
    import anthropic
    _empty = {"success": False, "raw": "", "input_tokens": 0, "output_tokens": 0}

    if not ANTHROPIC_API_KEY:
        return {**_empty, "error": "ANTHROPIC_API_KEY not set — add it to .env"}

    model = DAIR_MODEL or _DEFAULT_CLAUDE_MODEL
    try:
        from core.execution_log import log as _elog
        _elog.record_call_initiated("dair_assess", "claude", {"model": model})
    except Exception as _e:
        import sys; print(f"[TRUDI WARN] record_call_initiated failed: {_e}", file=sys.stderr)
    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY, timeout=DAIR_TIMEOUT)
        resp = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=[{
                "type": "text",
                "text": system,
                "cache_control": {"type": "ephemeral"},
            }],
            messages=[{"role": "user", "content": user}],
        )
        raw = resp.content[0].text
        return {
            "success": True,
            "raw": raw,
            "input_tokens": getattr(resp.usage, "input_tokens", 0),
            "output_tokens": getattr(resp.usage, "output_tokens", 0),
        }
    except Exception as e:
        try:
            from core.execution_log import log as _elog
            _elog.record_call_abandoned("dair_assess", str(e))
        except Exception as _log_err:
            # Best-effort — we're already in the failure path; surface to
            # stderr so the operator sees the double-fault. Not routed
            # through record_system_error because that path can fail for
            # the same reason and we'd risk infinite recursion.
            import sys as _sys
            print(f"[TRUDI WARN] dair record_call_abandoned failed during "
                  f"backend error: {_log_err!r}", file=_sys.stderr)
        return {**_empty, "error": str(e)}


def _ask_openai_compat(system: str, user: str, max_tokens: int = 2048) -> dict:
    """OpenAI-compatible backend via the shared thinking-aware client in
    tools.reasoning (`_compat_chat`): honours the caller's max_tokens (this
    path used to hard-code 2048 while MAX_TOKENS_DAIR is 4096), widens the
    budget for a thinking model's chain-of-thought, retries once on a
    budget-exhausted empty answer, and records every failure cause as a
    `call_abandoned` trace entry."""
    _empty = {"success": False, "raw": "", "input_tokens": 0, "output_tokens": 0}

    if not DAIR_URL:
        return {**_empty, "error": "DAIR_URL not set for openai-compat backend"}

    chat = _compat_chat(DAIR_URL, DAIR_API_KEY, DAIR_MODEL, system, user,
                        max_tokens, DAIR_TIMEOUT, "dair_assess")
    if not chat["ok"]:
        return {**_empty, "error": chat["error"],
                "input_tokens": chat["prompt_tokens"],
                "output_tokens": chat["completion_tokens"],
                "backend_meta": chat["meta"]}
    return {
        "success": True,
        "raw": chat["text"],
        "input_tokens": chat["prompt_tokens"],
        "output_tokens": chat["completion_tokens"],
        "backend_meta": chat["meta"],
    }


def _ask(system: str, user: str, max_tokens: int = 2048) -> dict:
    backend = _active_backend()
    if backend == "claude":
        return _ask_claude(system, user, max_tokens)
    return _ask_openai_compat(system, user, max_tokens)


def _log_dair(assessment: dict, input_tokens: int, output_tokens: int,
              inputs: dict | None = None,
              input_call_ids: list[int] | None = None,
              candidate_pivots: list[dict] | None = None,
              error: str = "",
              backend_meta: dict | None = None,
              parse_path: str = "",
              server_override: dict | None = None,
              observed_principals: list[dict] | None = None,
              observed_hosts: list[str] | None = None,
              case_question: str = "") -> int:
    try:
        from core.execution_log import log
        return log.record_dair_call(
            current_phase=assessment.get("current_phase", ""),
            phase_rationale=assessment.get("phase_rationale", ""),
            transition_recommended=assessment.get("transition_recommended", False),
            next_phase=assessment.get("next_phase", ""),
            transition_rationale=assessment.get("transition_rationale", ""),
            stack_action=assessment.get("stack_action", "stay"),
            investigation_focus=assessment.get("investigation_focus", ""),
            verification_satisfied=assessment.get("verification_satisfied", False),
            verification_challenges=assessment.get("verification_challenges", []),
            recommended_actions=assessment.get("recommended_actions", []),
            directives=assessment.get("directives", {}),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            inputs=inputs,
            input_call_ids=input_call_ids,
            pending_pivots=assessment.get("pending_pivots") or None,
            candidate_pivots=candidate_pivots,
            error=error or "",
            backend_meta=backend_meta,
            parse_path=parse_path,
            server_override=server_override,
            observed_principals=observed_principals,
            observed_hosts=observed_hosts,
            case_question=case_question,
        )
    except Exception as e:
        import sys
        print(f"[TRUDI WARN] _log_dair failed: {e}", file=sys.stderr)
        return 0


# ── System prompt ─────────────────────────────────────────────────────────────

_DAIR_SYS = """\
You are the DAIR Director for a read-only digital forensic investigation. \
Your role is to plan each investigation batch and track phase progression.

YOUR ROLE AS INVESTIGATION PLANNER:
You do not merely assess what was found — you prescribe exactly what to investigate \
next. The investigator executes ONLY what you list in directives.priority_tools. \
Nothing outside that list will be run.
- Non-Report phases: priority_tools MUST always be non-empty. If you have nothing \
  new to prescribe for the current phase, transition to the next phase instead of \
  emitting stay with an empty list. An empty priority_tools with stack_action "stay" \
  is invalid and stalls the investigation.
- investigation_focus: one sentence stating the question this batch answers.
- Report phase only: priority_tools is empty; populate recommended_actions instead.
- priority_tools is the complete work order — not a priority ranking. List every \
  tool needed to answer investigation_focus. The investigator runs them all.

CURIOSITY BUDGET (directives.curiosity_budget):
priority_tools is a convergent work order; on its own it drives single-actor \
lock-in and shallow coverage. The curiosity_budget is its counterweight — the \
number of read-only probes the investigator may run of their OWN choosing this \
batch, on top of priority_tools, to chase a hunch about a LESS-OBVIOUS artifact. \
Set it per batch:
  - Triage / Analyze: 2-3 (these phases surface the leads worth chasing).
  - Collect / Scan: 1-2.
  - Report: 0 (the investigation is converging; no new exploration).
Raise it (to 3) when the batch surfaced a NEW principal/identity, a coverage gap, \
or an artifact that contradicts the working hypothesis — those are exactly the \
moments to widen the look. A probe is read-only and cannot itself record a \
finding, so granting budget never risks evidence integrity.
ABSENCE-HYPOTHESIZE BEFORE TRANSITION: before you set transition_recommended=true \
to leave a non-Report phase, OR when the Triage max-pass cap is about to force a \
transition, FIRST put reason.hypothesize (mode="absence") at the front of \
priority_tools — observation = the still-unresolved part of the case question, \
evidence = the artifact categories already examined. It returns the untouched \
high-value categories (second-principal logon source, a different SID's profile, \
an alternate exfil channel, setupapi.dev.log) as probe candidates. This forces \
one divergent look before the funnel closes. Skip it only in Report.

IMPORTANT CONSTRAINTS:
- TRUDI is a read-only forensic tool. Improve & Response actions are NEVER \
performed — they appear only as recommendations in the final report.
- The investigation begins with a confirmed positive detection already in hand. \
Start at Triage unless the stack says otherwise.
- You are a state machine, not a checklist. Any phase can transition to any other \
when evidence demands it.
- LINEAGE IS MANDATORY: every dair_assess, reason.*, record_finding, and \
record_self_correction call MUST pass input_call_ids=[<cid>, ...] listing the \
_trudi_call_id values of the entries that informed this step. The lineage_required \
gate refuses calls with empty input_call_ids after the first 5 trace entries \
(genesis grace). This makes the trace a self-describing causal DAG so the chain \
view and audit consumers can traverse real foreign keys, not heuristic guesses.

ACTIVE PHASES:
CASE-QUESTION ANCHORING: Every investigation has a case question stated in \
case_context as 'CASE_QUESTION: <one sentence>'. The initial Triage MUST run \
reason.hypothesize on the case question BEFORE reason.plan — the returned \
hypotheses become the testable propositions tracked across the investigation. \
DAIR's transition to Report is gated by reason.pre_report_check, which refuses \
ready_to_report unless at least one CONFIRMED or LIKELY finding directly \
addresses the case question's key entities.

KNOWNS-DRIVEN HUNTING: When case_context includes a reference set (suspect \
list, asset inventory, allowlist, baseline, hash list), include \
misc.knowns_pattern_generate followed by a knowns-IOC sweep \
(net.ngrep_search / strings.strings_grep / yara.scan_strings against the \
returned pattern) in the FIRST Triage batch — before generic enumeration.

  Triage   — confirm the initial IOC/alert AND actively challenge your own findings \
for hallucinations. Check file existence, registry key presence, process records, \
network connections. Every claim must be traceable to a specific tool output field \
and value. Produce an investigation plan via directives.priority_tools.
  Collect  — gather raw artifacts as directed by the Triage plan. Run ez.*, vol.*, \
tsk.*, strings.* tools. Stay until the plan is satisfied; advance to Analyze when \
sufficient evidence is in hand. \
EXHAUSTION RULE: for each artifact category named in the Triage plan (registry hives, \
event log channels, HTTP session cookies, memory regions, browser profiles), collect \
ALL instances of that category — not just the first one that yields results. Advance \
to Analyze only when every named category has been fully collected, not merely sampled. \
For network evidence: before advancing from Collect, run net.ngrep_search(pattern="Cookie:") \
and net.ngrep_search(pattern="(login|email|username|user=|gausr=|Y=|T=)") on each \
suspect device's traffic, plus net.tcpdump_extract_http and net.tcpxtract_streams. \
Cross-reference every found identity (email, username, screen name, cookie value) \
against any suspect list provided in case_context before advancing.
  Analyze  — reason about the collected artifacts: process trees, network \
connections, persistence mechanisms, TTPs. Each suspicious artifact should be \
examined. A genuinely ambiguous artifact may require more collection before \
proceeding. \
PIVOT CANDIDATES: a host or principal other than the one under investigation — \
remote logon (4624 type 3/10), SMB session, mapped drive, inbound RDP, \
\\\\HOST\\share path, named pipe to a remote endpoint, newly-created account, or \
first-seen identity — is surfaced structurally: the investigator declares it typed \
(observed_hosts / observed_principals) and dair_assess returns it in candidate_pivots. \
You do not infer pivots from summary prose. When a returned candidate matters to the \
case question, prescribe explicit evidence-gathering tools for it; never mutate the \
phase stack merely because a candidate exists. \
ALSO run anti-forensics detectors here when the relevant input artifacts exist: \
af.af_timestomp_drift (after ez.mftecmd CSV), af.af_event_log_clear (after \
ez.evtxecmd), af.af_sysmon_evasion (after ez.recmd_hive SYSTEM), af.af_usn_gaps \
(after misc.usnparser_parse), af.af_prefetch_deletion (after ez.pecmd + \
ez.appcompatcacheparser/amcacheparser).

INAPPLICABLE TOOL SUBSTITUTION: If a priority_tools entry names a tool that \
cannot run against the available evidence type (e.g. ez.evtxecmd, ez.mftecmd, \
vol.pslist, tsk.fls on a PCAP-only case; net.tcpdump_read on a disk-only case), \
do NOT skip it silently and treat the work order as satisfied. Instead: \
(a) remove the inapplicable tool from the work order; \
(b) substitute the nearest equivalent for the actual evidence type — for Windows \
artifact tools on a PCAP case use net.ngrep_search or net.tcpdump_extract_http; \
(c) log the substitution as an agent_message. An empty work order after \
substitution means call dair_assess again for new priority_tools — not that \
collection is complete.

IDENTITY RESOLUTION (mandatory before leaving Analyze): before recording any finding \
that states a real-world identity is unknown or unresolvable, verify that the Collect \
phase ran ALL identity-yielding tool categories for this evidence type. If any category \
was skipped, return stack_action "stay" and add the missing tools to priority_tools — \
do not advance to Scan or Report with an unresolved identity when evidence remains \
uncollected. Cross-referencing found identities against any suspect list in case_context \
is a required Analyze step, not optional enrichment.

LIVE ENDPOINT CASES: When case_context names a live endpoint (the agent will \
mention 'live=true' or supply an endpoint_host like 'ubuntu-endpoint' in case \
context), include live.* tools in priority_tools as appropriate:
  Triage   — live.live_processes, live.live_network_connections, live.live_recent_logins
  Collect  — live.live_persistence_audit, live.live_services, live.live_scheduled_tasks
  Analyze  — live.live_process_details(pid) and live.live_open_files(pid) for \
suspicious PIDs; live.live_event_log_tail(unit) for services of interest; \
live.live_read_file for small config artifacts (max 64KB cap)
  Scan     — live.live_yara_scan(rules_path, target_dir) for cross-host hunting
The live.* tools route through SSH with fixed argv (no remote shell parsing); \
findings can use their _trudi_call_id as linked_call_id like any other tool.
  Scan     — SCOPING: pursue every newly-discovered IOC to depth. Scoping has \
TWO senses, not one: (i) OTHER hosts / network scope — did this propagate? \
(yara.scan_directory across all collected disk/memory, net.tcpdump_extract_dns \
for exfil signatures, enrich.vt_lookup_hash / enrich.abuseipdb_check for \
hashes/IPs); AND (ii) DEEPER investigation of the SAME host driven by a new IOC \
surfaced in Triage/Collect/Analyze — a covert account (its $Recycle.Bin, \
Desktop, LNKs, autoruns), a flagged injector-payload scheduled task (read the \
payload, tie it to its device and author), an unexpected inbound logon source \
(who operated it). A new IOC is FOLLOWED, not ticked and passed: scoping the \
account-creation task means opening the %duck% payload and asking who ran it, \
not recording that a task exists. Candidate pivots (hosts AND forced principals) \
and flagged IOCs discovered anywhere are the scoping leads; they are advisory \
metadata (they do not rewrite the phase stack), but each must be driven to a \
finding or a typed disposition before Report — the server surfaces any left open \
as a pre_report warning. Advance to Report when both senses are exhausted: the \
cross-host sweep is done AND every case-relevant lead has been investigated or \
explicitly parked (out of scope / evidence unavailable).
  Report   — terminal phase unless report review exposes unresolved evidence. \
If reason.synthesize or reason.pre_report_check returns any BLOCKER / \
ready_to_report=false issue that asks for missing evidence, do NOT try to satisfy \
it by rephrasing findings. Set stack_action to "push" with next_phase="Collect" \
or next_phase="Analyze" (whichever is the smallest phase that can gather or \
reason over the missing artifact), and put the concrete missing tools in \
directives.priority_tools. Only stay in Report for wording/citation cleanup when \
no missing-evidence blocker remains. BEFORE reason.synthesize, call BOTH \
coverage.coverage_report (TTP coverage checklist) AND attribution.attribute_actors \
(adversary attribution from observed T-IDs) so the final synthesis input has the \
complete picture. When findings span multiple hosts, ALSO call \
correlate.process_to_file and correlate.network_to_process (with no PID/IP/path \
filter, to get the full cross-host join) so the synthesis input has real \
cross-host joins rather than isolated per-host slices. Then synthesise findings \
into a timeline. Emit Improve & Response recommendations for the IR team in \
recommended_actions. Never direct containment or eradication tool calls.

PHASE STACK:
The phase_stack is the investigation phase history. Newest entry is last. \
Use it to understand depth and context. Candidate pivots are separate metadata; \
they do not automatically add Triage frames.
  stack_action "push"  → transition to next_phase; new entry added to stack
  stack_action "pop"   → current sub-phase resolved; resume the phase beneath
  stack_action "stay"  → continue in current_phase (e.g. challenges still pending)

VERIFICATION CHALLENGES (mandatory when current_phase == Triage):
For every discrete claim in the tool results summary, emit a challenge entry:
  - claim: the exact claim (file path, registry key, process name, IP, etc.)
  - challenge_method: the specific TRUDI tool that confirms it \
(strings.stat_file, tsk.fls, vol.pslist, ez.recmd_hive, vol.netscan, etc.)
  - verified: null if the tool has not yet run; true if tool output confirms; \
false if tool output refutes
  - confidence_impact: tier downgrade string if verified is false (e.g. \
"CONFIRMED → SUSPECTED"); "—" if verified is true or null
  - notes: what the tool found, or why the claim cannot be verified
When verified is null, the challenge_method tool MUST appear in \
directives.priority_tools so it runs in the next batch.
If any challenge resolves to false, that claim must be downgraded or removed \
before advancing to Collect.
In Collect, Analyze, or Scan phases, VERIFICATION_CHALLENGES may be omitted \
unless a specific claim needs active challenging.

TRIAGE SATISFACTION:
Set verification_satisfied=true when the primary IOCs are confirmed or refuted \
to a sufficient evidential standard, even if some secondary challenges remain \
pending. Criteria for satisfaction:
  - All load-bearing claims (file existence, process identity, network connection \
    attribution) have verified=true or verified=false.
  - Remaining verified=null entries are enrichment-only (VT lookups, timestamp \
    cross-checks, attribution details) — they add confidence but are not required \
    to establish the core compromise.
  - Re-running the same challenge category for the third or more time yields \
    diminishing returns (no new material pivots).
When verification_satisfied=true, set transition_recommended=true, \
next_phase="Collect", and stack_action="push". Do not keep the investigation in \
Triage indefinitely — acceptable residual uncertainty is normal.


OUTPUT FORMAT:
Write your analysis first. Then output the structured blocks in this order:

If current_phase is Triage, output VERIFICATION_CHALLENGES first:
VERIFICATION_CHALLENGES:
[
  {
    "claim": "...",
    "challenge_method": "strings.stat_file",
    "verified": null,
    "confidence_impact": "—",
    "notes": ""
  }
]

Then always output DAIR_ASSESSMENT (no markdown bold, no code fences, no // comments):
DAIR_ASSESSMENT:
{
  "current_phase": "Triage",
  "phase_rationale": "...",
  "transition_recommended": false,
  "next_phase": "",
  "transition_rationale": "",
  "stack_action": "stay",
  "investigation_focus": "...",
  "verification_satisfied": false,
  "verification_challenges": [],
  "recommended_actions": [],
  "directives": {
    "priority_tools": [],
    "skip_tools": [],
    "focus_pids": [],
    "focus_paths": [],
    "max_depth": "",
    "next_hypothesis_triggers": [],
    "curiosity_budget": 0
  }
}

verification_challenges in DAIR_ASSESSMENT must mirror VERIFICATION_CHALLENGES block \
exactly when in Triage phase. recommended_actions is populated ONLY when \
transitioning to Report — list specific Improve & Response actions for the IR team. \
Tool names in directives must use TRUDI MCP format: namespace.tool and must \
come from the Tool Capability Manifest below. \
Remember: priority_tools is the investigator's complete work order for this batch. \
Make it specific and executable — every entry will be run before you see results.\
""" + result_instruction(
    '{"assessment": { … the DAIR_ASSESSMENT object … }, "challenges": [ … the '
    'VERIFICATION_CHALLENGES array (Triage only) … ], "directives": { … the DIRECTIVES object … }}'
)

_DAIR_SYS = _DAIR_SYS + "\n\n" + format_tool_manifest_for_prompt()


# ── MCP tool ──────────────────────────────────────────────────────────────────


def _phases_entered(entries) -> set:
    """Phases the investigation entered, counted ONLY from server-trusted
    events: the backend's recommended pushes (next_phase, parsed server-side
    from the DAIR model's answer, including server overrides) and the
    server-gated max-pass-cap self_correction (its manual Collect push is
    validated by the max_pass_cap gate). A dair entry's `current_phase` is
    the model's echo of the agent-supplied phase_stack and is NOT counted —
    an asserted stack must never satisfy phase coverage. Every investigation
    starts in Triage."""
    out: set = {"Triage"}
    for e in entries or []:
        if not isinstance(e, dict):
            continue
        if (e.get("type") == "dair_call"
                and str(e.get("stack_action") or "") == "push"
                and e.get("transition_recommended")):
            np = str(e.get("next_phase") or "").strip().capitalize()
            if np:
                out.add(np)
        elif (e.get("type") == "self_correction"
              and str(e.get("trigger") or "") == "dair_max_pass_cap"):
            out.add("Collect")
    return out


def _is_live_monitoring_trace(entries) -> bool:
    """Per-investigation live-monitoring traces (a SUCCESSFUL
    monitor.start_investigation — the call itself refuses outside a
    baselined live-monitoring case) run a compressed alert-response loop,
    not the full static-case DAIR cycle."""
    return any(isinstance(e, dict)
               and "monitor_start_investigation" in str(e.get("cmd") or "")
               and e.get("success") is not False
               for e in entries or [])


_MEM_EXT_RE = re.compile(r"\.(mem|dmp|vmem|lime|crash|hpak|aff4)$", re.IGNORECASE)
_PCAP_EXT_RE = re.compile(r"\.(pcap|pcapng|cap)$", re.IGNORECASE)
_DISK_EVIDENCE_RE = re.compile(r"\.(e01|dd|img|001|vhdx?|vmdk|ex01)$|cylr", re.IGNORECASE)


def _evidence_types(trace_path) -> tuple:
    """(memory_present, pcap_present) from the case evidence/ dir — each True or
    False, or None when undeterminable (fail-open). Conservative on the RISKY
    direction: only report an evidence type ABSENT when disk/other evidence is
    present AND no file of that type (and, for memory, no ambiguous .raw) exists —
    so vol.*/net.* are dropped only when we're confident the case cannot run them."""
    if not trace_path:
        return (None, None)
    try:
        from pathlib import Path as _P
        evd = _P(trace_path).resolve().parent.parent / "evidence"
        if not evd.is_dir():
            return (None, None)
        names, n = [], 0
        for p in evd.rglob("*"):
            names.append(p.name); n += 1
            if n > 20000:
                break
        disk = any(_DISK_EVIDENCE_RE.search(x) for x in names)
        mem_files = any(_MEM_EXT_RE.search(x) for x in names)
        raw_amb = any(x.lower().endswith(".raw") for x in names)   # .raw: disk OR memory — ambiguous
        pcap_files = any(_PCAP_EXT_RE.search(x) for x in names)
        mem = True if mem_files else (False if (disk and not raw_amb) else None)
        pcap = True if pcap_files else (False if disk else None)
        return (mem, pcap)
    except Exception:
        return (None, None)


def missing_report_phases(entries) -> list:
    """Phases a static investigation must have transited before Report:
    Collect AND Analyze always; Scan additionally when host candidate pivots
    exist (a lead to other hosts demands the sweep). [] when satisfied or when
    this is a live-monitoring investigation trace."""
    if _is_live_monitoring_trace(entries):
        return []
    entered = _phases_entered(entries)
    required = ["Collect", "Analyze"]
    if any(isinstance(pv, dict) and str(pv.get("kind") or "").lower() == "host"
           for e in (entries or []) if isinstance(e, dict) and e.get("type") == "dair_call"
           for pv in (e.get("candidate_pivots") or [])):
        required.append("Scan")
    return [ph for ph in required if ph not in entered]


@mcp.tool()
def dair_assess(
    tool_results_summary: str,
    phase_stack: str = "[]",
    case_context: str = "",
    input_call_ids: list[int] | None = None,
    observed_principals: list[dict] | None = None,
    observed_hosts: list[str] | None = None,
    case_question: str = "",
) -> dict:
    """
    Assess the current DAIR phase, challenge findings, and direct the next steps.
    Call this after every parallel tool batch, and at each phase transition.

    tool_results_summary: 3-5 sentence summary of what the last tool batch found.
    phase_stack: JSON list of {phase, entry_reason, depth} objects, newest last.
                 Pass "[]" on the first call — DAIR will start at Triage.
    case_context: case ID, known threat actor, confirmed IOCs so far.
    input_call_ids: REQUIRED — list of _trudi_call_id values for the tool calls
        whose results you summarised in tool_results_summary. This makes the
        DAIR entry's upstream lineage explicit (instead of being inferred
        positionally by the chain view).

    Returns: current_phase, phase_rationale, transition_recommended, next_phase,
             transition_rationale, stack_action, investigation_focus,
             verification_challenges (when in Triage), recommended_actions
             (when transitioning to Report), directives, _trudi_call_id.

    stack_action "push"  → append {phase: next_phase, entry_reason, depth} to stack
    stack_action "pop"   → remove top entry; resume parent phase
    stack_action "stay"  → no change to stack

    observed_principals: TYPED declaration of the accounts/identities this
        batch surfaced — [{"name": "svc_x", "cue": "created"|"interactive_logon"|
        "network_logon"|"correspondent"|"other", "call_ids": [<cid>, …]}]. A
        previously-unseen principal with cue created / interactive_logon is a
        FORCED candidate pivot that must be dispositioned before Report
        (bind it with a session artifact, or misc.record_disposition). DAIR
        does not read principals out of the summary prose.
    observed_hosts: TYPED declaration of hosts this batch surfaced (IPv4,
        \\\\HOST\\share, or hostname). New ones become host candidate pivots.
    case_question: the one-sentence case question (same as reason.plan's).

    Cycle: Triage → Collect → Analyze → Scan → Report. Candidate hosts or
    principals may be returned in candidate_pivots, but they are advisory
    observations and do not alter stack_action or next_phase. DAIR refuses
    next_phase="Report" server-side while the trace holds no finding entries.

    When stack_action is "push" and next_phase is "Triage": check
    verification_challenges for entries with verified=null and run the specified
    challenge_method tools (they will be in directives.priority_tools).

    When next_phase is "Report": review recommended_actions for Improve & Response
    items to include in the report. These are advisory only — TRUDI never performs
    containment or eradication.
    """
    summary = _cap_lines(tool_results_summary.strip(), 100)
    context = _cap_lines(case_context.strip(), 50) if case_context else ""

    stack_str = phase_stack.strip() or "[]"
    try:
        stack = json.loads(stack_str)
        if not isinstance(stack, list):
            stack = []
    except (json.JSONDecodeError, ValueError):
        stack = []

    current = stack[-1].get("phase", "Triage") if stack else "Triage"

    user_parts = [f"TOOL RESULTS SUMMARY:\n{summary}"]
    user_parts.append(f"\nCURRENT PHASE STACK (newest last):\n{json.dumps(stack, indent=2)}")
    user_parts.append(f"\nCURRENT PHASE: {current}")
    if context:
        user_parts.append(f"\nCASE CONTEXT:\n{context}")
    user = "\n".join(user_parts)

    # Capture exactly what was sent to the DAIR model so the trace can be
    # audited by judges or replayed later.
    call_inputs = {
        "tool_results_summary": summary,
        "phase_stack": stack,
        "case_context": context,
        "current_phase": current,
        "tool_manifest_version": MANIFEST_VERSION,
        "user_message": user,
    }

    backend_result = _ask(_DAIR_SYS, user, max_tokens=MAX_TOKENS_DAIR)

    _empty_result = {
        **_EMPTY_ASSESSMENT,
        "directives": _parse_directives(""),
        "success": False,
        "input_tokens": 0,
        "output_tokens": 0,
    }

    if not backend_result.get("success"):
        err = backend_result.get("error", "unknown error")
        result = {**_empty_result, "error": err}
        _log_dair(_EMPTY_ASSESSMENT | {"directives": _parse_directives("")},
                  backend_result.get("input_tokens", 0),
                  backend_result.get("output_tokens", 0),
                  inputs=call_inputs, input_call_ids=input_call_ids,
                  error=err, backend_meta=backend_result.get("backend_meta"))
        result["_trudi_call_id"] = 0
        return result

    raw = backend_result["raw"]
    # Structured-first: RESULT {"assessment": {...}, "challenges": [...],
    # "directives": {...}}; the legacy DAIR_ASSESSMENT / VERIFICATION_CHALLENGES
    # blocks remain the fallback. parse_path records which one was used.
    rb, _ = parse_result_block(raw)
    parse_path = PARSE_NONE
    if isinstance(rb, dict) and isinstance(rb.get("assessment"), dict):
        assessment = {**_EMPTY_ASSESSMENT, **rb["assessment"]}
        challenges = rb.get("challenges") if isinstance(rb.get("challenges"), list) else []
        if isinstance(rb.get("directives"), dict) and rb["directives"]:
            assessment["directives"] = dict(rb["directives"])
        parse_path = RESULT_JSON
    else:
        challenges = _parse_challenges(raw)
        assessment = _parse_dair_assessment(raw)
        if re.search(r"DAIR_ASSESSMENT|VERIFICATION_CHALLENGES", raw or "", re.IGNORECASE):
            parse_path = LEGACY_BLOCK

    # challenges from dedicated block take precedence over those embedded in assessment
    if challenges:
        assessment["verification_challenges"] = challenges

    # Server-side: a challenge whose challenge_method ALREADY ran successfully
    # in this trace is verified by that run — DAIR can re-issue challenges for
    # tools that ran earlier, and the never-run check only counts runs AFTER
    # the challenge. The verifying call is stamped so the auditor can follow it.
    try:
        from core.execution_log import log as _vlog
        if getattr(_vlog, "_path", None):
            from tools._gates.work_order import _binary_sig as _bsig
            from tools._gates._evidence_calls import is_evidence_tool_call as _is_ev
            from tools._gates.max_pass_cap import claim_tokens as _ctok, \
                run_matches_challenge as _rmatch
            _runs = [e for e in (getattr(_vlog, "_entries", None) or []) if _is_ev(e)]
            for _c in assessment.get("verification_challenges") or []:
                if not isinstance(_c, dict) or _c.get("verified") is not None:
                    continue
                _m = str(_c.get("challenge_method") or "").strip().split("(", 1)[0].strip()
                if not _m or _m.split(".")[0].split("_")[0] in ("reason", "dair"):
                    continue
                _sig = _bsig(_m)
                if len(_sig) < 3:
                    continue
                # Signature AND claim-token overlap: a bare `stat` of the
                # image must not verify a claim about a registry value.
                _toks = _ctok(_c.get("claim"))
                _hit = next((int(e.get("call_id") or 0) for e in _runs
                             if _rmatch(e, _sig, _toks)), None)
                if _hit:
                    _c["verified"] = True
                    _c["verified_basis"] = "prior_run"
                    _c["verified_by_call_id"] = _hit
    except Exception:
        pass

    candidate_pivots: list[dict] = []
    ok_hosts, bad_hosts = _validate_hosts(observed_hosts)
    ok_principals, principal_errs = _validate_principals(observed_principals)
    typed_input_errors = ([f"observed_hosts value is not a host: {b!r}" for b in bad_hosts]
                          + principal_errs)

    # Cross-phase pivot observation from the agent's TYPED declarations. Any
    # non-Triage phase may surface a host or principal worth follow-up, but this
    # metadata must not rewrite the DAIR transition.
    #
    # Triage is excluded because it is *about* the host/principal already under
    # investigation — but that rationale does not cover a NEW external party or
    # a newly-created/logged-on account surfaced during Triage (a front-loaded
    # Triage that declares an external RDP source as a host must not silently
    # drop it, or no Scan is ever required). An external (public) IP is not the
    # subject host, and a created/interactive_logon principal is a distinct
    # principal by definition — both pivot even at Triage. Per-item eligibility
    # instead of a blanket phase gate.
    _pivot_phase = current in _PIVOT_ELIGIBLE_PHASES
    known_hosts = _known_hosts()
    for h in ok_hosts:
        if h in known_hosts:
            continue
        if not (_pivot_phase or _is_external_ip(h)):
            continue
        candidate_pivots.append({
            "kind": "host", "value": h, "source": "observed_hosts", "phase": current,
        })
    known_principals = _known_principals()
    for it in ok_principals:
        n = it["norm"]
        if not n or n in known_principals or it["name"].lower() in _BUILTIN_PRINCIPALS:
            continue
        forced = it["cue"] in FORCED_CUES
        if not (_pivot_phase or forced):
            continue
        candidate_pivots.append({
            "kind": "principal", "value": it["name"], "source": "observed_principals",
            "phase": current, "cue": "forced" if forced else "appearance",
            "declared_cue": it["cue"], "call_ids": it["call_ids"],
        })

    # Guard: if all triage challenges resolved true but the assessment JSON failed
    # to parse (phase_rationale empty = _EMPTY_ASSESSMENT fallback), auto-satisfy.
    if (
        assessment.get("current_phase") == "Triage"
        and not assessment.get("verification_satisfied")
        and assessment.get("stack_action") == "stay"
    ):
        _ch = assessment.get("verification_challenges", [])
        if _ch and all(c.get("verified") is not None for c in _ch) \
                and all(c.get("verified") is not False for c in _ch):
            assessment["verification_satisfied"] = True
            assessment["transition_recommended"] = True
            assessment["next_phase"] = "Collect"
            assessment["stack_action"] = "push"
            if not assessment.get("transition_rationale"):
                assessment["transition_rationale"] = (
                    "Auto-satisfied: all verification challenges confirmed"
                )

    # directives come from inside the DAIR_ASSESSMENT JSON block; ensure they have
    # all required keys by merging with the empty template via _parse_directives
    embedded = assessment.get("directives")
    if isinstance(embedded, dict) and embedded:
        from tools.reasoning import _EMPTY_DIRECTIVES
        assessment["directives"] = annotate_directives_with_manifest(
            {**_EMPTY_DIRECTIVES, **embedded}
        )
    else:
        assessment["directives"] = annotate_directives_with_manifest(
            _parse_directives(raw)
        )

    # Server-side refusal: Report with ZERO findings in the trace is never a
    # valid transition — a report has nothing to say. The model's decision is
    # overridden, the override is persisted on the entry, and the work order
    # asks for findings.
    server_override = None
    try:
        from core.execution_log import log as _flog
        _n_findings = len((_flog.index().by_type.get("finding") or [])) if getattr(_flog, "_path", None) else 0
    except Exception:
        _n_findings = 0
    if assessment.get("next_phase") == "Report" and _n_findings == 0:
        server_override = {"kind": "report_refused_zero_findings",
                           "detail": "no finding entries in trace",
                           "model_next_phase": "Report",
                           "model_stack_action": assessment.get("stack_action")}
        assessment["transition_recommended"] = False
        assessment["next_phase"] = ""
        assessment["stack_action"] = "stay"
        assessment["transition_rationale"] = (
            "Server override: Report refused — the trace holds no finding entries. "
            "Record findings (misc.record_finding with a typed claim) from a collection "
            "phase, then re-assess."
        )
        d = assessment.get("directives") or {}
        pt = [t for t in (d.get("priority_tools") or []) if t != "misc.record_finding"]
        d["priority_tools"] = ["misc.record_finding"] + pt
        assessment["directives"] = d

    # Server-side refusal: Report before the investigation has transited its
    # collection/analysis phases is a methodology violation — a report written
    # from Triage alone skipped the systematic enumeration the phases exist to
    # force. Phase history is read from the trace's dair entries, never from
    # agent prose.
    _missing_phases: list = []
    if assessment.get("next_phase") == "Report":
        try:
            from core.execution_log import log as _phlog
            if getattr(_phlog, "_path", None):
                _missing_phases = missing_report_phases(getattr(_phlog, "_entries", None) or [])
        except Exception:
            _missing_phases = []
    if assessment.get("next_phase") == "Report" and _missing_phases and server_override is None:
        server_override = {"kind": "report_refused_phase_coverage",
                           "detail": f"phases never entered: {', '.join(_missing_phases)}",
                           "model_next_phase": "Report",
                           "model_stack_action": assessment.get("stack_action")}
        _next = _missing_phases[0]
        assessment["transition_recommended"] = True
        assessment["next_phase"] = _next
        assessment["stack_action"] = "push"
        assessment["transition_rationale"] = (
            f"Server override: Report refused — the investigation never entered "
            f"{', '.join(_missing_phases)}. A defensible report requires the full "
            f"DAIR cycle (Triage → Collect → Analyze{' → Scan' if 'Scan' in _missing_phases else ''} "
            f"→ Report); transitioning to {_next} to run the systematic collection "
            f"the phase exists for."
        )

    # Triage must not absorb the Collect work order: a model that emits
    # next_phase=Collect while keeping stack_action=stay is the contradiction —
    # collection then runs under a single Triage frame, hosts declared there
    # never become candidate pivots, and the dair history stays all-Triage.
    # When verification is complete (genuine parse, no open challenge), coerce
    # the push so collection runs IN Collect. Server coercion of stack_action
    # is the established pattern (phase_coverage, work_order_incomplete).
    if (server_override is None
            and str(assessment.get("current_phase")) == "Triage"
            and str(assessment.get("stack_action")) == "stay"
            and str(assessment.get("next_phase")) == "Collect"
            and assessment.get("phase_rationale")):
        _ch_a = [c for c in (assessment.get("verification_challenges") or [])
                 if isinstance(c, dict)]
        if not any(c.get("verified") is None for c in _ch_a):
            assessment["transition_recommended"] = True
            assessment["stack_action"] = "push"
            assessment["transition_rationale"] = (
                "Server override: Triage points to Collect and verification is "
                "complete (no open challenge) — advancing so the collection work "
                "order runs in Collect, not under a single Triage frame. Collection "
                "does not happen in Triage.")
            server_override = {
                "kind": "triage_points_to_collect",
                "detail": "next=Collect + verification complete → push Triage→Collect"}

    # Phase-aware handling of an empty work order in a non-Report phase (the
    # director's prompt forbids it, but models emit it and stall). Each phase
    # has a distinct duty, so the response is phase-specific, never a blanket
    # "backfill collection":
    #   Triage  — VERIFICATION, not collection. Empty ⇒ IOC challenges resolved ⇒
    #             ADVANCE to Collect. Collection never happens in Triage.
    #   Collect — the collection phase. Empty ⇒ BACKFILL from uncovered lifecycle
    #             phases; advance to Analyze only when coverage is complete.
    #   Analyze — reasoning. Empty ⇒ advance to SCAN while scoping leads remain
    #             (unresolved pivots / flagged IOCs — deeper same-host OR other
    #             host), else Report.
    #   Scan    — scoping. Empty ⇒ leads all resolved ⇒ advance to Report.
    # The director then always returns directives or advances — never a bare stall.
    if (server_override is None
            and str(assessment.get("stack_action")) == "stay"
            and str(assessment.get("current_phase") or "") not in ("Report", "")
            and not (assessment.get("directives") or {}).get("priority_tools")):
        try:
            from tools._gates._lifecycle import prescribe_for_gaps
            from tools._gates._scoping import open_scoping_leads
            _entries3 = getattr(_flog, "_entries", None) or []
            _cur3 = str(assessment.get("current_phase") or "")

            def _advance3(nxt, kind, detail, rationale):
                assessment["transition_recommended"] = True
                assessment["next_phase"] = nxt
                assessment["stack_action"] = "push"
                assessment["transition_rationale"] = rationale
                return {"kind": kind, "detail": detail}

            if _cur3 == "Triage":
                # Triage is verification — advance, never backfill collection here.
                # BUT only when verification is genuinely complete: the assessment
                # actually parsed (a malformed/fallback assessment is not evidence
                # of anything) AND no verification challenge is still open
                # (verified is None). Otherwise leave the stack alone — the agent
                # keeps working the challenges / re-assesses; the max-pass cap
                # handles a genuine stall. This prevents a parse failure or a
                # pending challenge from being read as "verification done".
                _ch3 = [c for c in (assessment.get("verification_challenges") or [])
                        if isinstance(c, dict)]
                _open_ch3 = any(c.get("verified") is None for c in _ch3)
                # A non-empty phase_rationale = a genuine parse (empty rationale is
                # the _EMPTY_ASSESSMENT fallback — same convention the auto-satisfy
                # guard uses). Never read a fallback assessment as "verification done".
                if assessment.get("phase_rationale") and not _open_ch3:
                    server_override = _advance3(
                        "Collect", "triage_verification_complete",
                        "empty Triage work order — verification done; advancing to Collect",
                        "Server override: Triage verification complete (no open challenges in "
                        "the work order) — advancing to Collect, where the systematic attack-"
                        "lifecycle collection belongs. Collection does not happen in Triage.")
            elif _cur3 == "Collect":
                _backfill = prescribe_for_gaps(_entries3)
                if _backfill:
                    server_override = {"kind": "lifecycle_backfill",
                                       "detail": f"empty Collect work order backfilled from "
                                                 f"uncovered lifecycle phases: {', '.join(_backfill)}"}
                    _d3 = assessment.get("directives") or {}
                    _d3["priority_tools"] = _backfill
                    assessment["directives"] = _d3
                    assessment["investigation_focus"] = (
                        "Examine the uncovered attack-lifecycle phase(s) — persistence, "
                        "privilege escalation, lateral movement, evidence of execution, "
                        "exfiltration — with the prescribed tools.")
                else:
                    server_override = _advance3(
                        "Analyze", "lifecycle_complete_advance",
                        "attack-lifecycle coverage complete; advancing to Analyze",
                        "Server override: empty Collect work order with complete attack-"
                        "lifecycle coverage — collection is done; advancing to Analyze.")
            elif _cur3 == "Analyze":
                _leads3 = open_scoping_leads(_entries3)
                if _leads3:
                    _shown = ", ".join(f"{l['kind']}:{l['value']}" for l in _leads3[:5])
                    server_override = _advance3(
                        "Scan", "analyze_to_scan_scoping",
                        f"open scoping leads: {_shown}",
                        "Server override: empty Analyze work order but scoping leads remain "
                        f"({_shown}) — advancing to Scan to pursue them to depth (deeper on "
                        "this host, or another host) before Report. Scan is scoping: a new "
                        "IOC is followed, not ticked and passed.")
                else:
                    server_override = _advance3(
                        "Report", "analyze_to_report",
                        "Analyze complete; no open scoping leads; advancing to Report",
                        "Server override: empty Analyze work order and no open scoping leads "
                        "— advancing to Report.")
            elif _cur3 == "Scan":
                _leads3 = open_scoping_leads(_entries3)
                if not _leads3:
                    server_override = _advance3(
                        "Report", "scan_complete_advance",
                        "scoping complete; no open leads; advancing to Report",
                        "Server override: empty Scan work order and no open scoping leads "
                        "— scoping is done; advancing to Report.")
                # else: leave the stall to the normal cap; open leads mean the
                # agent still has scoping work the director already surfaced.
        except Exception as _e3:
            import sys as _sys3
            print(f"[TRUDI WARN] phase-aware layer3 failed: {_e3}", file=_sys3.stderr)

    # Evidence-aware prescription: the backend prescribes from a generic playbook
    # and can list tools that need an evidence type this case lacks — vol.* (a
    # memory image) or pcap-based net.* (a network capture) on a disk-only case.
    # Drop those from the work order so the agent isn't handed tools it cannot run
    # (and the work-order gates don't force it to disposition them). Conservative
    # + fail-open: only drops when the type is confidently absent.
    try:
        _mem, _pcap = _evidence_types(getattr(_flog, "_path", None))
        _d0 = assessment.get("directives") or {}
        _pt0 = list(_d0.get("priority_tools") or [])
        if _pt0 and (_mem is False or _pcap is False):
            _dropped, _kept = [], []
            for _t in _pt0:
                _tl = str(_t).lower().replace(".", "_")
                if _mem is False and (_tl.startswith("vol_") or _tl.startswith("volatility")
                                      or _tl.startswith("rekall")):
                    _dropped.append(_t); continue
                if _pcap is False and re.match(r"net_(tcpdump|ngrep|http_session|tcpxtract|pcap)", _tl):
                    _dropped.append(_t); continue
                _kept.append(_t)
            if _dropped:
                _d0["priority_tools"] = _kept
                assessment["directives"] = _d0
                assessment["prescription_filtered"] = _dropped
    except Exception:
        pass

    # Work-order completion on advance. A phase is left only when its work
    # order is done — a transition (push/pop) while the PRIOR dair_call's
    # priority_tools are neither run nor dispositioned is refused and the tools
    # re-issued. The unrun_priority_tools audit applied per-transition; Report
    # transitions are already governed by phase coverage + pre_report.
    if (server_override is None and assessment.get("transition_recommended")
            and str(assessment.get("stack_action")) in ("push", "pop")
            and str(assessment.get("next_phase") or "") != "Report"):
        try:
            from tools._gates.work_order import unrun_from_list, _display as _display6
            _entries6 = getattr(_flog, "_entries", None) or []
            _prior = [e for e in _entries6 if e.get("type") == "dair_call"]
            _prior_pt = ((_prior[-1].get("directives") or {}).get("priority_tools")) if _prior else []
            _outstanding = unrun_from_list(_entries6, _prior_pt)
            if _outstanding:
                server_override = {"kind": "work_order_incomplete",
                                   "detail": f"unrun prescribed tools: {', '.join(_outstanding)}",
                                   "model_next_phase": assessment.get("next_phase"),
                                   "model_stack_action": assessment.get("stack_action")}
                assessment["transition_recommended"] = False
                assessment["stack_action"] = "stay"
                _d6 = assessment.get("directives") or {}
                _cur = list(_d6.get("priority_tools") or [])
                _d6["priority_tools"] = _outstanding + [t for t in _cur
                                                        if _display6(t) not in _outstanding]
                assessment["directives"] = _d6
                assessment["transition_rationale"] = (
                    f"Server override: work order incomplete — {len(_outstanding)} tool(s) "
                    f"DAIR prescribed for this phase were never run or dispositioned "
                    f"({', '.join(_outstanding)}). A phase is entered to execute its work "
                    f"order, not to be passed through: run each, or settle it with "
                    f"misc.record_disposition(target_kind=\"tool\", reason=\"inapplicable\"|"
                    f"\"absent_from_evidence\"), before advancing."
                )
        except Exception as _e6:
            import sys as _sys6
            print(f"[TRUDI WARN] work-order advance gate failed: {_e6}", file=_sys6.stderr)

    tok_in  = backend_result.get("input_tokens", 0)
    tok_out = backend_result.get("output_tokens", 0)
    call_id = _log_dair(assessment, tok_in, tok_out, inputs=call_inputs,
                        input_call_ids=input_call_ids,
                        candidate_pivots=candidate_pivots,
                        backend_meta=backend_result.get("backend_meta"),
                        parse_path=parse_path, server_override=server_override,
                        observed_principals=[{k: v for k, v in it.items() if k != "norm"}
                                             for it in ok_principals] or None,
                        observed_hosts=ok_hosts or None,
                        case_question=case_question or "")

    result = {
        **assessment,
        "success": True,
        "server_override": server_override,
        "typed_input_errors": typed_input_errors,
        "input_tokens": tok_in,
        "output_tokens": tok_out,
        "_trudi_call_id": call_id,
    }
    if candidate_pivots:
        result["candidate_pivots"] = candidate_pivots
    return result
