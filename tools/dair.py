"""DAIR Director — Dynamic Approach to Incident Response phase tracking.

Runs as a parallel track alongside reason.*. Called after every tool batch to
assess which DAIR phase the investigation is in, whether to transition, and what
to focus on next. Maintains a recursive phase stack — any phase can transition
to any other when evidence demands it.

Active phases for TRUDI (read-only forensic tool):
  Triage        — confirm initial IOCs, challenge for hallucinations, produce plan
  Collect       — gather raw artifacts per plan (ez.*, vol.*, tsk.*, strings.*)
  Analyze       — reason about collected artifacts; hypothesize on suspicious findings
  Scan          — sweep for lateral movement and pivot hosts (yara.*, net.*, enrich.*)
  Report        — terminal; emit Improve & Response recommendations

Detection is the assumed trigger (investigation already started). Improve &
Response actions are report recommendations only — never directed tool calls.
The cycle loops: Scan finding a new pivot pushes a new Triage onto the stack.
"""
import os
import re
import json
from fastmcp import FastMCP
from core.paths import DAIR_TIMEOUT
from tools.reasoning import _parse_directives, _cap_lines

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


# ── Auto-push: Scan → Triage pivot detection ─────────────────────────────────
# When a Scan-phase tool_results_summary names a host (IP or hostname) that
# isn't already in case_context or any prior investigation_focus, force a
# stack_action="push" with next_phase="Triage". Engages the recursive
# investigation pattern automatically rather than relying on the model to
# decide. Override only fires when the model emitted stack_action="stay" — a
# model "push" is never downgraded.
#
# Two detection paths run by default and are case-agnostic:
#   1. IPv4 — every host has one; the regex is rock-solid.
#   2. UNC paths — \\HOSTNAME\share is unambiguously a host reference,
#      regardless of the case's hostname naming convention.
# A third optional path handles case-specific hostname patterns that don't
# surface via UNC (e.g. bare "<prefix>-NN" mentions in narrative text): the
# operator sets TRUDI_PIVOT_HOSTNAME_PREFIXES="<prefix1>,<prefix2>,..." in
# .env and the prefix-based regex is compiled lazily inside
# _extract_host_tokens so env-var changes take effect without a server restart.

# IPv4 address anywhere in the summary text.
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# UNC-path hostname extraction: captures the host portion of a \\HOST\share
# reference. Works for both IP and DNS-name forms; the IP form is filtered
# out downstream so it isn't double-counted.
_UNC_HOST_RE = re.compile(r"\\\\([A-Za-z0-9][\w.-]*)")


def _hostname_prefix_regex():
    """Compile the case-specific hostname regex from TRUDI_PIVOT_HOSTNAME_PREFIXES.

    Returns None if the env var is empty/unset (default case-agnostic mode —
    only IPv4 + UNC-path detection runs). Compiled lazily on each call so
    operators can adjust the env var between investigations without
    bouncing the MCP server, and so tests can monkeypatch it cleanly.
    """
    raw = os.environ.get("TRUDI_PIVOT_HOSTNAME_PREFIXES", "")
    prefixes = tuple(p.strip().lower() for p in raw.split(",") if p.strip())
    if not prefixes:
        return None
    return re.compile(
        rf"\b(?:{'|'.join(re.escape(p) for p in prefixes)})[-_]?\d+\b",
        re.IGNORECASE,
    )


# Tokens that look like hostnames but are forensic-jargon noise. Anything that
# matches the prefix-based regex but appears in this set is dropped before
# the new-host comparison. These words turn up in any Windows / DFIR case
# regardless of naming scheme:
#   - Forensic phase / tool jargon (scan, triage, system, registry, etc.)
#   - Common AV product names that frequently appear in event logs
#   - Networking and file-type tokens with digit suffixes that can match a
#     hostname-shaped regex (tcp4, http2, json5, etc.)
_PIVOT_STOP_WORDS = frozenset({
    "scan", "triage", "windows", "system", "report", "phase", "stage",
    "claude", "dair", "reason", "trudi", "mcp", "vol", "ez", "ntlm", "smb",
    "tcp", "udp", "dns", "http", "https", "rdp", "log", "evtx", "csv",
    "json", "xml", "mft", "pdf", "exe", "dll", "ps1", "bat", "vbs",
    "amcache", "shimcache", "prefetch", "registry",
    "mcafee", "windefend", "defender", "symantec", "crowdstrike", "sentinel",
})


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


def _extract_host_tokens(text: str) -> set[str]:
    """Return the set of host references (IPs + hostnames) appearing in `text`.

    Detection sources:
      1. IPv4 addresses — always.
      2. UNC-path hostnames — `\\HOST\share` patterns; case-agnostic and
         unambiguous.
      3. Case-specific hostname prefixes — only if
         TRUDI_PIVOT_HOSTNAME_PREFIXES is set in the environment.

    Hostnames are normalized to uppercase so the set comparison against
    `case_context` is case-insensitive and matches how agents typically
    write them in narrative text (BASE-RD-01).
    """
    if not text:
        return set()
    ips = set(_IPV4_RE.findall(text))
    hostnames: set[str] = set()

    # UNC-path host extraction. An IP in a UNC path is already counted via
    # _IPV4_RE — skip those so they aren't double-counted as a hostname.
    for h in _UNC_HOST_RE.findall(text):
        if _IPV4_RE.fullmatch(h):
            continue
        norm = h.upper().replace("_", "-")
        if norm.lower() in _PIVOT_STOP_WORDS:
            continue
        hostnames.add(norm)

    # Optional case-specific prefix-based detection. Lazy compile so changes
    # to TRUDI_PIVOT_HOSTNAME_PREFIXES take effect without a server restart.
    prefix_re = _hostname_prefix_regex()
    if prefix_re is not None:
        for h in prefix_re.findall(text):
            norm = h.upper().replace("_", "-")
            # Stop-word filter (e.g. SCAN3, WINDOWS-1).
            if norm.lower() in _PIVOT_STOP_WORDS:
                continue
            if norm.lower().split("-")[0] in _PIVOT_STOP_WORDS:
                continue
            hostnames.add(norm)

    return ips | hostnames


def _build_known_host_set(case_context: str) -> set[str]:
    """Union of all hosts referenced in case_context plus every
    investigation_focus from prior dair_call entries in the trace.

    The "known" set represents hosts the investigation has already touched —
    new pivots are anything mentioned in tool_results_summary that isn't here.
    """
    known: set[str] = set()
    known |= _extract_host_tokens(case_context or "")
    try:
        from core.execution_log import log as _elog
        for e in _elog._entries:
            if e.get("type") != "dair_call":
                continue
            focus = e.get("investigation_focus") or ""
            known |= _extract_host_tokens(focus)
    except Exception as _read_err:
        # Fail-open: if we can't read the trace, treat known set as
        # case_context only. Worst case is a noisier push. Print so the
        # operator sees the cause when investigating pivot-detection bugs.
        import sys as _sys
        print(f"[TRUDI WARN] dair host-context read failed: {_read_err!r}",
              file=_sys.stderr)
    return known


def _drain_queued_pivots(case_context: str) -> list[str]:
    """Return the queued pivot hosts that have never been pivoted to.

    A host enters the queue when a prior dair_call's auto-push captured it as
    overflow (`pending_pivots`). It leaves implicitly the first time a Triage
    `investigation_focus` mentions it (captured by _build_known_host_set).
    """
    queued: set[str] = set()
    try:
        from core.execution_log import log as _elog
        for e in _elog._entries:
            if e.get("type") != "dair_call":
                continue
            for h in e.get("pending_pivots") or []:
                queued.add(str(h).upper())
    except Exception as _read_err:
        import sys as _sys
        print(f"[TRUDI WARN] dair queue read failed: {_read_err!r}",
              file=_sys.stderr)
        return []
    known = {h.upper() for h in _build_known_host_set(case_context)}
    return sorted(queued - known)


# Pivot-detection allow-list. Hosts surfaced from these phases are eligible
# for auto-push or queueing; Triage is excluded because Triage is *about* the
# host already under investigation.
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


def _ask_openai_compat(system: str, user: str) -> dict:
    import httpx
    _empty = {"success": False, "raw": "", "input_tokens": 0, "output_tokens": 0}

    if not DAIR_URL:
        return {**_empty, "error": "DAIR_URL not set for openai-compat backend"}

    model = DAIR_MODEL or _DEFAULT_COMPAT_MODEL
    headers = {"Authorization": f"Bearer {DAIR_API_KEY}"} if DAIR_API_KEY else {}
    try:
        from core.execution_log import log as _elog
        _elog.record_call_initiated("dair_assess", "openai-compat", {"model": model, "url": DAIR_URL})
    except Exception as _e:
        import sys; print(f"[TRUDI WARN] record_call_initiated failed: {_e}", file=sys.stderr)
    try:
        resp = httpx.post(
            f"{DAIR_URL.rstrip('/')}/v1/chat/completions",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "max_tokens": 2048,
            },
            headers=headers,
            timeout=DAIR_TIMEOUT,
        )
        resp.raise_for_status()
        body = resp.json()
        choice = body["choices"][0]["message"]
        raw = choice.get("content") or choice.get("reasoning") or ""
        if not raw:
            return {**_empty, "error": "Model returned empty response"}
        usage = body.get("usage", {})
        return {
            "success": True,
            "raw": raw,
            "input_tokens": usage.get("prompt_tokens", 0),
            "output_tokens": usage.get("completion_tokens", 0),
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


def _ask(system: str, user: str, max_tokens: int = 2048) -> dict:
    backend = _active_backend()
    if backend == "claude":
        return _ask_claude(system, user, max_tokens)
    return _ask_openai_compat(system, user)


def _log_dair(assessment: dict, input_tokens: int, output_tokens: int,
              inputs: dict | None = None,
              input_call_ids: list[int] | None = None) -> int:
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
examined. A genuinely ambiguous artifact may push back to Triage before proceeding. \
LATERAL-MOVEMENT PIVOTING: if Analyze surfaces a reference to a host other than \
the one under investigation — remote logon (4624 type 3/10), SMB session, \
mapped drive, inbound RDP, \\\\HOST\\share path in a command line or registry \
value, named pipe to a remote endpoint — that host is a pivot. Do not wait for \
Scan; the server-enforced auto-push will fire on the new host token and push a \
fresh Triage onto the stack. Continue the current Analyze work order in parallel \
where possible; the pivot Triage will be drained from the persistent queue. \
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
  Scan     — exhaustive cross-host IOC sweep and propagation check: \
yara.scan_directory across all collected disk/memory, net.tcpdump_extract_dns \
for exfil signatures, enrich.vt_lookup_hash and enrich.abuseipdb_check for \
hashes/IPs the agent had no earlier reason to look up. This phase is the \
safety net for IOCs the per-host Analyze passes did not surface — NOT the \
gatekeeper of pivoting. Pivot hosts are now discovered in any phase that \
surfaces a new host token (Collect, Analyze, Scan); the server-enforced \
auto-push fires from each and persists overflow pivots to the pending_pivots \
queue. Advance to Report when the cross-host sweep is exhausted and the \
pivot queue has drained.
  Report   — terminal phase. BEFORE reason.synthesize, call BOTH \
coverage.coverage_report (TTP coverage checklist) AND attribution.attribute_actors \
(adversary attribution from observed T-IDs) so the final synthesis input has the \
complete picture. When findings span multiple hosts, ALSO call \
correlate.process_to_file and correlate.network_to_process (with no PID/IP/path \
filter, to get the full cross-host join) so the synthesis input has real \
cross-host joins rather than isolated per-host slices. Then synthesise findings \
into a timeline. Emit Improve & Response recommendations for the IR team in \
recommended_actions. Never direct containment or eradication tool calls.

PHASE STACK:
The phase_stack is the recursive history of the investigation. Newest entry is last. \
Use it to understand depth and context. A stack ending in Triage inside a Scan means \
a new pivot host was found and a full investigation cycle is running for that host.
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
    "next_hypothesis_triggers": []
  }
}

verification_challenges in DAIR_ASSESSMENT must mirror VERIFICATION_CHALLENGES block \
exactly when in Triage phase. recommended_actions is populated ONLY when \
transitioning to Report — list specific Improve & Response actions for the IR team. \
Tool names in directives must use TRUDI MCP format: namespace.tool \
(e.g. strings.stat_file, tsk.fls, vol.pslist, vol.netscan, ez.recmd_hive, \
ez.mftecmd, ez.evtxecmd, yara.scan_directory, net.tcpdump_extract_dns, \
enrich.vt_lookup_hash, enrich.vt_lookup_ip). \
Remember: priority_tools is the investigator's complete work order for this batch. \
Make it specific and executable — every entry will be run before you see results.\
"""


# ── MCP tool ──────────────────────────────────────────────────────────────────

@mcp.tool()
def dair_assess(
    tool_results_summary: str,
    phase_stack: str = "[]",
    case_context: str = "",
    input_call_ids: list[int] | None = None,
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

    Cycle: Triage → Collect → Analyze → Scan → (loop or Report)
    Loop: when stack_action is "push" and next_phase is "Triage", a new pivot host
    was discovered during Scan. Call reason.plan for the new host before proceeding.

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
        "user_message": user,
    }

    # Persistent pivot-queue drain. If a prior dair_call queued overflow
    # pivots (via the auto-push below) and none of them have been pivoted to
    # yet, synthesize a Triage push for the next queued host and skip the
    # model call entirely. This guarantees deterministic drain across turns
    # and saves a model round-trip per queued pivot. Triage entries do NOT
    # drain — Triage is the host investigation itself, not a transit phase.
    if current != "Triage":
        queued = _drain_queued_pivots(context)
        if queued:
            first_pivot = queued[0]
            remaining = queued[1:]
            from tools.reasoning import _EMPTY_DIRECTIVES
            drain_assessment = {
                **_EMPTY_ASSESSMENT,
                "current_phase": current,
                "phase_rationale": (
                    f"Pivot queue non-empty ({len(queued)} host(s) pending) — "
                    f"draining {first_pivot} before continuing {current}."
                ),
                "transition_recommended": True,
                "next_phase": "Triage",
                "transition_rationale": (
                    f"Auto-drain: queued pivot host {first_pivot} from "
                    f"prior pending_pivots (server-enforced, no model call)."
                ),
                "stack_action": "push",
                "investigation_focus": (
                    f"Triage pivot host {first_pivot} (drained from queue)"
                ),
                "directives": {
                    **_EMPTY_DIRECTIVES,
                    "priority_tools": ["reason.hypothesize", "reason.plan"],
                },
            }
            if remaining:
                drain_assessment["pending_pivots"] = remaining
            call_id = _log_dair(drain_assessment, 0, 0,
                                inputs=call_inputs,
                                input_call_ids=input_call_ids)
            return {
                **drain_assessment,
                "success": True,
                "input_tokens": 0,
                "output_tokens": 0,
                "_trudi_call_id": call_id,
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
        _log_dair(_EMPTY_ASSESSMENT | {"directives": _parse_directives("")}, 0, 0,
                  inputs=call_inputs, input_call_ids=input_call_ids)
        result["_trudi_call_id"] = 0
        return result

    raw = backend_result["raw"]
    challenges = _parse_challenges(raw)
    assessment = _parse_dair_assessment(raw)

    # challenges from dedicated block take precedence over those embedded in assessment
    if challenges:
        assessment["verification_challenges"] = challenges

    # Cross-phase pivot auto-push. Any phase that surfaces a host token not
    # in case_context or any prior investigation_focus treats that host as a
    # new pivot. Two paths:
    #   (a) model emitted "stay" — force a push to Triage for the first new
    #       host; overflow goes into pending_pivots for the drain preamble
    #       to process on subsequent calls.
    #   (b) model emitted "push" to a non-Triage phase (advancing the
    #       per-host pipeline, e.g. Analyze → Scan) — keep the model's push
    #       intact (NEVER downgrade) but capture overflow new hosts into
    #       pending_pivots so the queue still drains.
    # Triage is excluded from both paths: Triage is *about* the host already
    # under investigation, so its own focus shouldn't trigger a self-pivot.
    if current in _PIVOT_ELIGIBLE_PHASES:
        summary_hosts = _extract_host_tokens(summary)
        known_hosts = _build_known_host_set(context)
        new_pivots = sorted(summary_hosts - known_hosts)
        if new_pivots:
            action = assessment.get("stack_action")
            next_phase = assessment.get("next_phase", "")
            if action == "stay":
                first_pivot = new_pivots[0]
                remaining = new_pivots[1:]
                assessment["transition_recommended"] = True
                assessment["next_phase"] = "Triage"
                assessment["stack_action"] = "push"
                note = (
                    f"Auto-pushed: {current} surfaced new host(s) "
                    f"{', '.join(new_pivots)} not in case_context or prior "
                    f"investigation_focus (server-enforced)."
                )
                prior_rationale = assessment.get("transition_rationale") or ""
                assessment["transition_rationale"] = (
                    f"{prior_rationale} {note}".strip()
                    if prior_rationale else note
                )
                if remaining:
                    assessment["pending_pivots"] = remaining
                if not assessment.get("investigation_focus"):
                    assessment["investigation_focus"] = (
                        f"Triage pivot host {first_pivot} surfaced during {current}"
                    )
            elif action == "push" and next_phase != "Triage":
                # Model is advancing the per-host pipeline (e.g. Collect →
                # Analyze). Don't override — just enqueue the pivots so the
                # drain preamble surfaces them after the model-directed push
                # completes.
                existing = list(assessment.get("pending_pivots") or [])
                for h in new_pivots:
                    if h not in existing:
                        existing.append(h)
                assessment["pending_pivots"] = existing
                enq_note = (
                    f"Enqueued pivot host(s) {', '.join(new_pivots)} surfaced "
                    f"during {current}; will drain after current push completes "
                    f"(server-enforced)."
                )
                prior_rationale = assessment.get("transition_rationale") or ""
                assessment["transition_rationale"] = (
                    f"{prior_rationale} {enq_note}".strip()
                    if prior_rationale else enq_note
                )

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
        assessment["directives"] = {**_EMPTY_DIRECTIVES, **embedded}
    else:
        assessment["directives"] = _parse_directives(raw)

    tok_in  = backend_result.get("input_tokens", 0)
    tok_out = backend_result.get("output_tokens", 0)
    call_id = _log_dair(assessment, tok_in, tok_out, inputs=call_inputs,
                        input_call_ids=input_call_ids)

    return {
        **assessment,
        "success": True,
        "input_tokens": tok_in,
        "output_tokens": tok_out,
        "_trudi_call_id": call_id,
    }
