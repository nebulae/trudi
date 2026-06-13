"""Adversarial reasoning — swappable backend (Claude API or any OpenAI-compatible endpoint)."""
import os
import re
import json
from fastmcp import FastMCP
from core.paths import REASON_TIMEOUT
from core.timeout import with_tool_timeout
from tools.tool_capabilities import (
    annotate_directives_with_manifest,
    format_tool_manifest_for_prompt,
)

# Watchdog budget: HTTP timeout (REASON_TIMEOUT, 90s default) handles a stalled
# local LLM; the watchdog gives a 30s buffer for parsing, trace-logging, and
# directive extraction after the HTTP response returns. Without this, a hang in
# the post-HTTP code path looks like a silent stall to the agent.
_REASON_WATCHDOG = REASON_TIMEOUT + 30

mcp = FastMCP("reasoning")

# ── Backend configuration ────────────────────────────────────────────────────
# Set REASON_BACKEND explicitly, or let auto-detection pick based on which
# keys are present.  Both sets of Foundation-Sec vars are kept as aliases
# so existing .env files keep working without changes.

REASON_BACKEND   = os.environ.get("REASON_BACKEND") or ""
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY") or ""

# openai-compat vars — FOUNDATION_SEC_URL / HF_TOKEN are deprecated aliases
REASON_URL       = (os.environ.get("REASON_URL")
                    or os.environ.get("FOUNDATION_SEC_URL") or "")
REASON_API_KEY   = (os.environ.get("REASON_API_KEY")
                    or os.environ.get("HF_TOKEN") or "")
REASON_MODEL     = os.environ.get("REASON_MODEL") or ""

# Default models per backend
_DEFAULT_CLAUDE_MODEL      = "claude-haiku-4-5-20251001"
_DEFAULT_COMPAT_MODEL      = "fdtn-ai/Foundation-Sec-8B-Reasoning"

# Per-call max_tokens budgets. Doubled from the original 1024/2048 defaults
# after observing reason.plan truncated outputs (conclusion ended mid-sentence,
# directives empty). Override via env if a different backend or task profile
# needs a different envelope.
MAX_TOKENS_PLAN           = int(os.environ.get("TRUDI_REASON_MAX_TOKENS_PLAN")           or "4096")
MAX_TOKENS_HYPOTHESIZE    = int(os.environ.get("TRUDI_REASON_MAX_TOKENS_HYPOTHESIZE")    or "2048")
MAX_TOKENS_EVALUATE       = int(os.environ.get("TRUDI_REASON_MAX_TOKENS_EVALUATE")       or "4096")
MAX_TOKENS_CITE_CHECK     = int(os.environ.get("TRUDI_REASON_MAX_TOKENS_CITE_CHECK")     or "2048")
MAX_TOKENS_CONFIDENCE     = int(os.environ.get("TRUDI_REASON_MAX_TOKENS_CONFIDENCE")     or "2048")
MAX_TOKENS_AUDIT_FINDINGS = int(os.environ.get("TRUDI_REASON_MAX_TOKENS_AUDIT_FINDINGS") or "4096")
MAX_TOKENS_SYNTHESIZE     = int(os.environ.get("TRUDI_REASON_MAX_TOKENS_SYNTHESIZE")     or "4096")


def _active_backend() -> str:
    """Resolve which backend to use, with auto-detection from available keys."""
    if REASON_BACKEND:
        return REASON_BACKEND
    if ANTHROPIC_API_KEY:
        return "claude"
    if REASON_URL:
        return "openai-compat"
    return "claude"  # will fail gracefully with a clear error if no key


# ── Shared constants ─────────────────────────────────────────────────────────

_EMPTY_DIRECTIVES: dict = {
    "priority_tools": [],
    "skip_tools": [],
    "focus_pids": [],
    "focus_paths": [],
    "max_depth": "",
    "next_hypothesis_triggers": [],
    # Exploratory allowance: the number of read-only "curiosity_probe" calls the
    # agent may run of its OWN choosing this batch, on top of priority_tools.
    # Granted by dair_assess, refreshed each call. 0 ⇒ today's strict
    # directive-only behavior. Enforced by tools/_gates/curiosity_budget.py.
    "curiosity_budget": 0,
}

_DIRECTIVES_INSTRUCTION = """\

Write your full analysis first, then end your response with the DIRECTIVES block. \
No markdown bold, no code fences, no // comments, plain text only:
DIRECTIVES:
{
  "priority_tools": ["vol.psscan", "ez.amcacheparser"],
  "skip_tools": [],
  "focus_pids": [],
  "focus_paths": [],
  "max_depth": "targeted",
  "next_hypothesis_triggers": []
}
Replace the example values with your actual recommendations. \
Tool names must use TRUDI MCP format: namespace.tool and must come from the \
Tool Capability Manifest. \
Do not invent tool names outside this list.

""" + format_tool_manifest_for_prompt(max_tools_per_capability=6)


_EVIDENCE_AUDIT_INSTRUCTION = """\

Write your full analysis first. Then include the EVIDENCE_AUDIT block, \
followed by the DIRECTIVES block at the very end. \
List each major claim in the finding in EVIDENCE_AUDIT:
EVIDENCE_AUDIT:
[
  {
    "claim": "brief statement of the claim being audited",
    "tool": "vol.psscan / ez.evtxecmd / yara / etc.",
    "command": "exact MCP tool call or command used",
    "raw_output_excerpt": "verbatim snippet from tool output",
    "artifact_path": "file path or memory offset",
    "timestamp_source": "how the timestamp was established",
    "proof_rationale": "why this output proves the claim",
    "benign_alternatives": "alternate non-attacker explanations"
  }
]
Write NOT PROVIDED for any field not supplied in the supporting evidence.
Claims with 2+ NOT PROVIDED fields are hallucination candidates."""


# ── Text utilities ────────────────────────────────────────────────────────────

def _strip_block(text: str, marker: str) -> str:
    """Remove a named block marker and everything after it."""
    if not text:
        return text
    return re.sub(
        rf"\*{{0,2}}{re.escape(marker)}\*{{0,2}}\s*:?\*{{0,2}}.*",
        "",
        text,
        flags=re.DOTALL | re.IGNORECASE,
    ).rstrip()


def _strip_directives(text: str) -> str:
    return _strip_block(text, "DIRECTIVES")


def _strip_evidence_audit(text: str) -> str:
    return _strip_block(text, "EVIDENCE_AUDIT")


def _parse_evidence_audit(text: str) -> list:
    """Extract the EVIDENCE_AUDIT JSON array from model output. Returns [] on failure."""
    if not text:
        return []
    match = re.search(
        r"EVIDENCE_AUDIT:\s*(\[.*?\])\s*(?:DIRECTIVES:|$)",
        text,
        re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return []
    raw = re.sub(r"\s*//[^\n]*", "", match.group(1))
    try:
        result = json.loads(raw)
        return result if isinstance(result, list) else []
    except (json.JSONDecodeError, ValueError):
        return []


def _parse_directives(text: str) -> dict:
    """Extract the DIRECTIVES JSON block from model output.

    Returns _EMPTY_DIRECTIVES template on any parse failure so callers always
    have the expected keys and can check priority_tools without KeyError.
    On successful parse, missing keys are filled from the template.
    """
    if not text:
        return annotate_directives_with_manifest(_EMPTY_DIRECTIVES.copy())
    match = re.search(
        r"\*{0,2}DIRECTIVES\*{0,2}\s*:?\*{0,2}\s*(?:```json\s*)?(\{.*?\})\s*(?:```)?",
        text,
        re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return annotate_directives_with_manifest(_EMPTY_DIRECTIVES.copy())
    raw = match.group(1)
    raw = re.sub(r"\s*//[^\n]*", "", raw)  # strip // comments
    try:
        return annotate_directives_with_manifest({**_EMPTY_DIRECTIVES, **json.loads(raw)})
    except (json.JSONDecodeError, ValueError):
        return annotate_directives_with_manifest(_EMPTY_DIRECTIVES.copy())


def _cap_lines(text: str, max_lines: int) -> str:
    """Trim text to max_lines, appending a note if trimmed."""
    lines = text.splitlines(keepends=True)
    if len(lines) <= max_lines:
        return text
    omitted = len(lines) - max_lines
    return "".join(lines[:max_lines]) + f"\n[... {omitted} lines omitted for brevity]\n"


# ── Backend implementations ───────────────────────────────────────────────────

def _ask_claude(system: str, user: str, max_tokens: int, _tool_name: str,
                hypothesis_id: str = "",
                input_call_ids: list[int] | None = None) -> dict:
    """Call the Anthropic Claude API with prompt caching on the system prompt."""
    import anthropic
    _inputs = {
        "user_message": user,
        "max_tokens": max_tokens,
        "system_prompt_kind": _tool_name,
    }
    _empty = {"success": False, "conclusion": "", "directives": {},
              "input_tokens": 0, "output_tokens": 0, "inputs": _inputs}
    if hypothesis_id:
        _empty["hypothesis_id"] = hypothesis_id

    if not ANTHROPIC_API_KEY:
        result = {**_empty, "error": "ANTHROPIC_API_KEY not set — add it to .env"}
        _log_reason(_tool_name, result, input_call_ids=input_call_ids)
        return result

    model = REASON_MODEL or _DEFAULT_CLAUDE_MODEL
    try:
        from core.execution_log import log as _elog
        _elog.record_call_initiated(_tool_name, "claude", {"model": model},
                                    input_call_ids=input_call_ids)
    except Exception as _e:
        import sys; print(f"[TRUDI WARN] record_call_initiated failed: {_e}", file=sys.stderr)
    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY, timeout=REASON_TIMEOUT)
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
        evidence_audit = _parse_evidence_audit(raw)
        directives = _parse_directives(raw)
        conclusion = _strip_evidence_audit(_strip_directives(raw))
        result = {
            "success": True,
            "conclusion": conclusion,
            "directives": directives,
            "evidence_audit": evidence_audit,
            "input_tokens": getattr(resp.usage, "input_tokens", 0),
            "output_tokens": getattr(resp.usage, "output_tokens", 0),
            "inputs": _inputs,
        }
        if hypothesis_id:
            result["hypothesis_id"] = hypothesis_id
        _log_reason(_tool_name, result, input_call_ids=input_call_ids)
        return result
    except Exception as e:
        try:
            from core.execution_log import log as _elog
            _elog.record_call_abandoned(_tool_name, str(e))
        except Exception as _log_err:
            # Best-effort — we're already in the failure path. Surface to
            # stderr so the double-fault isn't completely silent. Not
            # routed through record_system_error to avoid recursion if the
            # trace itself is the cause.
            import sys as _sys
            print(f"[TRUDI WARN] reason record_call_abandoned failed during "
                  f"{_tool_name} error: {_log_err!r}", file=_sys.stderr)
        result = {**_empty, "error": str(e)}
        _log_reason(_tool_name, result, input_call_ids=input_call_ids)
        return result


def _ask_openai_compat(system: str, user: str, max_tokens: int, _tool_name: str,
                       hypothesis_id: str = "",
                       input_call_ids: list[int] | None = None) -> dict:
    """Call any OpenAI-compatible endpoint (OpenAI, Foundation-Sec vLLM, Ollama, etc.)."""
    import httpx
    _inputs = {
        "user_message": user,
        "max_tokens": max_tokens,
        "system_prompt_kind": _tool_name,
    }
    _empty = {"success": False, "conclusion": "", "directives": {},
              "input_tokens": 0, "output_tokens": 0, "inputs": _inputs}
    if hypothesis_id:
        _empty["hypothesis_id"] = hypothesis_id

    if not REASON_URL:
        result = {**_empty, "error": "REASON_URL not set for openai-compat backend"}
        _log_reason(_tool_name, result, input_call_ids=input_call_ids)
        return result

    model = REASON_MODEL or _DEFAULT_COMPAT_MODEL
    headers = {"Authorization": f"Bearer {REASON_API_KEY}"} if REASON_API_KEY else {}
    try:
        from core.execution_log import log as _elog
        _elog.record_call_initiated(_tool_name, "openai-compat",
                                    {"model": model, "url": REASON_URL},
                                    input_call_ids=input_call_ids)
    except Exception as _e:
        import sys; print(f"[TRUDI WARN] record_call_initiated failed: {_e}", file=sys.stderr)
    try:
        resp = httpx.post(
            f"{REASON_URL.rstrip('/')}/v1/chat/completions",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "max_tokens": max_tokens,
            },
            headers=headers,
            timeout=REASON_TIMEOUT,
        )
        resp.raise_for_status()
        body = resp.json()
        choice = body["choices"][0]["message"]
        raw = choice.get("content") or choice.get("reasoning") or ""
        if not raw:
            result = {**_empty, "error": "Model returned empty response"}
            _log_reason(_tool_name, result, input_call_ids=input_call_ids)
            return result
        evidence_audit = _parse_evidence_audit(raw)
        directives = _parse_directives(raw)
        conclusion = _strip_evidence_audit(_strip_directives(raw))
        usage = body.get("usage", {})
        result = {
            "success": True,
            "conclusion": conclusion,
            "directives": directives,
            "evidence_audit": evidence_audit,
            "input_tokens": usage.get("prompt_tokens", 0),
            "output_tokens": usage.get("completion_tokens", 0),
            "inputs": _inputs,
        }
        if hypothesis_id:
            result["hypothesis_id"] = hypothesis_id
        _log_reason(_tool_name, result, input_call_ids=input_call_ids)
        return result
    except Exception as e:
        try:
            from core.execution_log import log as _elog
            _elog.record_call_abandoned(_tool_name, str(e))
        except Exception as _log_err:
            # Best-effort — we're already in the failure path. Surface to
            # stderr so the double-fault isn't completely silent. Not
            # routed through record_system_error to avoid recursion if the
            # trace itself is the cause.
            import sys as _sys
            print(f"[TRUDI WARN] reason record_call_abandoned failed during "
                  f"{_tool_name} error: {_log_err!r}", file=_sys.stderr)
        result = {**_empty, "error": str(e)}
        _log_reason(_tool_name, result, input_call_ids=input_call_ids)
        return result


def _ask(system: str, user: str, max_tokens: int = 2048, _tool_name: str = "",
         hypothesis_id: str = "",
         input_call_ids: list[int] | None = None) -> dict:
    """Dispatch to the active reasoning backend. `input_call_ids` is propagated
    through to the eventual record_reason_call so the reason entry carries its
    agent-declared upstream lineage as a foreign key."""
    backend = _active_backend()
    if backend == "claude":
        return _ask_claude(system, user, max_tokens, _tool_name, hypothesis_id,
                           input_call_ids=input_call_ids)
    return _ask_openai_compat(system, user, max_tokens, _tool_name, hypothesis_id,
                              input_call_ids=input_call_ids)


def _log_reason(tool_name: str, result: dict,
                input_call_ids: list[int] | None = None) -> None:
    try:
        from core.execution_log import log
        cid = log.record_reason_call(
            tool=tool_name,
            success=result.get("success", False),
            conclusion=result.get("conclusion", ""),
            directives=result.get("directives", {}),
            evidence_audit=result.get("evidence_audit"),
            input_tokens=result.get("input_tokens", 0),
            output_tokens=result.get("output_tokens", 0),
            hypothesis_id=result.get("hypothesis_id", ""),
            inputs=result.get("inputs"),
            input_call_ids=input_call_ids,
        )
        if cid:
            result["_trudi_call_id"] = cid
    except Exception as e:
        import sys
        print(f"[TRUDI WARN] _log_reason failed for {tool_name}: {e}", file=sys.stderr)


def _next_hypothesis_id() -> str:
    """Generate a stable, sequential hypothesis_id like H0001.
    Used to build the hypothesis→finding lineage rendered in trace.md."""
    try:
        from core.execution_log import log
        existing = sum(
            1 for e in log._entries
            if e.get("type") == "reason_call" and e.get("hypothesis_id")
        )
        return f"H{existing + 1:04d}"
    except Exception:
        return "H0001"


# ── System prompts ────────────────────────────────────────────────────────────

_PLAN_SYS = (
    "You are a senior DFIR analyst receiving a new case. Given the case description "
    "and available evidence, produce a prioritized investigation plan:\n"
    "1. Most likely threat scenarios based on the evidence profile\n"
    "2. Highest-yield artifacts to examine first and why\n"
    "3. Specific TTPs to hunt for given the scenario\n"
    "4. Recommended tool sequence (memory → disk → network → enrichment or adjusted)\n"
    "5. Red flags that would change the priority order mid-investigation\n\n"
    "Be specific and opinionated. The investigator will follow this plan.\n"
    "The DIRECTIVES block is the primary output — populate priority_tools with the "
    "first 3-5 concrete tool calls the investigator should run, in order.\n\n"
    "EXHAUSTIVE COLLECTION: for each artifact category in the plan, the tool sequence "
    "must collect ALL instances, not just the first. Explicitly name: all registry hive "
    "variants needed (SOFTWARE, SYSTEM, SAM, NTUSER.DAT per user profile), all event "
    "log channels relevant to the TTP, all HTTP session types (Cookie headers, URL auth "
    "params: login=, email=, user=, gausr=, Y=, T=), all browser profiles present. "
    "If the case description includes a suspect list (class roster, employee directory, "
    "user accounts), include a cross-reference step as a named plan item — it is "
    "mandatory, not optional. The plan is incomplete if it names an identity-bearing "
    "artifact category without specifying the full collection sequence for that category."
    + _DIRECTIVES_INSTRUCTION
)

_HYPOTHESIZE_SYS = (
    "You are a senior DFIR analyst reviewing a colleague's live investigation. "
    "Given a forensic observation, generate ranked alternative hypotheses — both "
    "malicious and benign. Be adversarial: challenge the obvious interpretation. "
    "For each hypothesis state: likelihood (high/medium/low), supporting artifacts, "
    "and what evidence would confirm or rule it out.\n"
    "Keep your response concise and structured.\n"
    "The DIRECTIVES block is the primary output — populate priority_tools with the "
    "discriminators that resolve the TOP TWO competing hypotheses: the artifacts "
    "that decide WHICH hypothesis is true (e.g. logon type/source, USB serials "
    "across profiles, registry account bindings like OneDrive), not just tools that "
    "support the leading one. Populate next_hypothesis_triggers with conditions "
    "that should prompt re-evaluation.\n"
    "IMPORTANT: priority_tools MUST be non-empty if your conclusion names specific "
    "search patterns, artifact types, or investigative steps. Convert every concrete "
    "recommendation in your conclusion text into a priority_tools entry. Examples: "
    "if you write 'search for the suspect username in webmail traffic', add "
    "net.ngrep_search(pattern='<username>'); if you write 'check webmail cookies', "
    "add net.ngrep_search(pattern='Cookie:') and net.tcpdump_extract_http. "
    "An empty priority_tools alongside a conclusion that contains investigative "
    "recommendations is invalid — the structured directive must reflect the text."
    + _DIRECTIVES_INSTRUCTION
)

# Absence-seeded mode. The presence-mode prompt above reasons over what was
# already surfaced; this one reasons over what is MISSING. It is the structural
# counterweight to single-actor lock-in and shallow coverage: it generates leads
# about evidence that has NOT yet been looked at, which is where less-obvious
# identity / attribution / exfil / second-principal evidence lives.
_HYPOTHESIZE_ABSENCE_SYS = (
    "You are a senior DFIR analyst doing a DIFFERENTIAL coverage review of a "
    "live investigation. You are given the case question, the part of it still "
    "UNRESOLVED, and the list of artifact categories ALREADY examined. Your job "
    "is NOT to re-explain what was found — it is to name the high-value artifact "
    "categories that have NOT yet been touched and could carry decisive evidence "
    "for the unresolved question, especially:\n"
    "  - IDENTITY / ATTRIBUTION (a second SID's profile, cookies, cert CNs, "
    "comms-store correspondents, USB serials across profiles)\n"
    "  - A SECOND PRINCIPAL (a newly-created or unseen account, a logon from an "
    "unexpected source/type, a controller binding not yet established)\n"
    "  - AN ALTERNATE EXFIL CHANNEL ranked weaker-evidenced but unchecked "
    "(removable-media LNK/MountedDevices, FTP/transfer logs, cloud-client DB, "
    "mail attachment, web upload) — a transfer artifact, not mere staging\n"
    "  - INGRESS / INITIAL ACCESS overlooked by an egress-only lens "
    "(setupapi.dev.log HID/composite / BadUSB when removable media is in evidence)\n"
    "For each gap, state the one finding it would most plausibly produce and rank "
    "by EXPECTED INFORMATION GAIN for the unresolved question — not by ease.\n"
    "Do not propose categories already in the examined list. If a category was "
    "examined but only sampled (first instance only), it IS a valid gap — say so.\n"
    "The DIRECTIVES block is the primary output — populate priority_tools with one "
    "concrete TRUDI MCP call per gap, highest-information-gain first. These become "
    "the investigator's curiosity probes; keep the list to the top 3-5. Populate "
    "next_hypothesis_triggers with the result conditions that would open a new line."
    + _DIRECTIVES_INSTRUCTION
)

_EVALUATE_SYS = (
    "You are a DFIR peer reviewer with two roles: adversarial challenger AND "
    "technical fact-checker.\n\n"
    "For the finding presented, work through ALL of the following:\n"
    "1. EVIDENCE SUPPORT — what raw tool output directly supports it? "
    "Name the specific tool, output field, and value.\n"
    "2. CONTRADICTING EVIDENCE — what contradicts or weakens it?\n"
    "3. ALTERNATIVE EXPLANATIONS — benign or non-attacker interpretations "
    "of the same artifacts.\n"
    "4. HALLUCINATION CHECK — flag any claim stated as fact but not derivable "
    "from the cited evidence: invented specificity (precise numbers/offsets "
    "without a cited source), fabricated mechanism (e.g. 'VAD tag X proves "
    "API Y was used' without a reference), or conclusions that require "
    "evidence not mentioned in the supporting evidence field.\n"
    "5. FACT-CHECK — verify technical accuracy:\n"
    "   - YARA match alone is NEVER sufficient to confirm a tool, technique, "
    "or actor — it is a lead requiring corroboration.\n"
    "   - Null process cmdline has multiple benign explanations; never "
    "characterize as intentional wiping without supporting evidence.\n"
    "   - ATT&CK technique IDs must exist in the MITRE ATT&CK matrix and "
    "correctly describe the behaviour being claimed.\n"
    "   - Port numbers, VAD tags, and memory structure claims must match "
    "established forensic facts — flag if unverifiable.\n"
    "   - NEGATIVE FINDING SCRUTINY: if the finding states that something was NOT "
    "found (no persistence, no injection, identity unknown, no C2 traffic), verify "
    "that the absence claim was reached by exhaustive collection — not by a single "
    "tool pass that returned empty. A single ngrep returning no results does not mean "
    "the artifact is absent; a single vol.malfind pass does not clear all processes. "
    "Flag CHALLENGED if the negative claim is based on incomplete collection coverage.\n"
    "6. ADDITIONAL INVESTIGATION — what specific tool run would upgrade this "
    "finding from its current confidence tier?\n"
    "7. VERDICT: SUPPORTED / CHALLENGED / UNCERTAIN — one-line rationale.\n\n"
    "Be blunt. Overclaimed findings damage court cases. Flag any finding "
    "that upgrades an indicator to a confirmed fact without direct evidence."
    + _EVIDENCE_AUDIT_INSTRUCTION
    + _DIRECTIVES_INSTRUCTION
)

_SYNTHESIZE_SYS = (
    "You are a DFIR lead analyst doing a final logic and confidence check before "
    "a report is written. Apply this evidence tier standard to every finding:\n\n"
    "  CONFIRMED   → physical artifact (file/key/log) + corroborating context\n"
    "  LIKELY      → live memory structure, active connection, or registry key "
    "with supporting context\n"
    "  SUSPECTED   → YARA match, behavioral indicator, or single corroborating "
    "point — never write CONFIRMED for a SUSPECTED-tier finding\n"
    "  UNCONFIRMED → inference or pattern-match without a direct artifact\n\n"
    "Identify:\n"
    "1. LOGICAL GAPS — steps in the attack chain that aren't evidenced\n"
    "2. CONTRADICTIONS — findings that conflict with each other\n"
    "3. TIER VIOLATIONS — findings written as CONFIRMED/HIGH where the evidence "
    "is SUSPECTED or UNCONFIRMED tier; list each with the correct tier\n"
    "4. TIER CONTRADICTIONS — any two findings that make the same mechanistic "
    "claim (same attacker action, same host, same credential) at different "
    "confidence tiers; list each pair as TIER_CONTRADICTION with the correct tier\n"
    "5. OVERCLAIMED MECHANISMS — technical explanations that aren't supported "
    "by cited evidence (e.g. YARA hit stated as 'confirmed execution')\n"
    "6. MISSING INVESTIGATION — what should have been checked but wasn't, including:\n"
    "   - EVIDENCE EXHAUSTION: for each artifact category named in findings, was the "
    "full category collected (all hives, all log channels, all HTTP cookie types, all "
    "memory regions) or only sampled? Flag as BLOCKER if a conclusion of 'identity "
    "unknown' or 'no evidence found' was reached without exhausting the artifact "
    "category. Flag as BLOCKER if found identities were never cross-referenced against "
    "a suspect list that was available in the case context.\n\n"
    "Return a structured punch list. Mark BLOCKERS (must fix before report is "
    "written) separately from ADVISORIES (should note, not blocking).\n\n"
    "ALWAYS end your response with a single canonical line in EXACTLY this form, "
    "on its own line:\n"
    "  BLOCKERS: None        (when there are no blockers)\n"
    "  BLOCKERS: <1-line summary of each blocker>   (when there are)\n"
    "This line is machine-parsed. Do not use the word 'blocker' elsewhere to "
    "describe a gap you are NOT blocking on — call those ADVISORIES."
    + _DIRECTIVES_INSTRUCTION
)


# ── MCP tools ─────────────────────────────────────────────────────────────────

@mcp.tool()
@with_tool_timeout(_REASON_WATCHDOG, label="reason_plan")
def reason_plan(case_description: str, evidence_available: str,
                input_call_ids: list[int] | None = None) -> dict:
    """
    Generate a prioritized investigation plan before deep forensic tool runs.
    Call this after the fast pre-enumeration block (SYSTEM hive, SAM hive,
    SOFTWARE hive, memory stat) so the plan is grounded in real evidence data.

    case_description: incident description — host, timeframe, known suspicion
    evidence_available: concatenated output from the pre-enumeration tools
    input_call_ids: REQUIRED (after genesis grace) — list of _trudi_call_id
        values for the pre-enumeration tool calls that produced the evidence
        you're passing in. The `lineage_required` gate enforces this.
    """
    capped = _cap_lines(evidence_available, 300)
    user = f"CASE:\n{case_description}\n\nEVIDENCE AVAILABLE:\n{capped}"
    return _ask(_PLAN_SYS, user, max_tokens=MAX_TOKENS_PLAN, _tool_name="reason_plan",
                input_call_ids=input_call_ids)


# ── Per-hypothesis split (sub-hypothesis tracking) ───────────────────────────
# reason_hypothesize returns N ranked alternatives in ONE call under ONE
# hypothesis_id. Parse them into individually-trackable records so the
# exhaustion gate can require EACH contested principal to be driven to a verdict
# (not just the leading one). Header form: "H1 — <title> (Likelihood: <level>)".
_SUB_HYP_HEADER_RE = re.compile(
    r"^\s*H(\d+)\s*[—–:\-]\s*(.+?)\s*\(\s*Likelihood\s*:\s*([A-Za-z/\- ]+?)\s*\)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_SUB_ENTITY_STOP = frozenset({
    "PC", "IT", "THE", "THIS", "THAT", "NEW", "ADMIN", "USER", "SERVICE",
    "DEFAULT", "SYSTEM", "NAME", "ACCOUNT", "PRINCIPAL",
})
_SUB_BUILTIN_ACCTS = ("guest", "administrator", "defaultaccount", "homegroupuser",
                      "wdagutilityaccount", "krbtgt")


def _sub_hyp_tier(level: str) -> str:
    """Normalise a likelihood string to HIGH/MEDIUM/LOW ('MEDIUM-HIGH'→HIGH,
    'LOW-MEDIUM'→MEDIUM, unknown→MEDIUM so it must still be resolved)."""
    l = (level or "").lower()
    if "high" in l:
        return "HIGH"
    if "med" in l:
        return "MEDIUM"
    if "low" in l:
        return "LOW"
    return "MEDIUM"


def _sub_hyp_entities(block: str) -> list[str]:
    """Principal/account tokens a sub-hypothesis contests: quoted account names
    and built-in account names. Quoting is how analysts mark a real account
    (e.g. 'svc_backup'); built-ins (Guest/Administrator) are valid subjects.
    Deliberately does NOT scrape 'X account' — that is descriptive noise
    ('OneDrive account binding', 'malware-created account')."""
    ents: set[str] = set()
    for m in re.finditer(r"[`'\"]([A-Za-z][\w.$-]{2,40})[`'\"]", block):
        ents.add(m.group(1).upper())
    low = block.lower()
    for b in _SUB_BUILTIN_ACCTS:
        if re.search(r"\b" + re.escape(b) + r"\b", low):
            ents.add(b.upper())
    return sorted(e for e in ents if e not in _SUB_ENTITY_STOP)


def _parse_sub_hypotheses(conclusion: str, hid: str) -> list[dict]:
    """Split a hypothesize conclusion's ranked 'H1 — … (Likelihood: …)' blocks
    into per-hypothesis records {sub_id,label,title,likelihood_tier,entities}.
    Returns [] when fewer than 2 parse, so callers fall back to per-call-id
    tracking (non-breaking for differently-formatted output)."""
    if not conclusion:
        return []
    matches = list(_SUB_HYP_HEADER_RE.finditer(conclusion))
    if len(matches) < 2:
        return []
    subs: list[dict] = []
    for i, m in enumerate(matches):
        n = m.group(1)
        title = (m.group(2) or "").strip()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(conclusion)
        block = title + "\n" + conclusion[start:end]
        subs.append({
            "sub_id": f"{hid}.{n}",
            "label": f"H{n}",
            "title": title[:160],
            "likelihood_tier": _sub_hyp_tier(m.group(3)),
            "entities": _sub_hyp_entities(block),
        })
    return subs


@mcp.tool()
@with_tool_timeout(_REASON_WATCHDOG, label="reason_hypothesize")
def reason_hypothesize(observation: str, evidence: str = "", context: str = "",
                       mode: str = "presence",
                       input_call_ids: list[int] | None = None) -> dict:
    """
    Generate ranked hypotheses to guide the investigation. Two modes:

    mode="presence" (default) — ranked alternative explanations (malicious and
    benign) for an artifact you HAVE surfaced. Call when a finding has multiple
    plausible interpretations.
      observation: the single behaviour/artifact being explained (one sentence,
                   e.g. "cmd.exe PID 5024 spawned from orphaned PPID 2748")
      evidence:    raw artifact list supporting it (tool output, EIDs, timestamps)

    mode="absence" — DIFFERENTIAL coverage review: what high-value artifact
    category has NOT been examined that could carry decisive identity /
    attribution / second-principal / alternate-exfil evidence for the unresolved
    question. Returns probe candidates in priority_tools. Fire this before any
    phase-out / Triage max-pass-cap transition, and whenever coverage feels thin.
      observation: the UNRESOLVED part of the case question (one sentence)
      evidence:    the artifact categories ALREADY examined (so it proposes gaps)

    context: broader case context (OS, known TTPs, incident timeline, roster).
    input_call_ids: REQUIRED — _trudi_call_id values for the calls that informed this.

    The returned hypothesis_id should be passed as `seeded_by` to any
    misc.record_curiosity_probe spawned from an absence-mode gap.
    """
    if mode == "absence":
        user = f"UNRESOLVED QUESTION:\n{observation}"
        if evidence:
            user += f"\n\nARTIFACT CATEGORIES ALREADY EXAMINED:\n{evidence}"
        if context:
            user += f"\n\nCASE CONTEXT:\n{context}"
        system = _HYPOTHESIZE_ABSENCE_SYS
    else:
        user = f"OBSERVATION:\n{observation}"
        if evidence:
            user += f"\n\nSUPPORTING EVIDENCE:\n{evidence}"
        if context:
            user += f"\n\nCASE CONTEXT:\n{context}"
        system = _HYPOTHESIZE_SYS
    hid = _next_hypothesis_id()
    result = _ask(system, user, max_tokens=MAX_TOKENS_HYPOTHESIZE,
                  _tool_name="reason_hypothesize", hypothesis_id=hid,
                  input_call_ids=input_call_ids)

    # ── Server-side conclusion parser (Fix G) ───────────────────────────────
    # If the model's prose conclusion names specific search patterns or
    # investigative steps but the structured directives.priority_tools is
    # empty, extract the recommendations from the prose and synthesise
    # priority_tools entries. Defense in depth — keeps the agent moving
    # even when the model forgets to populate the directives block.
    try:
        import re as _re
        directives = result.get("directives") or {}
        existing_tools = list(directives.get("priority_tools") or [])
        if not existing_tools:
            conclusion = result.get("conclusion", "") or ""
            extracted: list[str] = []
            # Pattern A: explicit "search for X" / "grep for X" / "look for X"
            for m in _re.finditer(
                r"(?:search|grep|look|check|hunt|extract|filter)\s+(?:for\s+|the\s+)?[`\"']?([A-Za-z0-9_@:.\-=/]{3,40})[`\"']?",
                conclusion, _re.IGNORECASE,
            ):
                term = m.group(1).strip().rstrip(".,;:")
                if term and term.lower() not in {"the", "and", "for", "from"}:
                    extracted.append(f"net.ngrep_search(pattern={term!r})")
            # Pattern B: explicit tool names mentioned (net.X, vol.X, ez.X, ...)
            for m in _re.finditer(
                r"\b((?:net|vol|tsk|ez|strings|hash|carve|enrich|misc|yara|correlate|af|live)\.[a-z_]+)",
                conclusion,
            ):
                tool_name = m.group(1)
                if tool_name not in extracted:
                    extracted.append(tool_name)
            # Pattern C: HTTP cookie / webmail keywords trigger session inventory.
            # Bare "session" — meaning a *logon* session — must NOT pull an HTTP
            # PCAP tool; that misfire emitted net.http_session_inventory for a
            # logon-session (not web-session) hypothesis.
            if _re.search(
                r"\b(cookie|webmail|gmail|yahoo|hotmail|aol|http session|web session)\b",
                conclusion, _re.IGNORECASE,
            ):
                if "net.http_session_inventory" not in extracted:
                    extracted.append("net.http_session_inventory")
            # Pattern D: identity-discriminator phrases → the EZ/misc tool that
            # extracts them, so the top-two competing hypotheses' discriminators
            # become the actual work order (not a generic sweep). Closes the
            # breakpoint where the model's confirm/rule-out recipe was dropped.
            for _rx, _tool in (
                (r"onedrive|account binding|registry .*account|cloud account|liveid", "ez.recmd_hive"),
                (r"\busb\b|usbstor|device serial|removable .*serial|usb serial", "misc.usbdeviceforensics"),
                (r"logon type|logon source|\b4624\b|\b4625\b|interactive logon|source address", "ez.evtxecmd"),
                (r"prefetch|run count", "ez.pecmd"),
                (r"shellbag", "ez.sbecmd"),
                (r"userassist", "misc.regripper_hive"),
                (r"amcache", "ez.amcacheparser"),
            ):
                if _re.search(_rx, conclusion, _re.IGNORECASE) and _tool not in extracted:
                    extracted.append(_tool)
            # Cap to avoid runaway
            extracted = extracted[:12]
            if extracted:
                directives["priority_tools"] = extracted
                directives.setdefault("_extracted_from_conclusion", True)
                result["directives"] = directives
                # Annotate the result so callers know these were auto-extracted
                result["_priority_tools_auto_extracted"] = True
    except Exception as _ge:
        import sys as _sys
        print(f"[TRUDI WARN] hypothesize conclusion post-processor failed: {_ge}",
              file=_sys.stderr)

    # ── Per-hypothesis split (Part 1) ───────────────────────────────────────
    # Parse the ranked H1…Hn alternatives into individually-trackable records and
    # persist them on this reason_call entry so the exhaustion gate can require
    # each contested principal to reach a verdict (not just the leading one).
    try:
        subs = _parse_sub_hypotheses(result.get("conclusion", "") or "",
                                     result.get("hypothesis_id", "") or "")
        if subs:
            cid = result.get("_trudi_call_id")
            if cid:
                from core.execution_log import log as _elog
                _elog.update_reason_call(cid, sub_hypotheses=subs,
                                         directives=result.get("directives"))
            result["sub_hypotheses"] = subs
    except Exception as _se:
        import sys as _sys
        print(f"[TRUDI WARN] hypothesize sub-split failed: {_se}", file=_sys.stderr)

    return result


@mcp.tool()
@with_tool_timeout(_REASON_WATCHDOG, label="reason_evaluate_finding")
def reason_evaluate_finding(
    finding: str,
    supporting_evidence: str,
    case_context: str = "",
    input_call_ids: list[int] | None = None,
) -> dict:
    """
    Adversarially challenge a specific conclusion before it goes into the report.
    Returns verdict (SUPPORTED / CHALLENGED / UNCERTAIN), identified weaknesses,
    and what additional evidence would resolve uncertainty.

    finding: the specific conclusion being made
    supporting_evidence: the artifacts and tool output that support it
    case_context: broader investigation context
    input_call_ids: REQUIRED — list of _trudi_call_id values that produced
        the supporting_evidence you're passing in.

    When the model returns VERDICT: CHALLENGED, this function auto-emits a
    `self_correction` trace entry so the moment is captured as a first-class
    audit event even when the agent abandons the claim without ever calling
    record_finding (the only path that previously emitted self_correction).

    Reformulation depth gate: tracks how many times the same normalized finding
    description has been through evaluate_finding recently without intervening
    new tool calls. Refuses on the third consecutive reformulation so the agent
    stops defending a finding that isn't improving with new evidence.
    """
    import re
    # ── Reformulation depth gate ────────────────────────────────────────────
    # Normalize the finding for comparison: lowercase, collapse whitespace,
    # drop punctuation. Then walk recent trace entries to count prior
    # evaluate_finding calls on the same normalized description that occurred
    # without an intervening tool_call producing new evidence.
    def _normalize(s: str) -> str:
        return re.sub(r"[\s\W_]+", " ", (s or "").lower()).strip()
    try:
        from core.execution_log import log
        norm_now = _normalize(finding)[:200]
        if norm_now:
            recent = log._entries[-60:] if len(log._entries) > 60 else log._entries
            prior_evals = 0
            new_tool_calls_since_last_eval = 0
            saw_eval = False
            for entry in reversed(recent):
                t = entry.get("type")
                if t == "reason_call" and entry.get("tool") == "reason_evaluate_finding":
                    blob = entry.get("conclusion", "") + " " + str(entry.get("inputs", {}).get("user_message", ""))
                    if norm_now and norm_now in _normalize(blob)[:5000]:
                        prior_evals += 1
                        saw_eval = True
                elif t == "tool_call" and entry.get("success"):
                    if not saw_eval:
                        new_tool_calls_since_last_eval += 1
            # 2 prior reformulations + no new tool evidence between latest eval
            # and now = refuse the third attempt.
            if prior_evals >= 2 and new_tool_calls_since_last_eval == 0:
                refusal_msg = (
                    f"Reformulation depth gate refused this evaluate_finding call: "
                    f"the same finding description has been evaluated {prior_evals} "
                    f"time(s) recently with no new tool evidence collected between "
                    f"attempts. Reformulating a finding that isn't acquiring new "
                    f"supporting evidence is a rumination spiral. Run new tool "
                    f"calls to gather fresh evidence, OR park this finding "
                    f"(record as UNCONFIRMED with note about the reformulation "
                    f"loop) and explore a different finding direction relevant "
                    f"to the case question."
                )
                # Emit a self_correction so the loop break is auditable
                try:
                    log.record_self_correction(
                        trigger="reformulation_depth_gate",
                        prior_belief=f"Repeated evaluate on: {finding[:200]}",
                        new_belief=("Refused by reformulation depth gate — explore "
                                    "different finding directions or run new tools."),
                        evidence=refusal_msg[:300],
                        linked_call_id=0,
                    )
                except Exception:
                    pass
                return {
                    "success": False,
                    "error": refusal_msg,
                    "gate": "reformulation_depth_limit",
                    "prior_evaluations": prior_evals,
                    "new_tool_calls_since_last_eval": new_tool_calls_since_last_eval,
                }
    except Exception as _gate_e:
        # Gate must never break the underlying call — log and continue
        import sys as _sys
        print(f"[TRUDI WARN] reformulation_depth_limit check failed: {_gate_e}",
              file=_sys.stderr)

    user = f"FINDING:\n{finding}\n\nSUPPORTING EVIDENCE:\n{supporting_evidence}"
    if case_context:
        user += f"\n\nCASE CONTEXT:\n{case_context}"
    result = _ask(_EVALUATE_SYS, user, max_tokens=MAX_TOKENS_EVALUATE,
                  _tool_name="reason_evaluate_finding",
                  input_call_ids=input_call_ids)
    conclusion = result.get("conclusion", "") or ""
    verdict_match = re.search(
        r"VERDICT:\s*(SUPPORTED|CHALLENGED|UNCERTAIN)", conclusion, re.IGNORECASE,
    )
    if verdict_match and verdict_match.group(1).upper() == "CHALLENGED":
        try:
            from core.execution_log import log
            # _log_reason has already written the reason_call entry. Find its
            # call_id so the self_correction can carry an explicit FK.
            eval_cid = 0
            for entry in reversed(log._entries):
                if (entry.get("type") == "reason_call"
                        and entry.get("tool") == "reason_evaluate_finding"):
                    eval_cid = int(entry.get("call_id") or 0)
                    break
            log.record_self_correction(
                trigger="evaluate_challenged",
                prior_belief=f"Attempted to assert: {finding[:200]}",
                new_belief=("reason.evaluate_finding returned CHALLENGED — claim "
                            "refuted before recording. Address the weaknesses or "
                            "downgrade the tier before re-evaluating."),
                evidence=conclusion[:300],
                linked_call_id=eval_cid,
            )
        except Exception as e:  # noqa: BLE001
            import sys
            print(f"[TRUDI WARN] auto-self_correction emit failed: {e}", file=sys.stderr)
    return result


_CITE_CHECK_SYS = (
    "You are a citation auditor. Given a forensic FINDING and its SUPPORTING_EVIDENCE, "
    "verify that every concrete claim in the finding has a citation in the evidence.\n\n"
    "Concrete claims include: file paths, IP addresses, port numbers, timestamps, "
    "process names, account names, registry keys, hash values, event IDs, port numbers, "
    "service names, MITRE ATT&CK technique IDs, and specific numeric quantities.\n\n"
    "For each concrete claim, decide:\n"
    "  CITED — the same value appears in supporting_evidence with a tool name or "
    "field reference (e.g. 'vol.psscan: PID=5024', '/mnt/rd01/Windows/Temp/X.exe').\n"
    "  UNCITED — the value appears in the finding but not in supporting_evidence, "
    "OR appears without a tool/field reference.\n\n"
    "Output format (strict, no markdown bolding, no code fences):\n"
    "CITE_CHECK:\n"
    "{\n"
    '  "verdict": "ALL_CITED" | "UNCITED_CLAIMS_PRESENT" | "INSUFFICIENT_EVIDENCE",\n'
    '  "cited_claims": ["claim text 1", "claim text 2", ...],\n'
    '  "uncited_claims": ["claim text X", "claim text Y", ...],\n'
    '  "rationale": "one-sentence summary"\n'
    "}\n\n"
    "Choose INSUFFICIENT_EVIDENCE only when supporting_evidence is empty or contains "
    "no actual artifact data. A finding with no concrete claims gets ALL_CITED with "
    "empty arrays."
)


def _parse_cite_check(raw: str) -> dict:
    """Extract CITE_CHECK JSON block from model output."""
    import re
    if not raw:
        return {"verdict": "INSUFFICIENT_EVIDENCE", "cited_claims": [],
                "uncited_claims": [], "rationale": "empty model output"}
    match = re.search(
        r"\*{0,2}CITE_CHECK\*{0,2}\s*:?\*{0,2}\s*(?:```json\s*)?(\{.*\})\s*(?:```)?",
        raw, re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return {"verdict": "INSUFFICIENT_EVIDENCE", "cited_claims": [],
                "uncited_claims": [], "rationale": "no CITE_CHECK block found"}
    text = re.sub(r"\s*//[^\n]*", "", match.group(1))
    try:
        parsed = json.loads(text)
        return {
            "verdict": parsed.get("verdict", "INSUFFICIENT_EVIDENCE"),
            "cited_claims": parsed.get("cited_claims", []) or [],
            "uncited_claims": parsed.get("uncited_claims", []) or [],
            "rationale": parsed.get("rationale", ""),
        }
    except (json.JSONDecodeError, ValueError):
        return {"verdict": "INSUFFICIENT_EVIDENCE", "cited_claims": [],
                "uncited_claims": [], "rationale": "malformed CITE_CHECK JSON"}


@mcp.tool()
@with_tool_timeout(_REASON_WATCHDOG, label="reason_cite_check")
def reason_cite_check(finding: str, supporting_evidence: str,
                      input_call_ids: list[int] | None = None) -> dict:
    """
    Proactively verify every concrete claim in `finding` is backed by a citation
    in `supporting_evidence`. Call before record_finding to surface uncited
    claims while you can still gather evidence.

    finding: the conclusion text as you intend to record it.
    supporting_evidence: the tool output excerpts and citations that back it.
    input_call_ids: REQUIRED — list of _trudi_call_id values that produced
        the supporting_evidence.

    Returns: verdict (ALL_CITED / UNCITED_CLAIMS_PRESENT / INSUFFICIENT_EVIDENCE),
             cited_claims, uncited_claims, rationale.
    """
    user = f"FINDING:\n{finding}\n\nSUPPORTING_EVIDENCE:\n{supporting_evidence}"
    result = _ask(_CITE_CHECK_SYS, user, max_tokens=MAX_TOKENS_CITE_CHECK,
                  _tool_name="reason_cite_check",
                  input_call_ids=input_call_ids)
    if result.get("success"):
        parsed = _parse_cite_check(result.get("conclusion", ""))
        result.update(parsed)
    return result


_CONFIDENCE_SCORE_SYS = (
    "You are a forensic confidence-tier scorer. Given a finding and its "
    "supporting evidence, decide the appropriate confidence tier:\n\n"
    "  CONFIRMED — multiple independent forensic artifacts directly support "
    "the claim (e.g. MFT record + Prefetch + EVTX 7045 all agreeing); the "
    "claim is technically verified and the alternative explanations are ruled out.\n"
    "  LIKELY    — a single high-quality artifact supports the claim "
    "(e.g. a definitive EVTX entry, an authoritative VT detection ratio); "
    "alternative explanations are weak but not eliminated.\n"
    "  SUSPECTED — indirect or pattern-based evidence (e.g. anomalous timing, "
    "YARA hit alone, suspicious filename); plausible alternatives remain.\n"
    "  UNCONFIRMED — inference or expectation only; no direct artifact.\n\n"
    "Apply hard rules:\n"
    "  - YARA hit ALONE is NEVER above SUSPECTED.\n"
    "  - A claim that the supporting evidence does not literally contain is "
    "UNCONFIRMED.\n"
    "  - Mechanism claims (how something happened) need direct artifact "
    "support or drop to SUSPECTED.\n"
    "  - Negative findings (we didn't see X) are UNCONFIRMED unless an "
    "exhaustive search method is cited.\n\n"
    "Output format (strict, no markdown bolding, no code fences):\n"
    "CONFIDENCE_SCORE:\n"
    "{\n"
    '  "tier": "CONFIRMED" | "LIKELY" | "SUSPECTED" | "UNCONFIRMED",\n'
    '  "score": 0.0,\n'
    '  "rationale": "one-line justification citing the evidence",\n'
    '  "downgrade_reasons": ["reason 1", "reason 2"]\n'
    "}\n\n"
    "score is a 0.0–1.0 numeric confidence: ≥0.85 CONFIRMED, 0.60–0.84 LIKELY, "
    "0.30–0.59 SUSPECTED, <0.30 UNCONFIRMED. downgrade_reasons is non-empty "
    "only when the tier is below the agent's apparent intent."
)


def _parse_confidence_score(raw: str) -> dict:
    """Extract CONFIDENCE_SCORE JSON from model output."""
    if not raw:
        return {"tier": "UNCONFIRMED", "score": 0.0,
                "rationale": "empty model output", "downgrade_reasons": []}
    match = re.search(
        r"\*{0,2}CONFIDENCE_SCORE\*{0,2}\s*:?\*{0,2}\s*(?:```json\s*)?(\{.*\})\s*(?:```)?",
        raw, re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return {"tier": "UNCONFIRMED", "score": 0.0,
                "rationale": "no CONFIDENCE_SCORE block found",
                "downgrade_reasons": []}
    text = re.sub(r"\s*//[^\n]*", "", match.group(1))
    try:
        parsed = json.loads(text)
        tier = (parsed.get("tier") or "UNCONFIRMED").upper()
        if tier not in ("CONFIRMED", "LIKELY", "SUSPECTED", "UNCONFIRMED"):
            tier = "UNCONFIRMED"
        score_val = parsed.get("score", 0.0)
        try:
            score = float(score_val)
        except (TypeError, ValueError):
            score = 0.0
        return {
            "tier": tier,
            "score": max(0.0, min(1.0, score)),
            "rationale": parsed.get("rationale", ""),
            "downgrade_reasons": parsed.get("downgrade_reasons", []) or [],
        }
    except (json.JSONDecodeError, ValueError):
        return {"tier": "UNCONFIRMED", "score": 0.0,
                "rationale": "malformed CONFIDENCE_SCORE JSON",
                "downgrade_reasons": []}


@mcp.tool()
@with_tool_timeout(_REASON_WATCHDOG, label="reason_confidence_score")
def reason_confidence_score(finding: str, supporting_evidence: str,
                            intended_tier: str = "",
                            input_call_ids: list[int] | None = None) -> dict:
    """
    Score a finding's confidence tier from its supporting evidence. Use BEFORE
    record_finding for any tier above SUSPECTED — this grounds the tier choice
    in evidence properties rather than agent assertion.

    finding: the claim text.
    supporting_evidence: tool output excerpts + citations that back the claim.
    intended_tier: optional — what tier the agent was about to use. The reviewer
                   compares its scoring to this and flags downgrades.
    input_call_ids: REQUIRED — list of _trudi_call_id values that produced
        the supporting_evidence.

    Returns: tier (CONFIRMED/LIKELY/SUSPECTED/UNCONFIRMED), score (0.0–1.0),
             rationale, downgrade_reasons.
    """
    user = (
        f"FINDING:\n{finding}\n\n"
        f"SUPPORTING_EVIDENCE:\n{supporting_evidence}"
    )
    if intended_tier:
        user += f"\n\nAGENT_INTENDED_TIER: {intended_tier.upper()}"
    result = _ask(_CONFIDENCE_SCORE_SYS, user, max_tokens=MAX_TOKENS_CONFIDENCE,
                  _tool_name="reason_confidence_score",
                  input_call_ids=input_call_ids)
    if result.get("success"):
        parsed = _parse_confidence_score(result.get("conclusion", ""))
        result.update(parsed)
    return result


_AUDIT_FINDINGS_SYS = (
    "You audit a forensic investigation's execution trace for unrecorded findings.\n\n"
    "You receive:\n"
    "  - A list of recent NARRATIONS (assistant analysis text written to the trace).\n"
    "  - A list of RECORDED_FINDINGS (structured finding entries currently in the trace).\n\n"
    "Identify factual claims in the narrations that should have been recorded as "
    "structured `finding` entries but weren't. Look for:\n"
    "  - Specific IOCs (file paths, IPs, hashes, process names, account names).\n"
    "  - Attribution claims (this is attacker tool X, this is technique Y).\n"
    "  - Mechanism claims (X happened because of Y).\n"
    "  - Confirmed compromise statements.\n"
    "  - Exfiltration / lateral-movement / persistence confirmations.\n\n"
    "Skip narrations that:\n"
    "  - Just restate a finding that's already in RECORDED_FINDINGS (same IOC + same claim).\n"
    "  - Describe planned next steps without stating facts.\n"
    "  - Express reasoning, hypotheses, or directives only.\n\n"
    "Output format (strict, no markdown bolding, no code fences):\n"
    "AUDIT_FINDINGS:\n"
    "[\n"
    "  {\n"
    "    \"narration_call_id\": 819,\n"
    "    \"narration_excerpt\": \"first ~200 chars of the narration\",\n"
    "    \"suggested_finding\": {\n"
    "      \"description\": \"…\",\n"
    "      \"suggested_confidence\": \"CONFIRMED|LIKELY|SUSPECTED|UNCONFIRMED\",\n"
    "      \"suggested_source\": \"tool that produced it, e.g. vol.netscan\"\n"
    "    },\n"
    "    \"suggested_linked_call_id\": 815,\n"
    "    \"rationale\": \"one-line why this should be a structured finding\"\n"
    "  }\n"
    "]\n\n"
    "Return an empty array [] if all factual claims are already represented in "
    "RECORDED_FINDINGS. Conservative is better than aggressive — if in doubt, skip."
)


def _parse_audit_findings(raw: str) -> list[dict]:
    """Extract AUDIT_FINDINGS JSON array from model output."""
    if not raw:
        return []
    match = re.search(
        r"\*{0,2}AUDIT_FINDINGS\*{0,2}\s*:?\*{0,2}\s*(?:```json\s*)?(\[.*\])\s*(?:```)?",
        raw, re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return []
    text = re.sub(r"\s*//[^\n]*", "", match.group(1))
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, list) else []
    except (json.JSONDecodeError, ValueError):
        return []


@mcp.tool()
@with_tool_timeout(_REASON_WATCHDOG, label="reason_audit_findings")
def reason_audit_findings(narration_window: int = 60,
                          input_call_ids: list[int] | None = None) -> dict:
    """
    Audit the live trace for unrecorded findings.

    Reads the most-recent `narration_window` investigation_narration entries
    and all current `finding` entries from the execution log, sends them to
    the reason backend, and returns model-judged candidates for factual
    claims that should be recorded as structured findings but aren't.

    narration_window: how many of the most recent narrations to audit.

    Returns:
      candidates: list of {
        narration_call_id, narration_excerpt,
        suggested_finding: {description, suggested_confidence, suggested_source},
        suggested_linked_call_id, rationale,
      }
      summary: {total_narrations, recorded_findings, candidate_count}
    """
    from core.execution_log import log
    narrations = [
        e for e in log._entries if e.get("type") == "investigation_narration"
    ]
    if narration_window and len(narrations) > narration_window:
        narrations = narrations[-narration_window:]
    findings_entries = [e for e in log._entries if e.get("type") == "finding"]

    if not narrations:
        return {
            "success": True,
            "candidates": [],
            "summary": {
                "total_narrations": 0,
                "recorded_findings": len(findings_entries),
                "candidate_count": 0,
            },
        }

    # Trim narrations/findings for the prompt
    nars_payload = [
        {"call_id": e.get("call_id"),
         "content": (e.get("content") or "")[:1200],
         "input_call_ids": e.get("input_call_ids") or []}
        for e in narrations
    ]
    finds_payload = [
        {"call_id": e.get("call_id"),
         "description": (e.get("description") or "")[:300],
         "confidence": e.get("confidence", ""),
         "linked_call_id": e.get("linked_call_id", 0)}
        for e in findings_entries
    ]
    user = (
        f"NARRATIONS ({len(nars_payload)} most recent):\n"
        f"{json.dumps(nars_payload, indent=2)}\n\n"
        f"RECORDED_FINDINGS ({len(finds_payload)}):\n"
        f"{json.dumps(finds_payload, indent=2)}"
    )
    # If no explicit input_call_ids supplied, auto-derive from the call_ids
    # of every narration + finding we just consumed — keeps the lineage
    # complete without forcing the agent to list them all.
    derived_ids = input_call_ids or [
        e.get("call_id") for e in (narrations + findings_entries)
        if e.get("call_id")
    ]
    result = _ask(_AUDIT_FINDINGS_SYS, user, max_tokens=MAX_TOKENS_AUDIT_FINDINGS,
                  _tool_name="reason_audit_findings",
                  input_call_ids=derived_ids)
    candidates = []
    if result.get("success"):
        candidates = _parse_audit_findings(result.get("conclusion", ""))
    return {
        **result,
        "candidates": candidates,
        "summary": {
            "total_narrations": len(narrations),
            "recorded_findings": len(findings_entries),
            "candidate_count": len(candidates),
        },
    }


@mcp.tool()
@with_tool_timeout(_REASON_WATCHDOG, label="reason_synthesize")
def reason_synthesize(findings: str, investigation_summary: str = "",
                      input_call_ids: list[int] | None = None) -> dict:
    """
    Cross-finding consistency and completeness check. Call this before writing
    the final report. Identifies logical gaps, contradictions, overclaimed
    conclusions, and missing investigation steps.

    findings: newline-separated list of confirmed findings
    investigation_summary: brief summary of tools run and scope covered
    input_call_ids: REQUIRED — typically the call_ids of every CONFIRMED/LIKELY
        finding entry in the trace (the synthesis aggregates them all).

    Only callable in the Report phase. Requires that the most recent dair_assess
    call returned current_phase="Report"; otherwise refused.
    """
    from core.execution_log import log
    recent_dair = None
    for e in reversed(log._entries):
        if e.get("type") == "dair_call":
            recent_dair = e
            break
    if recent_dair is None:
        return {
            "success": False,
            "error": (
                "No dair_assess call found in execution trace. Call dair_assess "
                "to establish phase state before reason.synthesize."
            ),
        }
    phase = recent_dair.get("current_phase", "")
    if phase != "Report":
        return {
            "success": False,
            "error": (
                f"reason.synthesize is only callable in Report phase. Current "
                f"DAIR phase: {phase or 'unknown'}. Continue the DAIR loop until "
                f"dair_assess returns next_phase='Report'."
            ),
        }
    user = f"FINDINGS:\n{findings}"
    if investigation_summary:
        user += f"\n\nINVESTIGATION COVERAGE:\n{investigation_summary}"
    # Auto-derive lineage from every finding cid if not supplied
    derived_ids = input_call_ids or [
        e.get("call_id") for e in log._entries
        if e.get("type") == "finding" and e.get("call_id")
    ]
    return _ask(_SYNTHESIZE_SYS, user, max_tokens=MAX_TOKENS_SYNTHESIZE,
                _tool_name="reason_synthesize",
                input_call_ids=derived_ids)


_BLOCKER_NEGATION_RE = re.compile(
    r"(?:no|zero|0|without|not|n/?a|none|never|free of|resolved|cleared|"
    r"are no|were no|there are no|there were no)[\s\w]{0,15}$",
    re.IGNORECASE,
)


def _has_unnegated_blocker(text: str) -> bool:
    """True if `text` mentions a 'blocker'/'blockers' that is NOT negated.

    Used only as a fallback when no canonical 'BLOCKERS:' header is present.
    A negated mention ("no blockers", "free of blockers", "0 blockers",
    "no blocker conditions found") is not a real blocker and must pass — the
    previous bare-word `\\bBLOCKER\\b` check wrongly flagged those, and also
    only matched the singular. Here we scan every blocker(s) occurrence and
    require at least one whose preceding context carries no negation.
    """
    for mt in re.finditer(r"blockers?\b", text, re.IGNORECASE):
        pre = text[max(0, mt.start() - 25):mt.start()]
        if not _BLOCKER_NEGATION_RE.search(pre):
            return True
    return False


@mcp.tool()
@with_tool_timeout(_REASON_WATCHDOG, label="reason_pre_report_check")
def reason_pre_report_check() -> dict:
    """
    Verify all mandatory investigation checkpoints before writing the report.
    Reads the live execution trace and returns blocking_issues (must resolve)
    and warnings (should review). Do not write the report if ready_to_report
    is False.

    Call this after reason.synthesize and before writing any report section.
    """
    from core.execution_log import log
    entries = log._entries

    has_plan = any(
        e["type"] == "reason_call" and e.get("tool") == "reason_plan"
        for e in entries
    )
    has_synthesize = any(
        e["type"] == "reason_call" and e.get("tool") == "reason_synthesize"
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

    issues: list[str] = []
    warnings: list[str] = []

    if len(entries) == 0:
        issues.append("Execution trace is empty — start_execution_log was not called before tool runs")
    if not has_plan:
        issues.append("reason.plan was not called — mandatory before tool selection")
    if not has_synthesize:
        issues.append("reason.synthesize was not called — mandatory before writing report")

    latest_synthesize = ""
    for e in reversed(entries):
        if e.get("type") == "reason_call" and e.get("tool") == "reason_synthesize":
            latest_synthesize = e.get("conclusion") or ""
            break
    if latest_synthesize:
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
            # No canonical "BLOCKERS:" header, but a non-negated "blocker"
            # mention remains in the prose. A negated mention ("no blockers",
            # "free of blockers", "0 blockers") is NOT a blocker and must pass —
            # the old bare-word \bBLOCKER\b check false-positived on those.
            issues.append(
                "Latest reason.synthesize still labels one or more gaps as "
                "BLOCKER. Return to Triage/Collect/Analyze as needed, run the "
                "missing evidence work, then re-run reason.synthesize before "
                "Report. Do not try to satisfy this by rewording findings."
            )

    # Case-question gate: if any reason.plan call carries an explicit case_question
    # (passed by the agent via the case_description), or if a CASE_QUESTION: marker
    # appears in any agent_message / dair_call case_context, require at least one
    # CONFIRMED or LIKELY finding whose description plausibly addresses that question.
    case_question = ""
    cq_re = re.compile(r"CASE[_ ]QUESTION:\s*(.+?)(?:\n|$)", re.IGNORECASE)
    for e in entries:
        for field in ("conclusion", "content", "case_context", "case_description"):
            blob = (e.get(field) or "") if isinstance(e.get(field), str) else ""
            m = cq_re.search(blob)
            if m:
                case_question = m.group(1).strip()
                # The question proper ends at the first '?'. Opening narrations
                # sometimes jam the case question + plan text onto one line; if
                # we keep all of it, the token-match threshold below inflates
                # and no single finding can satisfy it. Truncate to the actual
                # question.
                qmark = case_question.find("?")
                if qmark != -1:
                    case_question = case_question[:qmark + 1]
                else:
                    # No '?': trim trailing plan/context text by keyword, then
                    # by first sentence, then a hard char cap.
                    case_question = re.split(
                        r"\b(?:Evidence|Case context|Known players|Comms channels|"
                        r"Starting pre-plan reads|Plan|Approach|Steps)\s*:",
                        case_question,
                        maxsplit=1,
                        flags=re.IGNORECASE,
                    )[0].strip()
                    case_question = case_question.split(". ")[0][:200]
                case_question = case_question.strip()
                break
        if case_question:
            break
    if case_question:
        # Tokenise the question into content words (drop stopwords/short tokens).
        stop = {"the", "and", "for", "with", "from", "this", "that", "what", "who",
                "where", "when", "why", "how", "did", "does", "was", "were", "are",
                "is", "of", "to", "on", "in", "at", "by", "an", "a", "as", "be",
                "or", "if", "it", "any"}
        q_tokens = [t for t in re.findall(r"[A-Za-z0-9_]+", case_question.lower())
                    if len(t) >= 3 and t not in stop]
        addressed = False
        if q_tokens:
            for e in entries:
                if e.get("type") != "finding":
                    continue
                tier = (e.get("confidence") or "").upper()
                if tier not in {"CONFIRMED", "LIKELY"}:
                    continue
                desc_l = (e.get("description") or "").lower()
                # Address = the finding mentions the question's key entities.
                # Cap the bar at 5 so a long (or still slightly polluted)
                # question can't demand an unreasonable number of token hits in
                # a single finding — the failure mode the SCHARDT run hit.
                hits = sum(1 for t in q_tokens if t in desc_l)
                required = min(max(2, len(q_tokens) // 2), 5)
                if hits >= required:
                    addressed = True
                    break
        if not addressed:
            issues.append(
                f"Case question \"{case_question}\" is not directly addressed by "
                f"any CONFIRMED or LIKELY finding. Record a finding whose description "
                f"answers the question (mentioning the question's key entities) "
                f"before transitioning to Report."
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
        from tools.dair import _extract_host_tokens
        finding_hosts: set[str] = set()
        for e in entries:
            if e.get("type") == "finding":
                finding_hosts |= _extract_host_tokens(e.get("description") or "")
            elif e.get("type") == "dair_call":
                finding_hosts |= _extract_host_tokens(
                    e.get("investigation_focus") or "")
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

    # Unrecorded-findings audit: model-based scan of narrations vs. structured
    # finding entries. Surfaces facts the agent wrote in chat but never
    # promoted via misc.record_finding.
    audit_summary: dict = {}
    try:
        audit = reason_audit_findings()
        audit_summary = audit.get("summary", {}) or {}
        n = int(audit_summary.get("candidate_count") or 0)
        if n > 0:
            cands = audit.get("candidates", [])[:5]
            cids = ", ".join(f"#{c.get('narration_call_id')}" for c in cands)
            warnings.append(
                f"{n} narration(s) appear to contain factual claims that aren't "
                f"recorded as structured `finding` entries (first 5: {cids}). "
                f"Call misc.record_finding (or misc.record_agent_message with "
                f"findings=[…]) for each, or restate to remove the fact language."
            )
    except Exception as _e:
        import sys as _sys
        print(f"[TRUDI WARN] audit_findings failed: {_e}", file=_sys.stderr)

    # ── Structural-integrity checks (generic) ───────────────────────────────
    # Catch the loose ends that let a verdict ship structurally wrong even when
    # every individual finding passed its record-time gates:
    #   #1 (blocking) a created/covert account whose controller was never
    #       established and was never parked as controller-unknown;
    #   #2 (warning) multiple un-ranked exfil channels;
    #   #3 (warning) a named recipient with no evident roster cross-reference.
    # #2/#3 are warnings because finding entries retain only the description,
    # not the supporting_evidence the record-time gates inspect — so channel /
    # recipient grounding cannot be soundly re-derived at report scope. #1 is
    # blocking: a named account with no controller binding is detectable from
    # descriptions alone and is the structural gap most likely to invert a case.
    try:
        from tools.dair import _extract_principal_tokens
        from tools._gates.principal_attribution_grounding import _SESSION_RE
        from tools._gates.exfil_channel_grounding import _EGRESS_RE, _CHANNEL_RE

        s_findings = [e for e in entries if e.get("type") == "finding"]

        def _ftier(e):
            return (e.get("confidence") or "").upper()

        # #1 — created/covert accounts named in CONFIRMED/LIKELY findings.
        # RID/SID tokens are excluded: they don't match reliably across prose
        # ("RID 1006" vs token "RID1006"); named accounts are trackable.
        created_principals = {
            p
            for e in s_findings if _ftier(e) in {"CONFIRMED", "LIKELY"}
            for p in _extract_principal_tokens(e.get("description") or "",
                                               require_cue=True)
            if not p.startswith("RID") and not p.startswith("S-1-")
        }
        for p in sorted(created_principals):
            established = False
            parked = False
            for e in s_findings:
                desc = e.get("description") or ""
                if p.lower() not in desc.lower():
                    continue
                if _ftier(e) in {"CONFIRMED", "LIKELY"} and _SESSION_RE.search(desc):
                    established = True
                    break
                if re.search(
                    r"(?:controll?er|who controls)[^.\n]*"
                    r"\b(?:unknown|unidentified|not established|unestablished)\b"
                    r"|\bunattributed\b",
                    desc, re.IGNORECASE,
                ):
                    parked = True
            if not established and not parked:
                issues.append(
                    f"Created/covert account '{p}' is named in a CONFIRMED/LIKELY "
                    f"finding but no finding establishes who controls it (no "
                    f"logon/session/source binding) and none parks it as "
                    f"controller-unknown. Pull the authentication artifact "
                    f"(Security 4624/4625 logon type + source address) and "
                    f"attribute it, or record an UNCONFIRMED 'controller unknown' "
                    f"finding before Report."
                )

        # #2 — multiple distinct exfil channel *families* in CONFIRMED/LIKELY
        # findings. Synonyms collapse to a family so "cloud via Dropbox" counts
        # once, not twice.
        def _channel_family(token: str) -> str:
            t = token.lower()
            if t in {"dropbox", "onedrive", "gdrive", "google drive", "mega", "box.com", "cloud"}:
                return "cloud"
            if t in {"ftp", "sftp", "tftp"}:
                return "ftp"
            if t in {"usb", "removable", "thumb drive", "flash drive"}:
                return "usb/removable"
            if t in {"email", "e-mail", "webmail", "smtp", "attachment"}:
                return "email"
            if t in {"web upload", "http upload"}:
                return "web upload"
            if t in {"c2", "telegram"}:
                return "c2/messenger"
            return t

        channels: set[str] = set()
        for e in s_findings:
            if _ftier(e) not in {"CONFIRMED", "LIKELY"}:
                continue
            desc = e.get("description") or ""
            if _EGRESS_RE.search(desc):
                channels |= {_channel_family(m.group(0)) for m in _CHANNEL_RE.finditer(desc)}
        if len(channels) >= 2:
            warnings.append(
                f"{len(channels)} distinct exfiltration channels appear in "
                f"CONFIRMED/LIKELY findings ({', '.join(sorted(channels))}). "
                f"Enumerate ALL candidate channels and ensure the verdict "
                f"headlines the strongest-evidenced one — a transfer artifact "
                f"beats tool/folder presence; do not over-weight a channel that "
                f"lacks a transfer record."
            )

        # #3 — a recipient named in a CONFIRMED/LIKELY exfil finding with no
        # evident roster cross-reference anywhere in the trace.
        recipient_findings = [
            e for e in s_findings
            if _ftier(e) in {"CONFIRMED", "LIKELY"}
            and _EGRESS_RE.search(e.get("description") or "")
            and re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+|\brecipient\b|\bbuyer\b|\bsent to\b",
                          e.get("description") or "", re.IGNORECASE)
        ]
        if recipient_findings:
            xref_seen = any(
                isinstance(e.get(f), str) and re.search(
                    r"roster|cross-referenc|suspect list|not on (?:the )?roster"
                    r"|knowns_pattern_generate|user directory",
                    e.get(f), re.IGNORECASE,
                )
                for e in entries
                for f in ("description", "content", "cmd", "conclusion")
            )
            if not xref_seen:
                warnings.append(
                    f"{len(recipient_findings)} exfil/dissemination finding(s) name "
                    f"a recipient but no roster / suspect-list cross-reference is "
                    f"evident in the trace. Inventory all correspondents and "
                    f"cross-reference the named recipient against the case roster "
                    f"(or note explicitly it is not on the roster) before Report."
                )

        # #4 — per-hypothesis exhaustion. reason_hypothesize returns N ranked
        # alternatives under ONE id; Part 1 split them into sub_hypotheses with
        # the principal entities each contests. EVERY contested principal at
        # MEDIUM+ likelihood must be driven to a verdict before Report — its
        # controller established (a CONFIRMED/LIKELY finding naming it WITH a
        # session/identity binding) or the alternative refuted. "Controller
        # unknown"/parked does NOT count (the single-actor lock-in dodge: a
        # second-principal alternative and the prime-subject hypothesis both
        # left unresolved while shipping a sole-actor verdict). When no
        # sub_hypotheses were parsed, fall back to the per-call-id ledger.
        idx = log.index()
        _distinct_principal_re = re.compile(
            r"(?:second (?:actor|principal|operator|user)\b|distinct principal\b"
            r"|who controls\b|another (?:account|user|person)\b|separate principal\b"
            r"|controller (?:of|unknown|unestablished)\b|who authenticated\b"
            r"|different (?:actor|operator)\b|\brdp\b|logon type\s*(?:2|10)\b)",
            re.IGNORECASE,
        )
        _refute_re = re.compile(
            r"\b(?:refuted|ruled out|disproven|false positive|rejected|not supported"
            r"|excluded|cannot be (?:attributed|established|determined)|unproven"
            r"|indeterminate|no identif\w+ artifact)\b", re.IGNORECASE,
        )
        all_subs = [
            s for e in entries
            if e.get("type") == "reason_call" and e.get("tool") == "reason_hypothesize"
            for s in (e.get("sub_hypotheses") or [])
        ]
        if all_subs:
            _rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
            ent_tier: dict[str, str] = {}
            ent_labels: dict[str, set] = {}
            for s in all_subs:
                t = s.get("likelihood_tier", "MEDIUM")
                for ent in s.get("entities") or []:
                    if _rank.get(t, 1) >= _rank.get(ent_tier.get(ent, "LOW"), 0):
                        ent_tier[ent] = t
                    ent_labels.setdefault(ent, set()).add(s.get("label") or "?")

            def _entity_terminal(ent: str) -> bool:
                el = ent.lower()
                for fe in s_findings:
                    d = fe.get("description") or ""
                    if el not in d.lower():
                        continue
                    if _ftier(fe) in {"CONFIRMED", "LIKELY"} and _SESSION_RE.search(d):
                        return True   # controller established
                    if _refute_re.search(d):
                        return True   # refuted / honestly exhausted
                return False

            for ent in sorted(ent_tier):
                if _entity_terminal(ent):
                    continue
                labels = ", ".join(sorted(ent_labels.get(ent, set())))
                tier = ent_tier[ent]
                msg = (
                    f"Contested principal '{ent}' (raised as hypothesis {labels}, "
                    f"likelihood {tier}) was never driven to a verdict: no "
                    f"CONFIRMED/LIKELY finding establishes its controller with a "
                    f"session/identity binding (logon 4624/4625 + type/source, "
                    f"OneDrive/registry account binding, USB serials), and no "
                    f"finding refutes the alternative. 'Controller unknown'/parked "
                    f"does not count — a sole-actor verdict cannot stand while "
                    f"'{ent}' is unresolved. Resolve it to CONFIRMED or REFUTED "
                    f"(run the discriminators) before Report."
                )
                if _rank.get(tier, 1) >= 1:   # MEDIUM / HIGH
                    issues.append(msg)
                else:                          # LOW
                    warnings.append(msg)
        else:
            # Fallback (no sub_hypotheses parsed): per-call-id resolution ledger.
            resolved_ids: set[str] = set()
            for e in s_findings:
                tid = (e.get("tested_hypothesis_id") or "").strip()
                if tid:
                    resolved_ids.add(tid)
                gh = e.get("gated_by_hypothesize_call_id")
                if gh:
                    ghe = idx.by_call_id.get(gh) or {}
                    ghid = (ghe.get("hypothesis_id") or "").strip()
                    if ghid:
                        resolved_ids.add(ghid)
            open_generic: list[str] = []
            for hid, hyp in sorted(idx.hypotheses_by_id.items()):
                if not hid or hid in resolved_ids:
                    continue
                obs = ((hyp.get("inputs") or {}).get("user_message") or "")
                is_distinct = bool(
                    _distinct_principal_re.search(obs)
                    or _distinct_principal_re.search(hyp.get("conclusion") or "")
                )
                if is_distinct:
                    issues.append(
                        f"Hypothesis {hid} frames a distinct/second principal or "
                        f"controller question but was never resolved: no finding "
                        f"carries it as tested_hypothesis_id and none parks it "
                        f"controller-unknown. A competing-principal hypothesis "
                        f"cannot be silently dropped — record a CONFIRMED/LIKELY "
                        f"finding that resolves it (with a logon/session binding), "
                        f"or an explicit UNCONFIRMED 'controller unknown' finding, "
                        f"before Report."
                    )
                else:
                    open_generic.append(hid)
            if open_generic:
                warnings.append(
                    f"{len(open_generic)} hypothesis/es raised but never resolved "
                    f"({', '.join(open_generic[:5])}"
                    f"{'…' if len(open_generic) > 5 else ''}) — no finding cites "
                    f"them as tested_hypothesis_id. Resolve or park each before Report."
                )

        # #5 (blocking) — attribution closure (i): a human/account attribution
        # verdict cannot ship without a logon/RDP session inventory that could
        # rule out a second principal operating the host. Scoped to human/account
        # verdicts so a process/malware attribution in a memory-only case (no
        # event logs) is not blocked.
        from tools._gates.principal_attribution_grounding import _ACCOUNT_RE
        from tools._gates.named_actor_attribution_grounding import (
            _NAME_RE as _na_name_re, _NAME_STOPS as _na_stops,
        )
        _VERDICT_RE = re.compile(
            r"\b(?:exfiltrat\w+|copied|stole|stol\w+|disseminat\w+|uploaded"
            r"|transferred|transmit\w+|leaked|smuggled|operated by|controlled by"
            r"|attributed to|logged ?in as|sole actor|acted alone"
            r"|responsible for)\b", re.IGNORECASE,
        )

        def _is_human_or_account_verdict(desc: str) -> bool:
            if not _VERDICT_RE.search(desc):
                return False
            if _ACCOUNT_RE.search(desc):
                return True
            if re.search(r"\bsole actor\b|\bacted alone\b|\bby [A-Z][a-z]+\b", desc):
                return True
            return bool(set(_na_name_re.findall(desc)) - _na_stops)

        has_verdict = any(
            _ftier(e) in {"CONFIRMED", "LIKELY"}
            and _is_human_or_account_verdict(e.get("description") or "")
            for e in s_findings
        )
        has_pcap_activity = any(
            e.get("type") == "tool_call" and isinstance(e.get("cmd"), str)
            and re.search(
                r"\b(?:tcpdump|ngrep)\b|http_session_inventory|pcap_identity_timeline",
                e["cmd"], re.IGNORECASE,
            )
            for e in entries
        )
        has_pcap_identity_closure = any(
            (
                e.get("type") == "tool_call"
                and isinstance(e.get("cmd"), str)
                and re.search(
                    r"http_session_inventory|pcap_identity_timeline",
                    e["cmd"], re.IGNORECASE,
                )
            )
            or (
                e.get("type") == "finding"
                and re.search(
                    r"net\.http_session_inventory|net\.pcap_identity_timeline",
                    e.get("source") or "", re.IGNORECASE,
                )
            )
            for e in entries
        )
        has_knowns_sweep = any(
            isinstance(e.get(f), str)
            and re.search(r"knowns_pattern_generate|roster", e.get(f), re.IGNORECASE)
            for e in entries
            for f in ("cmd", "description", "content", "conclusion")
        )
        _LOGON_TOOL_RE = re.compile(
            r"(?:evtxecmd|chainsaw|evtx_filter|evtx_dump"
            r"|\b4624\b|\b4625\b|\b4778\b|\b4779\b"
            r"|\blast\b|wtmp|utmp|lastlog|\bwho\b)", re.IGNORECASE,
        )
        has_logon_enum = any(
            e.get("type") == "tool_call" and isinstance(e.get("cmd"), str)
            and _LOGON_TOOL_RE.search(e["cmd"])
            for e in entries
        )
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

        # #6 (blocking) — attribution closure (ii): every previously-unseen
        # identity for which a controller question was opened, or which DAIR
        # surfaced as a forced principal candidate, must be dispositioned:
        # attributed-with-session, excluded-with-evidence, or parked
        # controller-unknown. Focus harvesting is restricted to controller
        # questions so an ordinary subject mention is not harvested.
        surfaced: set[str] = set()
        for e in entries:
            if e.get("type") != "dair_call":
                continue
            focus = e.get("investigation_focus") or ""
            if re.search(r"controls principal|who controls", focus, re.IGNORECASE):
                surfaced |= _extract_principal_tokens(focus, require_cue=False)
            for pivot in e.get("candidate_pivots") or []:
                if not isinstance(pivot, dict):
                    continue
                if str(pivot.get("kind") or "").lower() != "principal":
                    continue
                if str(pivot.get("cue") or "").lower() != "forced":
                    continue
                value = str(pivot.get("value") or "")
                surfaced |= _extract_principal_tokens(
                    f"who controls principal {value}", require_cue=False)
        surfaced = {p for p in surfaced
                    if not p.startswith("RID") and not p.startswith("S-1-")}
        for p in sorted(surfaced):
            dispositioned = False
            for e in s_findings:
                d = e.get("description") or ""
                if p.lower() not in d.lower():
                    continue
                if _ftier(e) in {"CONFIRMED", "LIKELY"} and _SESSION_RE.search(d):
                    dispositioned = True
                    break
                if (re.search(r"\b(?:excluded|ruled out|not the (?:actor|operator)"
                              r"|did not (?:log|authenticate))\b", d, re.IGNORECASE)
                        and _SESSION_RE.search(d)):
                    dispositioned = True
                    break
                if re.search(r"(?:controll?er|who controls)[^.\n]*\b(?:unknown"
                             r"|unidentified|not established|unestablished)\b"
                             r"|\bunattributed\b", d, re.IGNORECASE):
                    dispositioned = True
                    break
            if not dispositioned:
                issues.append(
                    f"Previously-unseen identity '{p}' surfaced during the "
                    f"investigation (a controller question was opened or DAIR "
                    f"surfaced a forced principal candidate) but no finding "
                    f"dispositions it: not attributed-with-session, not "
                    f"excluded-with-evidence, and not parked "
                    f"controller-unknown. Disposition '{p}' before Report."
                )
    except Exception as _e:
        import sys as _sys
        print(f"[TRUDI WARN] structural-integrity check failed: {_e}",
              file=_sys.stderr)

    ready = len(issues) == 0

    # Persist ready_to_report as a reason_call trace entry so downstream gates
    # (misc.export_execution_log) can read the verdict from the audit log
    # instead of relying on the agent re-narrating the result. The conclusion
    # leads with a parseable marker so the gate's regex is trivial.
    conclusion = (
        f"READY_TO_REPORT: {'true' if ready else 'false'}\n"
        f"BLOCKING_ISSUES ({len(issues)}): {'; '.join(issues) if issues else 'none'}\n"
        f"WARNINGS ({len(warnings)}): {'; '.join(warnings) if warnings else 'none'}"
    )
    try:
        # Auto-derive lineage: the pre-report check by nature reads the entire
        # trace, so its upstream lineage is "every finding + every synthesize".
        synthesized_cids = [
            e.get("call_id") for e in entries
            if e.get("call_id") and (
                e.get("type") == "finding"
                or (e.get("type") == "reason_call" and e.get("tool") == "reason_synthesize")
            )
        ]
        log.record_reason_call(
            tool="reason_pre_report_check",
            success=True,
            conclusion=conclusion,
            directives={},
            input_call_ids=synthesized_cids or None,
        )
    except Exception as _e:
        import sys as _sys
        print(f"[TRUDI WARN] pre_report_check trace write failed: {_e}", file=_sys.stderr)

    return {
        "ready_to_report": ready,
        "blocking_issues": issues,
        "warnings": warnings,
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
