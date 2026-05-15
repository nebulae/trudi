"""Adversarial reasoning — swappable backend (Claude API or any OpenAI-compatible endpoint)."""
import os
import re
import json
from fastmcp import FastMCP

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
}

_DIRECTIVES_INSTRUCTION = """\

Output the DIRECTIVES block FIRST — before your analysis. \
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
Replace the example values with your actual recommendations, \
then write your full analysis after. \
Tool names must use TRUDI MCP format: namespace.tool \
(e.g. vol.psscan, vol.cmdline, vol.netscan, vol.dlllist, vol.malfind, \
ez.amcacheparser, ez.appcompatcacheparser, ez.mftecmd, ez.evtxecmd, \
tsk.fls, tsk.icat, misc.regripper_hive, misc.evtx_dump, \
enrich.vt_lookup_hash, enrich.vt_lookup_ip). \
Do not invent tool names outside this list."""


_EVIDENCE_AUDIT_INSTRUCTION = """\

Output the EVIDENCE_AUDIT block FIRST — before your analysis, after DIRECTIVES. \
List each major claim in the finding:
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
    """Extract the DIRECTIVES JSON block from model output. Returns {} on any failure."""
    if not text:
        return {}
    match = re.search(
        r"\*{0,2}DIRECTIVES\*{0,2}\s*:?\*{0,2}\s*(?:```json\s*)?(\{.*?\})\s*(?:```)?",
        text,
        re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return {}
    raw = match.group(1)
    raw = re.sub(r"\s*//[^\n]*", "", raw)  # strip // comments
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {}


def _cap_lines(text: str, max_lines: int) -> str:
    """Trim text to max_lines, appending a note if trimmed."""
    lines = text.splitlines(keepends=True)
    if len(lines) <= max_lines:
        return text
    omitted = len(lines) - max_lines
    return "".join(lines[:max_lines]) + f"\n[... {omitted} lines omitted for brevity]\n"


# ── Backend implementations ───────────────────────────────────────────────────

def _ask_claude(system: str, user: str, max_tokens: int, _tool_name: str) -> dict:
    """Call the Anthropic Claude API with prompt caching on the system prompt."""
    import anthropic
    _empty = {"success": False, "conclusion": "", "directives": {}}

    if not ANTHROPIC_API_KEY:
        result = {**_empty, "error": "ANTHROPIC_API_KEY not set — add it to .env"}
        _log_reason(_tool_name, result)
        return result

    model = REASON_MODEL or _DEFAULT_CLAUDE_MODEL
    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
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
        result = {"success": True, "conclusion": conclusion, "directives": directives,
                  "evidence_audit": evidence_audit}
        _log_reason(_tool_name, result)
        return result
    except Exception as e:
        result = {**_empty, "error": str(e)}
        _log_reason(_tool_name, result)
        return result


def _ask_openai_compat(system: str, user: str, max_tokens: int, _tool_name: str) -> dict:
    """Call any OpenAI-compatible endpoint (OpenAI, Foundation-Sec vLLM, Ollama, etc.)."""
    import httpx
    _empty = {"success": False, "conclusion": "", "directives": {}}

    if not REASON_URL:
        result = {**_empty, "error": "REASON_URL not set for openai-compat backend"}
        _log_reason(_tool_name, result)
        return result

    model = REASON_MODEL or _DEFAULT_COMPAT_MODEL
    headers = {"Authorization": f"Bearer {REASON_API_KEY}"} if REASON_API_KEY else {}
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
            timeout=120,
        )
        resp.raise_for_status()
        choice = resp.json()["choices"][0]["message"]
        raw = choice.get("content") or choice.get("reasoning") or ""
        if not raw:
            result = {**_empty, "error": "Model returned empty response"}
            _log_reason(_tool_name, result)
            return result
        evidence_audit = _parse_evidence_audit(raw)
        directives = _parse_directives(raw)
        conclusion = _strip_evidence_audit(_strip_directives(raw))
        result = {"success": True, "conclusion": conclusion, "directives": directives,
                  "evidence_audit": evidence_audit}
        _log_reason(_tool_name, result)
        return result
    except Exception as e:
        result = {**_empty, "error": str(e)}
        _log_reason(_tool_name, result)
        return result


def _ask(system: str, user: str, max_tokens: int = 2048, _tool_name: str = "") -> dict:
    """Dispatch to the active reasoning backend."""
    backend = _active_backend()
    if backend == "claude":
        return _ask_claude(system, user, max_tokens, _tool_name)
    return _ask_openai_compat(system, user, max_tokens, _tool_name)


def _log_reason(tool_name: str, result: dict) -> None:
    try:
        from core.execution_log import log
        log.record_reason_call(
            tool=tool_name,
            success=result.get("success", False),
            conclusion=result.get("conclusion", ""),
            directives=result.get("directives", {}),
            evidence_audit=result.get("evidence_audit"),
        )
    except Exception:
        pass


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
    "first 3-5 concrete tool calls the investigator should run, in order."
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
    "tools that would most efficiently confirm or rule out the top hypothesis, and "
    "next_hypothesis_triggers with conditions that should prompt re-evaluation."
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
    "4. OVERCLAIMED MECHANISMS — technical explanations that aren't supported "
    "by cited evidence (e.g. YARA hit stated as 'confirmed execution')\n"
    "5. MISSING INVESTIGATION — what should have been checked but wasn't\n\n"
    "Return a structured punch list. Mark BLOCKERS (must fix before report is "
    "written) separately from ADVISORIES (should note, not blocking)."
    + _DIRECTIVES_INSTRUCTION
)


# ── MCP tools ─────────────────────────────────────────────────────────────────

@mcp.tool()
def reason_plan(case_description: str, evidence_available: str) -> dict:
    """
    Generate a prioritized investigation plan before deep forensic tool runs.
    Call this after the fast pre-enumeration block (SYSTEM hive, SAM hive,
    SOFTWARE hive, memory stat) so the plan is grounded in real evidence data.

    case_description: incident description — host, timeframe, known suspicion
    evidence_available: concatenated output from the pre-enumeration tools
    """
    capped = _cap_lines(evidence_available, 300)
    user = f"CASE:\n{case_description}\n\nEVIDENCE AVAILABLE:\n{capped}"
    return _ask(_PLAN_SYS, user, max_tokens=2048, _tool_name="reason_plan")


@mcp.tool()
def reason_hypothesize(observation: str, context: str = "") -> dict:
    """
    Generate ranked alternative hypotheses for a forensic observation before
    committing to an interpretation. Call this when a finding has multiple
    plausible explanations — malicious and benign.

    observation: the raw forensic artifact or behaviour (e.g. "cmd.exe PID 5024
                 spawned from orphaned PPID 2748 in Session 0 at 17:15 UTC")
    context: any relevant case context (OS, known attacker TTPs, timeline)
    """
    user = f"OBSERVATION:\n{observation}"
    if context:
        user += f"\n\nCASE CONTEXT:\n{context}"
    return _ask(_HYPOTHESIZE_SYS, user, max_tokens=1024, _tool_name="reason_hypothesize")


@mcp.tool()
def reason_evaluate_finding(
    finding: str,
    supporting_evidence: str,
    case_context: str = "",
) -> dict:
    """
    Adversarially challenge a specific conclusion before it goes into the report.
    Returns verdict (SUPPORTED / CHALLENGED / UNCERTAIN), identified weaknesses,
    and what additional evidence would resolve uncertainty.

    finding: the specific conclusion being made
    supporting_evidence: the artifacts and tool output that support it
    case_context: broader investigation context
    """
    user = f"FINDING:\n{finding}\n\nSUPPORTING EVIDENCE:\n{supporting_evidence}"
    if case_context:
        user += f"\n\nCASE CONTEXT:\n{case_context}"
    return _ask(_EVALUATE_SYS, user, max_tokens=2048, _tool_name="reason_evaluate_finding")


@mcp.tool()
def reason_synthesize(findings: str, investigation_summary: str = "") -> dict:
    """
    Cross-finding consistency and completeness check. Call this before writing
    the final report. Identifies logical gaps, contradictions, overclaimed
    conclusions, and missing investigation steps.

    findings: newline-separated list of confirmed findings
    investigation_summary: brief summary of tools run and scope covered
    """
    user = f"FINDINGS:\n{findings}"
    if investigation_summary:
        user += f"\n\nINVESTIGATION COVERAGE:\n{investigation_summary}"
    return _ask(_SYNTHESIZE_SYS, user, max_tokens=2048, _tool_name="reason_synthesize")
