"""Slim MCP tool descriptions for schema-eager clients (OpenCode).

OpenCode renders every tool's full schema into every model request; TRUDI's
docstrings double as agent documentation, so the raw description mass is
~18.7k tokens across 277 tools. This pass — enabled by
TRUDI_SLIM_TOOL_DESCRIPTIONS=1, set per-client by the OpenCode registrar —
rewrites each tool's description to its first paragraph, capped, while leaving
the TYPED PARAMETER SCHEMAS untouched (they are the guardrail, and cheap).

Safe because the orchestrator (CLAUDE.md / AGENTS.md) already teaches tool
usage and every gate refusal names the missing field and its remediation at
runtime. Contract-critical tools keep a curated summary via OVERRIDES instead
of a blind truncation.

Claude Code is unaffected: it defers schema loading, so the full docstrings
stay its at-hand reference and the env is never set for it.
"""
from __future__ import annotations

import re

ENV_FLAG = "TRUDI_SLIM_TOOL_DESCRIPTIONS"
CAP = 300  # chars, applied after first-paragraph extraction

# Curated summaries for the contract-critical tools whose one-line form would
# lose load-bearing structure. Keys are the MOUNTED tool names.
OVERRIDES: dict[str, str] = {
    "misc_record_finding": (
        "Record a structured finding in the trace. Requires linked_call_id (the "
        "_trudi_call_id of the source tool call), input_call_ids lineage, and a "
        "typed claim: claim_kind, category, act, plus conditional fields "
        "(channel/transfer_call_ids for egress; principal/session_binding_call_ids "
        "for attribution; recipients/receipt_call_ids for delivery; window/scope "
        "for negatives). CONFIRMED/LIKELY additionally need a SUPPORTED "
        "reason.evaluate_finding for the same typed claim, and the tier must be "
        "reachable from the cited artifact classes (gate: tier_contract)."
    ),
    "dair_assess": (
        "DAIR phase director — call after every tool batch with "
        "tool_results_summary, phase_stack (JSON), case_context, and "
        "input_call_ids. Returns directives (priority_tools = the binding work "
        "order, curiosity_budget) and phase transitions. Declare observed_hosts / "
        "observed_principals (typed) so candidate pivots are diffed structurally; "
        "declare the case_question typed on first Triage."
    ),
    "reason_evaluate_finding": (
        "Adversarial fact-check before recording a CONFIRMED/LIKELY finding. "
        "Pass finding, supporting_evidence (tool output: command + field + "
        "value), input_call_ids citing the extractor runs, and the SAME typed "
        "claim you will record (claim_kind, category, act, entities, principal, "
        "channel). Verdict: SUPPORTED / CONTRADICTED (sticky CHALLENGED) / "
        "UNVERIFIABLE."
    ),
    "misc_record_agent_message": (
        "Log narration/reasoning to the trace. Not for stating facts — "
        "conclusions need misc.record_finding, or pass findings=[...] here to "
        "record them atomically with the narration. Requires input_call_ids."
    ),
    "reason_hypothesize": (
        "Generate competing hypotheses for an observation (hypothesis_kind: "
        "case_question at Triage start, distinct_principal for any new "
        "account/identity, mechanism, coverage_gap). Capture each hypothesis_id "
        "and route resolving findings back via tested_hypothesis_id. Requires "
        "input_call_ids."
    ),
}

_WS = re.compile(r"\s+")


def slim_text(desc: str, cap: int = CAP) -> str:
    """First paragraph, whitespace-collapsed, sentence-aware cap."""
    para = desc.split("\n\n", 1)[0]
    para = _WS.sub(" ", para).strip()
    if len(para) <= cap:
        return para
    cut = para[:cap]
    # prefer ending at the last full sentence inside the cap
    m = max(cut.rfind(". "), cut.rfind(".\t"), cut.rfind(".") if cut.endswith(".") else -1)
    if m >= 40:
        return cut[: m + 1]
    return cut.rstrip() + "…"


async def slim_tool_descriptions(namespaces, cap: int = CAP,
                                 overrides: dict[str, str] | None = None) -> int:
    """Rewrite every tool's description in place. Returns tools changed.

    `namespaces` is server.NAMESPACES: (namespace, child FastMCP) pairs. The
    mutation MUST happen on the child servers — the composed parent's
    get_tool() returns copies for mounted tools, so a parent-level rewrite
    does not survive to list_tools(). OVERRIDES keys use the mounted name
    (f"{namespace}_{child tool name}"). Parameter schemas are never touched;
    empty descriptions stay empty.
    """
    if overrides is None:
        overrides = OVERRIDES
    changed = 0
    for ns, child in namespaces:
        for t in await child.list_tools():
            live = await child.get_tool(t.name)
            desc = live.description or ""
            if not desc:
                continue
            mounted = f"{ns}_{t.name}"
            new = overrides.get(mounted) or slim_text(desc, cap)
            if new != desc:
                live.description = new
                changed += 1
    return changed
