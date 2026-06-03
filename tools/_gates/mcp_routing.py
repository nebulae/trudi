"""Gate: linked_call_id must not point at a raw-bash forensic-binary call.

Forensic execution must flow through the typed MCP wrapper so the
architectural-guardrail story holds. A finding citing a `claude_code_bash`
entry that executes vol/fls/icat/etc. is refused with the wrapper hint.
"""
from typing import Optional


def check(ctx) -> Optional[dict]:
    if ctx.linked_call_id == 0:
        return None
    linked_entry = ctx.idx.by_call_id.get(ctx.linked_call_id)
    if linked_entry is None:
        return None  # let linked_call_id_must_exist handle it
    if linked_entry.get("source") != "claude_code_bash":
        return None
    from core.middleware import _identify_forensic_binary, MCP_WRAPPER_HINTS
    bin_key = _identify_forensic_binary(linked_entry.get("cmd", "") or "")
    if bin_key is None:
        return None
    wrapper_hint = MCP_WRAPPER_HINTS.get(bin_key, "the corresponding MCP wrapper")
    bin_display = bin_key or "forensic binary"
    return {
        "success": False,
        "error": (
            f"MCP routing required: linked_call_id={ctx.linked_call_id} "
            f"executed {bin_display!r} via raw Bash (source='claude_code_bash'). "
            f"Re-run the operation via {wrapper_hint} and record the finding "
            f"with that MCP call's _trudi_call_id. "
            f"Architectural-guardrail compliance requires forensic execution "
            f"to flow through the typed MCP surface."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "mcp_routing",
        "offending_cmd_excerpt": (linked_entry.get("cmd") or "")[:200],
        "suggested_wrapper": wrapper_hint,
    }
