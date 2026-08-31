"""Dedupe doubled wire names at mount time.

Some tool modules bake their namespace into their function names
(``tsk_mmls`` in the ``tsk`` module, ``vol_pslist`` in ``vol``, ``read_output``
in ``read``); mounting them under that same namespace produced stuttered wire
names — ``tsk_tsk_mmls``, ``vol_vol_pslist``, ``read_read_output``. That was
cosmetic while an LLM drove, but pilot mode makes tool names a human typing
surface, and the deny-hint deny-loop (e3617ee) showed even models navigate by
name. This pass renames the CHILD tool objects — stripping one redundant
leading ``<ns>_`` — so every mounted name is ``<ns>_<tool>`` exactly once.

Python function names are untouched: only the FastMCP Tool registration name
changes, at a single choke point, before the server accepts a call.
``tools/_fk.py:normalize_tool_name`` (idempotent) still collapses doubled
names read from OLD traces, so replays and recorded cases keep working.
"""
from __future__ import annotations


async def normalize_tool_names(namespaces) -> int:
    """Strip one redundant ``<ns>_`` prefix from each child tool's name.

    ``namespaces`` is server.NAMESPACES: (namespace, child FastMCP) pairs.
    Mutation targets the CHILD servers (the composed parent's get_tool
    returns copies for mounted tools; mounting resolves names dynamically,
    so renaming works whether called before or after mount). Returns the
    number of tools renamed. Defensive: never renames to an empty string or
    onto an existing sibling name.
    """
    renamed = 0
    for ns, child in namespaces:
        prefix = ns + "_"
        tools = await child.list_tools()
        names = {t.name for t in tools}
        for t in tools:
            if not t.name.startswith(prefix):
                continue
            new = t.name[len(prefix):]
            if not new or new in names:
                continue
            live = await child.get_tool(t.name)
            child.local_provider.remove_tool(t.name)
            live.name = new
            child.add_tool(live)
            names.discard(t.name)
            names.add(new)
            renamed += 1
    return renamed
