"""FastMCP middleware: auto-log agent narration passed as _note= on any tool call."""
from fastmcp.server.middleware import Middleware, MiddlewareContext
from mcp import types as mt

_SKIP_TOOLS = frozenset({"misc_record_agent_message", "misc_start_execution_log"})


class NarrationMiddleware(Middleware):
    """Extract _note from tool arguments and log it as an agent_message.

    Claude passes _note="narration text" on any tool call. The middleware
    logs it to the execution trace before the tool runs, then strips _note
    so the underlying tool never sees the unexpected argument.
    """

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next,
    ):
        args = dict(context.message.arguments or {})
        note = args.pop("_note", None)

        if note and context.message.name not in _SKIP_TOOLS:
            try:
                from core.execution_log import log
                log.record_agent_message(str(note))
            except Exception:
                pass  # never block a tool call over a logging failure

        if "_note" in (context.message.arguments or {}):
            new_message = context.message.model_copy(update={"arguments": args})
            context = context.copy(message=new_message)

        return await call_next(context)
