"""Tests for NarrationMiddleware._note extraction and logging."""
import pytest
from unittest.mock import patch, MagicMock, AsyncMock


@pytest.fixture
def mock_context():
    from mcp import types as mt
    msg = MagicMock(spec=mt.CallToolRequestParams)
    msg.name = "_note_test_tool"
    msg.arguments = {}
    msg.model_copy = lambda update=None: MagicMock(
        name=msg.name,
        arguments=(update or {}).get("arguments", {}),
    )
    ctx = MagicMock()
    ctx.message = msg
    ctx.copy = lambda **kw: MagicMock(message=kw.get("message", msg))
    return ctx


@pytest.mark.asyncio
async def test_note_extracted_and_logged(mock_context):
    mock_context.message.arguments = {"file_path": "/foo.bin", "_note": "my narration"}
    call_next = AsyncMock(return_value="tool_result")
    with patch("core.execution_log.log") as mock_log:
        from core.middleware import NarrationMiddleware
        await NarrationMiddleware().on_call_tool(mock_context, call_next)
    mock_log.record_agent_message.assert_called_once_with("my narration")


@pytest.mark.asyncio
async def test_note_stripped_before_tool_sees_it(mock_context):
    mock_context.message.arguments = {"pid": 1234, "_note": "narration"}
    captured = {}

    async def capture(ctx):
        captured["args"] = ctx.message.arguments
        return "ok"

    with patch("core.execution_log.log"):
        from core.middleware import NarrationMiddleware
        await NarrationMiddleware().on_call_tool(mock_context, capture)
    assert "_note" not in (captured.get("args") or {})


@pytest.mark.asyncio
async def test_no_note_passes_through(mock_context):
    mock_context.message.arguments = {"pid": 5678}
    call_next = AsyncMock(return_value="ok")
    with patch("core.execution_log.log") as mock_log:
        from core.middleware import NarrationMiddleware
        await NarrationMiddleware().on_call_tool(mock_context, call_next)
    mock_log.record_agent_message.assert_not_called()


@pytest.mark.asyncio
async def test_record_agent_message_tool_skipped(mock_context):
    mock_context.message.name = "misc_record_agent_message"
    mock_context.message.arguments = {"content": "x", "_note": "should not double-log"}
    call_next = AsyncMock(return_value="ok")
    with patch("core.execution_log.log") as mock_log:
        from core.middleware import NarrationMiddleware
        await NarrationMiddleware().on_call_tool(mock_context, call_next)
    mock_log.record_agent_message.assert_not_called()
