"""Slim tool descriptions for schema-eager clients (core/slim_descriptions.py)."""
import asyncio
import json

import pytest

from core.slim_descriptions import CAP, OVERRIDES, slim_text, slim_tool_descriptions


class TestSlimText:
    def test_short_first_paragraph_kept_verbatim(self):
        assert slim_text("Run a tool.\n\nLong details here.") == "Run a tool."

    def test_whitespace_collapsed(self):
        assert slim_text("Run a\n    tool  now.") == "Run a tool now."

    def test_long_paragraph_capped_at_sentence(self):
        d = ("First sentence about the tool. " * 20)
        out = slim_text(d)
        assert len(out) <= CAP
        assert out.endswith(".")

    def test_hard_cut_gets_ellipsis(self):
        d = "x" * 800  # no sentence boundary at all
        out = slim_text(d)
        assert len(out) <= CAP + 1
        assert out.endswith("…")


@pytest.fixture
def server_mcp():
    import server
    return server


class TestSlimPass:
    def test_all_descriptions_capped_and_schemas_untouched(self, server_mcp):
        async def run():
            before = {t.name: json.dumps(getattr(t, "inputSchema", None) or {},
                                         sort_keys=True)
                      for t in await server_mcp.mcp.list_tools()}
            changed = await slim_tool_descriptions(server_mcp.NAMESPACES)
            assert changed > 100  # the bulk of 277 tools have long docstrings
            total = 0
            for t in await server_mcp.mcp.list_tools():
                desc = t.description or ""
                if t.name in OVERRIDES:
                    assert desc == OVERRIDES[t.name]
                else:
                    assert len(desc) <= CAP + 1, t.name
                assert "\n\n" not in desc, t.name
                total += len(desc)
                schema = json.dumps(getattr(t, "inputSchema", None) or {},
                                    sort_keys=True)
                assert schema == before[t.name], f"schema mutated: {t.name}"
            # budget regression bar: measured post-slim mass is ~8.1k tokens
            # (down from ~18.7k). Bar at 8.5k so docstring growth can't
            # silently re-bloat schema-eager clients.
            assert total / 4 < 8500, f"description mass regressed: ~{total//4} tokens"
        asyncio.run(run())

    def test_overrides_target_existing_tools(self, server_mcp):
        async def run():
            names = {t.name for t in await server_mcp.mcp.list_tools()}
            for k in OVERRIDES:
                assert k in names, f"OVERRIDES names unknown tool {k}"
        asyncio.run(run())

    def test_idempotent(self, server_mcp):
        async def run():
            await slim_tool_descriptions(server_mcp.NAMESPACES)
            snap = {t.name: t.description
                    for t in await server_mcp.mcp.list_tools()}
            changed = await slim_tool_descriptions(server_mcp.NAMESPACES)
            assert changed == 0
            assert snap == {t.name: t.description
                            for t in await server_mcp.mcp.list_tools()}
        asyncio.run(run())
