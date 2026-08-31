"""Pilot Phase-0 spike: command parsing and schema-driven completion."""
import asyncio

import pytest

from pilot.spike import (
    PilotCompleter, build_alias_map, dotted_to_wire, parse_command,
    wire_to_dotted,
)


class TestNames:
    def test_dotted_wire_round_trip(self):
        assert dotted_to_wire("ez.mftecmd") == "ez_mftecmd"
        assert wire_to_dotted("ez_mftecmd") == "ez.mftecmd"
        assert wire_to_dotted("ez_recmd_hive") == "ez.recmd_hive"
        assert dotted_to_wire("ez_mftecmd") == "ez_mftecmd"  # pass-through


class TestParse:
    def test_json_values_parse_strings_survive(self):
        tool, args = parse_command(
            'tsk.fls image=/e/x.E01 offset_sectors=63 recursive=true tags=[1,2]')
        assert tool == "tsk_fls"
        assert args == {"image": "/e/x.E01", "offset_sectors": 63,
                        "recursive": True, "tags": [1, 2]}

    def test_quoted_strings(self):
        _, args = parse_command('net.ngrep_search pattern="jean alison"')
        assert args["pattern"] == "jean alison"

    def test_errors(self):
        with pytest.raises(ValueError):
            parse_command("")
        with pytest.raises(ValueError):
            parse_command("tsk.fls not-a-kv")


@pytest.fixture(scope="module")
def live_completer():
    from fastmcp import Client
    import server

    async def build():
        async with Client(server.mcp) as c:
            return PilotCompleter(await c.list_tools(), build_alias_map())
    return asyncio.run(build())


class TestCompletion:
    def test_tool_prefix(self, live_completer):
        hits = live_completer.complete_first("ez.m")
        assert "ez.mftecmd" in hits and all(h.startswith("ez.m") for h in hits)

    def test_binary_alias_offers_wrapper(self, live_completer):
        assert any("tsk.fls" in h for h in live_completer.complete_first("fls"))
        assert any("ez.mftecmd" in h for h in live_completer.complete_first("mftecmd"))

    def test_param_completion_excludes_used(self, live_completer):
        assert "offset_sectors=" in live_completer.complete_param("tsk.fls", "o", set())
        assert live_completer.complete_param("tsk.fls", "o", {"offset_sectors"}) == []

    def test_prompt_toolkit_async_path(self, live_completer):
        """prompt_toolkit's async completer calls get_completions_async from
        the Completer base class — a duck-typed completer crashes on first
        Tab (observed live). Exercise the real async path."""
        from prompt_toolkit.completion import CompleteEvent
        from prompt_toolkit.document import Document

        async def hits(text):
            doc = Document(text, len(text))
            return [x.text async for x in
                    live_completer.get_completions_async(doc, CompleteEvent())]

        assert "ez.mftecmd" in asyncio.run(hits("ez.m"))
        assert "tsk.fls" in asyncio.run(hits("fls"))
        assert "offset_sectors=" in asyncio.run(hits("tsk.fls image=/x o"))

    def test_every_alias_targets_a_mounted_tool(self, live_completer):
        for alias, dotted in live_completer.aliases.items():
            base = dotted.rstrip("*")
            assert any(d.startswith(base) for d in live_completer.dotted), \
                f"alias {alias} -> {dotted} matches no mounted tool"
