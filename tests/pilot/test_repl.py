"""Pilot Phase-0 spike: command parsing and schema-driven completion."""
import asyncio

import pytest

from pilot.repl import (
    PilotCompleter, build_alias_map, complete_path, dotted_to_wire,
    parse_command, shell_guard, wire_to_dotted,
)


class TestShellGuard:
    def test_forensic_binaries_denied_with_hint(self):
        msg = shell_guard("fls -r /e/disk.E01")
        assert msg and "tsk.fls" in msg
        assert shell_guard("tcpdump -r x.pcap") is not None

    def test_navigation_allowed(self):
        for cmd in ("ls -la evidence/", "tree analysis", "du -sh .",
                    "wc -l notes.txt"):
            assert shell_guard(cmd) is None


class TestPathCompletion:
    def test_dirs_get_slash_and_hidden_skipped(self, tmp_path, monkeypatch):
        (tmp_path / "evidence").mkdir()
        (tmp_path / "report.txt").write_text("x")
        (tmp_path / ".hidden").write_text("x")
        monkeypatch.chdir(tmp_path)
        assert complete_path("") == ["evidence/", "report.txt"]
        assert complete_path("e") == ["evidence/"]
        assert complete_path(".hid") == [".hidden"]

    def test_bad_dir_is_empty_not_error(self):
        assert complete_path("/no/such/dir/x") == []


class TestPrefill:
    SCHEMAS = {
        "net_tcpdump_read": {
            "properties": {"pcap_path": {"type": "string"},
                           "packet_count": {"type": "integer", "default": 100}},
            "required": ["pcap_path"]},
        "tsk_fls": {
            "properties": {"image": {"type": "string"},
                           "offset_sectors": {"type": "integer"}},
            "required": ["image"]},
        "reason_plan": {
            "properties": {"case_description": {"type": "string"}},
            "required": ["case_description"]},
    }
    EVIDENCE = ["/e/case dir/nitroba.pcap", "/e/disk.E01"]

    def test_bare_tool_gets_required_args_with_guesses(self):
        from pilot.repl import prefill_command
        line = prefill_command("net.tcpdump_read", self.SCHEMAS, self.EVIDENCE)
        # pcap param prefers the .pcap evidence; spaces get quoted
        assert line == 'net.tcpdump_read pcap_path="/e/case dir/nitroba.pcap"'
        assert prefill_command("tsk.fls", self.SCHEMAS, self.EVIDENCE) == \
            "tsk.fls image=/e/disk.E01"

    def test_unguessable_required_left_empty(self):
        from pilot.repl import prefill_command
        assert prefill_command("reason.plan", self.SCHEMAS, self.EVIDENCE) == \
            "reason.plan case_description="

    def test_suggestion_with_args_and_unknown_tool_verbatim(self):
        from pilot.repl import prefill_command
        ritual = 'reason.hypothesize observation="q" hypothesis_kind=case_question'
        assert prefill_command(ritual, self.SCHEMAS, self.EVIDENCE) == ritual
        assert prefill_command("ez.evtxecmd Security 4624",
                               self.SCHEMAS, self.EVIDENCE) == \
            "ez.evtxecmd Security 4624"
        assert prefill_command("no.such_tool", self.SCHEMAS, self.EVIDENCE) == \
            "no.such_tool"

    def test_cli_style_suggestion_rebuilt_from_schema(self):
        """DAIR/reason suggestions arrive CLI-shaped with placeholder paths
        (observed live: net.ngrep_search -p 'Cookie:|user=' /path/to/x.pcap).
        They must be rebuilt into our syntax with real values."""
        from pilot.repl import prefill_command
        schemas = {
            "net_ngrep_search": {
                "properties": {"pcap_path": {"type": "string"},
                               "pattern": {"type": "string"}},
                "required": ["pcap_path", "pattern"]},
            **self.SCHEMAS,
        }
        line = prefill_command(
            "net.ngrep_search -p 'Cookie:|user=|login' /path/to/suspicious.pcap",
            schemas, self.EVIDENCE)
        assert line == ('net.ngrep_search pcap_path="/e/case dir/nitroba.pcap" '
                        'pattern="Cookie:|user=|login"')
        # flags + placeholder path with no quoted pattern: rebuilt clean
        assert prefill_command("tsk.fls -r -m /mnt/disk_image",
                               schemas, self.EVIDENCE) == \
            "tsk.fls image=/e/disk.E01"

    def test_schema_default_wins_over_evidence(self):
        from pilot.repl import guess_value
        assert guess_value("pcap_path", {"default": "/x.pcap"},
                           self.EVIDENCE) == "/x.pcap"

    def test_missing_required_reports_empty_and_absent(self):
        from pilot.repl import missing_required
        assert missing_required("tsk_fls", {}, self.SCHEMAS) == ["image(string)"]
        assert missing_required("tsk_fls", {"image": ""}, self.SCHEMAS) == \
            ["image(string)"]
        assert missing_required("tsk_fls", {"image": "/e/disk.E01"},
                                self.SCHEMAS) == []


class TestTaskDrafting:
    def test_briefs_rank_by_task_overlap(self, live_completer):
        # need the raw tools list, not the completer — build from the server
        import asyncio as _a
        from fastmcp import Client
        import server
        from pilot.repl import build_tool_briefs

        async def get_tools():
            async with Client(server.mcp) as c:
                return await c.list_tools()
        tools = _a.run(get_tools())
        briefs = build_tool_briefs(
            "extract all the columns from evidence.csv", tools)
        assert "read.output" in briefs          # the csv tool ranks in
        assert briefs.count("\n  params") <= 12
        assert "*" in briefs                    # required params marked

    def test_validate_candidates_drops_broken(self):
        from pilot.repl import validate_candidates
        schema_map = {"read_output": {}, "tsk_fls": {}}
        cands = [
            {"command": "read.output path=x.csv", "why": "ok"},
            {"command": "no.such_tool a=1", "why": "invented"},
            {"command": "tsk.fls bad token", "why": "unparseable"},
        ]
        assert [c["why"] for c in validate_candidates(cands, schema_map)] == ["ok"]


class TestCallProgress:
    class _SlowClient:
        def __init__(self, delay, result=None, exc=None):
            self.delay, self.result, self.exc = delay, result, exc

        async def call_tool(self, tool, args):
            await asyncio.sleep(self.delay)
            if self.exc:
                raise self.exc
            return self.result

    def test_fast_call_prints_nothing(self, capsys):
        from pilot.repl import call_with_progress
        c = self._SlowClient(0.0, result="ok")
        out = asyncio.run(call_with_progress(c, "t", {}, tick=0.2))
        assert out == "ok"
        assert capsys.readouterr().out == ""

    def test_slow_call_ticks_elapsed(self, capsys):
        from pilot.repl import call_with_progress
        c = self._SlowClient(0.35, result="ok")
        out = asyncio.run(call_with_progress(c, "dair_assess", {},
                                             label="dair.assess", tick=0.1))
        assert out == "ok"
        printed = capsys.readouterr().out
        assert "dair.assess running" in printed and "ctrl+c cancels" in printed

    def test_exception_propagates(self):
        from pilot.repl import call_with_progress
        c = self._SlowClient(0.0, exc=RuntimeError("boom"))
        with pytest.raises(RuntimeError):
            asyncio.run(call_with_progress(c, "t", {}, tick=0.2))


class TestLookAndFeel:
    def test_enter_with_selected_completion_accepts_not_submits(self):
        """The reported glitch: Enter mid-menu executed the half-finished
        command. The binding must fire only when a completion is selected,
        and must clear complete_state (accept) instead of submitting."""
        from prompt_toolkit.filters import Condition
        from pilot.repl import make_key_bindings

        kb = make_key_bindings()
        [binding] = kb.bindings
        assert [k.value if hasattr(k, "value") else k for k in binding.keys] \
            == ["c-m"]  # enter

        class Buf:
            complete_state = object()
            called = False

            def validate_and_handle(self):
                self.called = True

        class Event:
            current_buffer = Buf()

        binding.handler(Event())
        assert Event.current_buffer.complete_state is None
        assert Event.current_buffer.called is False  # did NOT submit

    def test_classify_line_mcp_command(self):
        from pilot.repl import classify_line
        frags = classify_line("ez.mftecmd file=/x/$MFT csv=analysis/")
        assert ("class:ns", "ez") in frags
        assert ("class:tool", "mftecmd") in frags
        assert ("class:key", "file") in frags and ("class:key", "csv") in frags
        assert "".join(t for _, t in frags) == "ez.mftecmd file=/x/$MFT csv=analysis/"

    def test_classify_line_shell_and_builtin(self):
        from pilot.repl import classify_line
        assert classify_line("!du -sh .") == [("class:shell", "!du -sh .")]
        assert classify_line("ls evidence") == [("class:shell", "ls evidence")]
        assert classify_line("cd ..") == [("class:shell", "cd ..")]
        assert classify_line("tools mft")[0] == ("class:builtin", "tools")

    def test_print_result_headline(self, capsys):
        from pilot.repl import print_result
        print_result({"success": True, "_trudi_call_id": 42, "rows": 3})
        out = capsys.readouterr().out
        assert "✓" in out and "cid 42" in out
        print_result({"success": False, "error": "nope"})
        assert "✗" in capsys.readouterr().out

    def test_reason_digest_surfaces_hypothesis_hides_noise(self, capsys):
        from pilot.repl import print_result
        payload = {"success": True, "_trudi_call_id": 9,
                   "hypothesis_id": "H0001",
                   "conclusion": "H1: benign. H2: exfil.",
                   "directives": {"priority_tools": ["net.ngrep_search"]},
                   "backend_meta": {"model": "titus"},
                   "inputs": {"user_message": "wall of text"},
                   "input_tokens": 1905}
        print_result(payload)
        out = capsys.readouterr().out
        assert "H0001" in out and "H1: benign" in out
        assert "1 suggested tool(s)" in out
        assert "titus" not in out and "wall of text" not in out
        # verbose (`last`) shows everything
        print_result(payload, verbose=True)
        assert "titus" in capsys.readouterr().out

    def test_long_stdout_paged_with_sidecar_pointer(self, capsys):
        from pilot.repl import print_result
        stdout = "\n".join(f"packet {i}" for i in range(200))
        print_result({"success": True, "_trudi_call_id": 5, "stdout": stdout})
        out = capsys.readouterr().out
        assert "packet 0" in out and "packet 29" in out
        assert "packet 31" not in out
        assert "170 more lines" in out and "read.output" in out


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

    def test_param_value_path_completion(self, live_completer, tmp_path,
                                         monkeypatch):
        (tmp_path / "evidence").mkdir()
        (tmp_path / "evidence" / "disk.E01").write_bytes(b"x")
        monkeypatch.chdir(tmp_path)
        from prompt_toolkit.completion import CompleteEvent
        from prompt_toolkit.document import Document

        async def hits(text):
            doc = Document(text, len(text))
            return [x.text async for x in
                    live_completer.get_completions_async(doc, CompleteEvent())]

        assert asyncio.run(hits("tsk.fls image=ev")) == ["evidence/"]
        assert asyncio.run(hits("tsk.fls image=evidence/")) == ["evidence/disk.E01"]
        # a bare path in argument position completes too (observed live:
        # "net.ngrep_search … ./evidence/" had no completion)
        assert asyncio.run(hits("tsk.fls ./ev")) == ["./evidence/"]
        assert asyncio.run(hits("tsk.fls evidence/")) == ["evidence/disk.E01"]
        # shell mode: paths complete for arguments
        assert "evidence/" in asyncio.run(hits("ls ev"))
        assert "evidence/" in asyncio.run(hits("!du -sh ev"))
        # param NAME completion still works when no '=' yet
        assert "offset_sectors=" in asyncio.run(hits("tsk.fls image=x o"))

    def test_every_alias_targets_a_mounted_tool(self, live_completer):
        for alias, dotted in live_completer.aliases.items():
            base = dotted.rstrip("*")
            assert any(d.startswith(base) for d in live_completer.dotted), \
                f"alias {alias} -> {dotted} matches no mounted tool"


class TestFilterKnown:
    def test_drops_unknown_tools(self):
        from pilot.repl import filter_known
        schema_map = {"hash_file": {}, "net_ngrep_search": {}}
        assert filter_known(
            ["hash.file", "sha256sum", "net.ngrep_search pattern=x", ""],
            schema_map) == ["hash.file", "net.ngrep_search pattern=x"]


class TestEvidenceTypeAwareness:
    def test_typed_param_with_no_matching_evidence_stays_empty(self):
        """observed live: guess handed nitroba.pcap to ewf.info's image= —
        a strongly-typed param must stay empty rather than take the wrong
        evidence type."""
        from pilot.repl import guess_value
        pcap_only = ["/e/nitroba.pcap"]
        assert guess_value("image", {}, pcap_only) == ""
        assert guess_value("memory_image", {}, pcap_only) == ""
        assert guess_value("pcap_path", {}, pcap_only) == "/e/nitroba.pcap"
        # generic pathy params keep the fallback
        assert guess_value("file_path", {}, pcap_only) == "/e/nitroba.pcap"

    def test_briefs_demote_wrong_evidence_namespaces(self, live_completer):
        import asyncio as _a
        from fastmcp import Client
        import server
        from pilot.repl import build_tool_briefs

        async def get_tools():
            async with Client(server.mcp) as c:
                return await c.list_tools()
        tools = _a.run(get_tools())
        briefs = build_tool_briefs(
            "what should i run to collect the baseline info",
            tools, evidence=["/e/nitroba.pcap"])
        assert "net." in briefs                       # pcap tools rank in
        for wrong in ("ewf.", "vol.", "img.bde"):     # image/memory tools out
            assert wrong not in briefs, wrong
