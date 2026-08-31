"""Mount-time wire-name dedup (core/normalize_names.py).

Modules whose function names bake in the namespace used to mount as
stuttered wire names (tsk_tsk_mmls, vol_vol_pslist, read_read_output).
Pilot mode makes tool names a human typing surface and the deny-loop
incident (e3617ee) showed models navigate by name too — so the dedup is
locked here: no mounted name may repeat its namespace, the canonical
names must exist, and the rename must not break dispatch.
"""
import asyncio

import pytest

from fastmcp import FastMCP

from core.normalize_names import normalize_tool_names


def _mounted_names():
    import server
    return {t.name for t in asyncio.run(server.mcp.list_tools())}


class TestLiveServerNames:
    def test_no_mounted_name_repeats_its_namespace(self):
        import server
        namespaces = [ns for ns, _ in server.NAMESPACES]
        for name in _mounted_names():
            for ns in namespaces:
                assert not name.startswith(f"{ns}_{ns}_"), \
                    f"doubled wire name survived normalization: {name}"

    def test_canonical_names_present(self):
        names = _mounted_names()
        for expected in (
            "vol_pslist", "vol_symbol_check", "tsk_mmls", "tsk_fls",
            "ez_mftecmd", "ez_recmd_hive", "plaso_create_timeline",
            "yara_scan_file", "af_timestomp_drift", "live_processes",
            "reason_plan", "reason_evaluate_finding", "dair_assess",
            "read_output", "read_mail", "accuracy_compare",
            "coverage_report", "ewf_info", "ewf_mount_full_image",
            "hash_file", "hash_verify_evidence_hash",
            "strings_extract", "strings_hexdump",
            "misc_record_finding", "net_tcpdump_read",
        ):
            assert expected in names, f"expected wire name missing: {expected}"

    def test_idempotent_on_normalized_server(self):
        import server
        assert asyncio.run(normalize_tool_names(server.NAMESPACES)) == 0

    def test_import_inside_running_event_loop(self):
        """The pilot REPL imports server from async code; a bare
        asyncio.run() at import time raised RuntimeError there (observed
        live on the spike's first interactive run). Fresh subprocess so the
        import actually executes."""
        import subprocess
        import sys
        code = (
            "import asyncio\n"
            "async def main():\n"
            "    import server\n"
            "    tools = {t.name for t in await server.mcp.list_tools()}\n"
            "    assert 'tsk_mmls' in tools and 'tsk_tsk_mmls' not in tools\n"
            "asyncio.run(main())\n"
        )
        r = subprocess.run([sys.executable, "-c", code],
                           capture_output=True, text=True, timeout=120)
        assert r.returncode == 0, r.stderr[-800:]


class TestRenameMechanics:
    @pytest.fixture()
    def mounted_pair(self):
        child = FastMCP("child")

        @child.tool()
        def tsk_mmls(x: int = 1) -> dict:
            return {"ok": x}

        @child.tool()
        def unprefixed(x: int = 1) -> dict:
            return {"ok": x}

        parent = FastMCP("parent")
        parent.mount(child, namespace="tsk")
        return parent, child

    def test_rename_dedupes_and_dispatches(self, mounted_pair):
        parent, child = mounted_pair
        assert asyncio.run(normalize_tool_names([("tsk", child)])) == 1
        names = {t.name for t in asyncio.run(parent.list_tools())}
        assert names == {"tsk_mmls", "tsk_unprefixed"}
        res = asyncio.run(parent.call_tool("tsk_mmls", {"x": 7}))
        assert res.structured_content == {"ok": 7}

    def test_collision_and_empty_are_skipped(self):
        child = FastMCP("child")

        @child.tool(name="ns_")
        def would_be_empty() -> dict:
            return {}

        @child.tool(name="ns_clash")
        def prefixed() -> dict:
            return {}

        @child.tool(name="clash")
        def bare() -> dict:
            return {}

        assert asyncio.run(normalize_tool_names([("ns", child)])) == 0
        names = {t.name for t in asyncio.run(child.list_tools())}
        assert names == {"ns_", "ns_clash", "clash"}
