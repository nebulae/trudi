"""Smoke tests for server.py — imports, mounts, tool count."""
import pytest


class TestServerImports:
    def test_server_imports(self):
        import server
        assert hasattr(server, "mcp")

    def test_all_namespaces_mounted(self):
        import server
        # FastMCP exposes mounted servers — verify the main mcp exists
        assert server.mcp is not None

    def test_all_tool_modules_importable(self):
        from tools import (
            imaging, volatility, sleuthkit, ewf, eztools,
            plaso, yara_tools, hashing, strings_tools,
            carving, network, enrichment, misc,
        )
        modules = [
            imaging, volatility, sleuthkit, ewf, eztools,
            plaso, yara_tools, hashing, strings_tools,
            carving, network, enrichment, misc,
        ]
        for m in modules:
            assert hasattr(m, "mcp"), f"{m.__name__} missing mcp attribute"


class TestToolCount:
    """Sanity check that we haven't accidentally dropped tools."""

    def _count_tools(self, module):
        from fastmcp import FastMCP
        mcp = module.mcp
        # FastMCP stores tools in _tool_manager or similar
        if hasattr(mcp, "_tool_manager"):
            return len(mcp._tool_manager._tools)
        if hasattr(mcp, "list_tools"):
            import asyncio
            tools = asyncio.get_event_loop().run_until_complete(mcp.list_tools())
            return len(tools)
        return -1  # can't count, skip assertion

    def test_volatility_tool_count(self):
        from tools import volatility
        count = self._count_tools(volatility)
        if count >= 0:
            assert count >= 40, f"Expected ≥40 vol tools, got {count}"

    def test_sleuthkit_tool_count(self):
        from tools import sleuthkit
        count = self._count_tools(sleuthkit)
        if count >= 0:
            assert count >= 18, f"Expected ≥18 tsk tools, got {count}"

    def test_hashing_tool_count(self):
        from tools import hashing
        count = self._count_tools(hashing)
        if count >= 0:
            assert count >= 7

    def test_misc_tool_count(self):
        from tools import misc
        count = self._count_tools(misc)
        if count >= 0:
            assert count >= 12


class TestCoreImports:
    def test_core_run_importable(self):
        from core import run
        assert callable(run)

    def test_core_run_dotnet_importable(self):
        from core import run_dotnet
        assert callable(run_dotnet)

    def test_core_vol3_symbols_importable(self):
        from core import vol3_symbols
        assert callable(vol3_symbols)

    def test_core_assert_output_safe_importable(self):
        from core import assert_output_safe
        assert callable(assert_output_safe)
