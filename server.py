"""
TRUDI MCP Server — SIFT Workstation forensic tool gateway.
Exposes all SIFT tools as typed MCP tools for Claude Code.
"""
import os
from dotenv import load_dotenv
load_dotenv()  # must run before tool modules read os.environ

from fastmcp import FastMCP
from core.middleware import NarrationMiddleware

from tools.imaging import mcp as imaging_mcp
from tools.volatility import mcp as vol_mcp
from tools.sleuthkit import mcp as tsk_mcp
from tools.ewf import mcp as ewf_mcp
from tools.eztools import mcp as ez_mcp
from tools.plaso import mcp as plaso_mcp
from tools.yara_tools import mcp as yara_mcp
from tools.hashing import mcp as hash_mcp
from tools.strings_tools import mcp as strings_mcp
from tools.carving import mcp as carving_mcp
from tools.network import mcp as network_mcp
from tools.enrichment import mcp as enrichment_mcp
from tools.misc import mcp as misc_mcp
from tools.read_output import mcp as read_mcp
from tools.reasoning import mcp as reason_mcp
from tools.dair import mcp as dair_mcp
from tools.accuracy import mcp as accuracy_mcp
from tools.correlate import mcp as correlate_mcp
from tools.coverage import mcp as coverage_mcp
from tools.antiforensics import mcp as antiforensics_mcp
from tools.attribution import mcp as attribution_mcp
from tools.live import mcp as live_mcp
from tools.velo import mcp as velo_mcp
from tools.monitor import mcp as monitor_mcp
from tools.respond import mcp as respond_mcp

mcp = FastMCP(
    "trudi-sift",
    instructions=(
        "TRUDI SIFT MCP Server — exposes SANS SIFT Workstation forensic tools as typed MCP tools. "
        "All tools are read-only with respect to evidence. "
        "Output paths must be within analysis/, exports/, or reports/ directories. "
        "Timestamps are always UTC."
    ),
)
mcp.add_middleware(NarrationMiddleware())

# (namespace, server) pairs — mounted below, and walked by the slim-descriptions
# pass, which must mutate CHILD tool objects (the parent's get_tool returns
# copies for mounted tools).
NAMESPACES = [
    ("img", imaging_mcp), ("vol", vol_mcp), ("tsk", tsk_mcp), ("ewf", ewf_mcp),
    ("ez", ez_mcp), ("plaso", plaso_mcp), ("yara", yara_mcp), ("hash", hash_mcp),
    ("strings", strings_mcp), ("carve", carving_mcp), ("net", network_mcp),
    ("enrich", enrichment_mcp), ("misc", misc_mcp), ("read", read_mcp),
    ("reason", reason_mcp), ("dair", dair_mcp), ("accuracy", accuracy_mcp),
    ("correlate", correlate_mcp), ("coverage", coverage_mcp),
    ("af", antiforensics_mcp), ("attribution", attribution_mcp),
    ("live", live_mcp), ("velo", velo_mcp), ("monitor", monitor_mcp),
    ("respond", respond_mcp),
]
for _ns, _child in NAMESPACES:
    mcp.mount(_child, namespace=_ns)


if __name__ == "__main__":
    # Schema-eager clients (OpenCode) pay for every description in every
    # request; the registrar sets this env for them. Claude Code defers schema
    # loading and keeps the full docstrings. Typed parameter schemas are never
    # touched — see core/slim_descriptions.py.
    if os.environ.get("TRUDI_SLIM_TOOL_DESCRIPTIONS") == "1":
        import asyncio
        from core.slim_descriptions import slim_tool_descriptions
        asyncio.run(slim_tool_descriptions(NAMESPACES))

    # The trace dashboard runs as a separate long-lived process (`trudi-dashboard`).
    # We no longer autostart a per-case copy here — it caused port collisions and
    # died whenever MCP restarted. start_execution_log surfaces the standalone
    # URL via ~/.cache/trudi/dashboard.url instead.
    mcp.run(transport="stdio")
