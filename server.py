"""
TRUDI MCP Server — SIFT Workstation forensic tool gateway.
Exposes all SIFT tools as typed MCP tools for Claude Code.
"""
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
from tools.reasoning import mcp as reason_mcp

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

mcp.mount(imaging_mcp, namespace="img")
mcp.mount(vol_mcp, namespace="vol")
mcp.mount(tsk_mcp, namespace="tsk")
mcp.mount(ewf_mcp, namespace="ewf")
mcp.mount(ez_mcp, namespace="ez")
mcp.mount(plaso_mcp, namespace="plaso")
mcp.mount(yara_mcp, namespace="yara")
mcp.mount(hash_mcp, namespace="hash")
mcp.mount(strings_mcp, namespace="strings")
mcp.mount(carving_mcp, namespace="carve")
mcp.mount(network_mcp, namespace="net")
mcp.mount(enrichment_mcp, namespace="enrich")
mcp.mount(misc_mcp, namespace="misc")
mcp.mount(reason_mcp, namespace="reason")


if __name__ == "__main__":
    mcp.run(transport="stdio")
