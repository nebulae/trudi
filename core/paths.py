"""Evidence path constants and read-only enforcement."""
import os
from pathlib import Path

# Paths that must never be written to
READ_ONLY_PREFIXES = (
    "/cases/",
    "/mnt/",
    "/media/",
)

READ_ONLY_SEGMENTS = ("evidence",)

# Maximum subprocess output returned to the LLM (bytes)
OUTPUT_CAP = 51_200  # 50 KB

# Maximum tool output lines returned to the agent (line-based cap)
MAX_TOOL_OUTPUT_LINES = 150

# ── Configurable timeouts (seconds) ─────────────────────────────────────────
# Override via environment variables — useful on slow hardware (WSL2, USB drives).

DEFAULT_TIMEOUT  = int(os.environ.get("TRUDI_DEFAULT_TIMEOUT")  or "300")
VOL_TIMEOUT      = int(os.environ.get("TRUDI_VOL_TIMEOUT")      or "600")
PLASO_TIMEOUT    = int(os.environ.get("TRUDI_PLASO_TIMEOUT")    or "21600")
REASON_TIMEOUT   = int(os.environ.get("TRUDI_REASON_TIMEOUT")   or "120")


def is_evidence_path(path: str) -> bool:
    """Return True if path is under a protected evidence location."""
    p = os.path.realpath(path)
    for prefix in READ_ONLY_PREFIXES:
        if p.startswith(prefix):
            return True
    parts = Path(p).parts
    return any(seg == "evidence" for seg in parts)


def assert_output_safe(path: str) -> None:
    """Raise ValueError if path resolves inside an evidence directory."""
    if is_evidence_path(path):
        raise ValueError(
            f"Output path '{path}' is inside a protected evidence directory. "
            "Write outputs to ./analysis/, ./exports/, or ./reports/ only."
        )


def vol3_bin() -> str:
    return "/usr/local/bin/vol"


def vol3_symbols() -> str:
    """Return writable Volatility 3 symbol cache directory, creating it if needed."""
    # Use `or` so an empty VOLATILITY_SYMBOLS env var falls back to the default
    path = os.environ.get("VOLATILITY_SYMBOLS") or os.path.expanduser("~/.cache/volatility3/symbols")
    os.makedirs(path, exist_ok=True)
    return path


def ez_tool(name: str, subdir: str | None = None) -> str:
    base = "/opt/zimmermantools"
    if subdir:
        return f"dotnet {base}/{subdir}/{name}.dll"
    return f"dotnet {base}/{name}.dll"
