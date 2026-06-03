"""Evidence path constants and read-only enforcement."""
import inspect
import os
from functools import wraps
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
REASON_TIMEOUT   = int(os.environ.get("TRUDI_REASON_TIMEOUT")   or "90")
DAIR_TIMEOUT     = int(os.environ.get("TRUDI_DAIR_TIMEOUT")     or "120")
# Watchdog budget for pure-Python hashing of large evidence files (memory raws,
# multi-GB E01s). Subprocess hashers (ssdeep, hashdeep) inherit DEFAULT_TIMEOUT
# from `core.executor.run`.
HASH_TIMEOUT     = int(os.environ.get("TRUDI_HASH_TIMEOUT")     or "900")


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


# Common output-parameter names across tool modules. The @output_safe
# decorator scans wrapped function signatures for any of these and validates
# the value at call-time. Centralising this means tool bodies do not need to
# repeat assert_output_safe() for every output param.
_OUTPUT_PARAM_NAMES = (
    "output_path",
    "output_dir",
    "output_file",
    "output_pcap",
    "output_csv",
    "output_json",
    "output_manifest",
    "storage_file",
)


def output_safe(func):
    """Decorator that validates any output_* / storage_file kwarg against the
    evidence read-only policy before calling the wrapped function.

    Apply BELOW @mcp.tool() so MCP introspects the original signature:

        @mcp.tool()
        @output_safe
        def my_tool(image: str, output_dir: str) -> dict: ...
    """
    sig = inspect.signature(func)
    relevant = tuple(n for n in _OUTPUT_PARAM_NAMES if n in sig.parameters)
    if not relevant:
        return func

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            bound = sig.bind_partial(*args, **kwargs)
        except TypeError:
            # Signature mismatch — let the wrapped function raise its own error.
            return func(*args, **kwargs)
        for name in relevant:
            value = bound.arguments.get(name)
            if value:
                assert_output_safe(value)
        return func(*args, **kwargs)

    return wrapper


def resolve_path_ci(path: str) -> tuple[str, bool]:
    """Walk path components case-insensitively on the real filesystem.

    Returns (resolved_path, was_corrected). was_corrected=True means at least
    one component was case-folded to match an actual directory entry.
    If a component has no match the original path is returned with was_corrected=False
    so callers can report a clean not-found error.
    """
    path = os.path.normpath(os.path.expanduser(path))
    parts = Path(path).parts          # e.g. ('/', 'mnt', 'rd01', 'Windows', ...)
    current = parts[0]                # '/'
    corrected = False
    for part in parts[1:]:
        try:
            entries = os.listdir(current)
        except (PermissionError, NotADirectoryError, FileNotFoundError):
            return path, False
        if part in entries:
            current = os.path.join(current, part)
        else:
            lower = part.lower()
            matches = [e for e in entries if e.lower() == lower]
            if matches:
                current = os.path.join(current, matches[0])
                corrected = True
            else:
                return path, False    # component missing — caller handles not-found
    return current, corrected


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
