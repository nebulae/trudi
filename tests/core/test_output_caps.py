"""Env-overridable tool-result caps (core/paths.py)."""
import importlib
import sys


def _fresh_paths(monkeypatch, **env):
    for k in ("TRUDI_OUTPUT_CAP", "TRUDI_OUTPUT_LINE_CAP"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import core.paths
    return importlib.reload(core.paths)


def test_defaults(monkeypatch):
    p = _fresh_paths(monkeypatch)
    assert p.OUTPUT_CAP == 51200
    assert p.MAX_TOOL_OUTPUT_LINES == 150


def test_env_overrides(monkeypatch):
    p = _fresh_paths(monkeypatch,
                     TRUDI_OUTPUT_CAP="16384", TRUDI_OUTPUT_LINE_CAP="100")
    assert p.OUTPUT_CAP == 16384
    assert p.MAX_TOOL_OUTPUT_LINES == 100
    # restore module state for other tests in this worker
    monkeypatch.delenv("TRUDI_OUTPUT_CAP")
    monkeypatch.delenv("TRUDI_OUTPUT_LINE_CAP")
    importlib.reload(sys.modules["core.paths"])
