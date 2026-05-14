"""Shared fixtures for TRUDI test suite."""
import pytest
from unittest.mock import MagicMock


def make_proc(returncode=0, stdout=b"output", stderr=b""):
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


@pytest.fixture
def ok_proc():
    return make_proc(0, b"tool output", b"")


@pytest.fixture
def fail_proc():
    return make_proc(1, b"", b"error detail")


@pytest.fixture
def run_ok():
    return {
        "success": True,
        "stdout": "tool output",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "cmd": "tool arg",
    }


@pytest.fixture
def run_fail():
    return {
        "success": False,
        "stdout": "",
        "stderr": "error detail",
        "exit_code": 1,
        "truncated": False,
        "cmd": "tool arg",
    }


@pytest.fixture
def tmp_evidence(tmp_path):
    """A fake evidence file (not in a protected path)."""
    f = tmp_path / "image.raw"
    f.write_bytes(b"\x00" * 1024)
    return str(f)


@pytest.fixture
def tmp_output(tmp_path):
    """A writable output directory (not in evidence paths)."""
    d = tmp_path / "exports"
    d.mkdir()
    return str(d)
