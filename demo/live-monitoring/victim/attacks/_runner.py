#!/usr/bin/env python3
"""Atomic Red Team test runner — invoked by /attacks/run.

Reads the atomic YAML at ATOMIC_TEST_YAML, picks test number
ATOMIC_TEST_NUMBER, substitutes input_arguments with their defaults, and
exec's the bash/sh executor block. If ATOMIC_CLEANUP=1, runs the
cleanup_command instead.

Why Python + bash split: bash + grep is too brittle for multi-line input
arguments and command blocks. Keeping the dispatcher in bash for clean
UX, the YAML walk in Python for correctness.
"""
import os
import re
import shlex
import subprocess
import sys

import yaml


def main() -> int:
    yaml_path = os.environ["ATOMIC_TEST_YAML"]
    test_no = int(os.environ.get("ATOMIC_TEST_NUMBER", "1"))
    cleanup = os.environ.get("ATOMIC_CLEANUP", "0") == "1"

    with open(yaml_path) as f:
        doc = yaml.safe_load(f)

    tests = doc.get("atomic_tests", [])
    if test_no < 1 or test_no > len(tests):
        print(f"[runner] test #{test_no} out of range (1..{len(tests)})", file=sys.stderr)
        return 4
    test = tests[test_no - 1]

    if "linux" not in (p.lower() for p in test.get("supported_platforms", [])):
        print(f"[runner] test #{test_no} doesn't list 'linux' as supported "
              f"({test.get('supported_platforms')}) — refusing to execute",
              file=sys.stderr)
        return 5

    executor = test.get("executor", {})
    if executor.get("name") not in ("bash", "sh"):
        print(f"[runner] test #{test_no} executor is "
              f"{executor.get('name')!r} — only bash/sh supported", file=sys.stderr)
        return 6

    raw = executor.get("cleanup_command" if cleanup else "command", "")
    if not raw or not raw.strip():
        action = "cleanup_command" if cleanup else "command"
        print(f"[runner] test #{test_no} has no {action}", file=sys.stderr)
        return 0 if cleanup else 7

    # Substitute #{input_arg} with its default value.
    args = test.get("input_arguments", {}) or {}
    def sub(match: "re.Match[str]") -> str:
        name = match.group(1)
        if name not in args:
            print(f"[runner] WARNING: input_argument {name!r} has no definition", file=sys.stderr)
            return match.group(0)
        return str(args[name].get("default", ""))
    rendered = re.sub(r"#\{([A-Za-z0-9_]+)\}", sub, raw)

    print(f"[runner] --- {test.get('name', '(unnamed)')} ---")
    print(f"[runner] {'cleanup' if cleanup else 'execute'} command:")
    for line in rendered.splitlines():
        print(f"    {line}")

    # Use bash -lc; many atomic commands assume a login shell.
    proc = subprocess.run(["bash", "-lc", rendered])
    print(f"[runner] exit_code={proc.returncode}")
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
