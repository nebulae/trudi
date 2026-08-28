"""Exit-code policies for wrapped binaries whose non-zero exit is a RESULT,
not a failure. Tool semantics only — never case data.

`run()` maps `success = returncode == 0` by default. For a scanner that exits
1 to say "I found something" (clamscan, ngrep) that inverts the meaning in the
trace: the positive detection is logged `success: false`. Wrappers pass
`**policy("<binary>")` into `core.executor.run` to declare the real mapping;
the executor stamps `exit_meaning` on the result and the trace entry.

Sources: clamscan(1) RETURN CODES; ngrep(8) EXIT STATUS (verified on this
host, V1.47.1); grep(1); oletools mraptor.py exit-code constants.
"""
from __future__ import annotations

EXIT_POLICIES: dict[str, dict] = {
    "clamscan": {
        "success_codes": frozenset({0, 1}),
        "meanings": {0: "clean — no infected files",
                     1: "infected — one or more files FOUND (see stdout)",
                     2: "error"},
    },
    "ngrep": {
        "success_codes": frozenset({0, 1}),
        "meanings": {0: "one or more frames matched",
                     1: "no frames matched",
                     2: "error"},
    },
    "grep": {
        "success_codes": frozenset({0, 1}),
        "meanings": {0: "matches found", 1: "no matches", 2: "error"},
    },
    "mraptor": {
        "success_codes": frozenset({0, 1, 2, 20}),
        "meanings": {0: "no macro", 1: "not an MS Office file",
                     2: "macro present — no suspicious pattern",
                     10: "error", 20: "SUSPICIOUS macro"},
    },
}


def policy(binary: str) -> dict:
    """kwargs for core.executor.run(): {"success_codes", "exit_meanings"}.
    Unknown binary ⇒ the default policy (only 0 succeeds)."""
    pol = EXIT_POLICIES.get(binary) or {}
    return {
        "success_codes": frozenset(pol.get("success_codes") or {0}),
        "exit_meanings": dict(pol.get("meanings") or {}),
    }
