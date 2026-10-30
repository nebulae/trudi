"""Client-scoped monitoring patches; never replace another client's table."""
from __future__ import annotations


def client_label(client_id: str) -> str:
    return f"TRUDI-client-{client_id}"


def _configuration(entry: dict) -> tuple:
    """Ignore server-generated compiled queries when comparing configurations."""
    args = entry.get("artifacts") or {}
    specs = {s.get("artifact"): {e["key"]: e.get("value", "")
                               for e in (s.get("parameters") or {}).get("env", [])}
             for s in args.get("specs") or []}
    return entry.get("label"), args.get("artifacts") or [], specs


def table_patch(state: dict, client_id: str, artifacts: list[str],
                parameters: dict | None = None) -> list[dict]:
    """Build JSON Patch operations against Velociraptor's ClientEventTable.

    Definitions are shared, but each label's specs contain its own baseline.
    Unrelated global artifacts, labels, and their parameter specs are preserved.
    """
    label = client_label(client_id)
    entries = state.get("label_events") or []
    matches = [i for i, entry in enumerate(entries) if entry.get("label") == label]
    if len(matches) > 1:
        raise ValueError(f"duplicate monitoring label {label}")
    ops = []
    if artifacts:
        specs = [{"artifact": name, "parameters": {"env": [
            {"key": key, "value": str(value)}
            for key, value in sorted((parameters or {}).get(name, {}).items())
        ]}} for name in dict.fromkeys(artifacts)]
        entry = {"label": label, "artifacts": {
            "artifacts": list(dict.fromkeys(artifacts)), "specs": specs}}
        if matches:
            if _configuration(entries[matches[0]]) != _configuration(entry):
                ops.append({"op": "replace", "path": f"/label_events/{matches[0]}", "value": entry})
        elif not entries:
            ops.append({"op": "add", "path": "/label_events", "value": [entry]})
        else:
            ops.append({"op": "add", "path": "/label_events/-", "value": entry})
    elif matches:
        ops.append({"op": "remove", "path": f"/label_events/{matches[0]}"})
    return ops
