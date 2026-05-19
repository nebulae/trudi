"""Execution trace log — records tool calls, reason calls, and findings per case."""
import json
import os
import datetime
from typing import Optional

# Written on every configure() so the singleton can auto-recover after a server restart.
_SESSION_FILE = os.path.expanduser("~/.cache/trudi/session.json")


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _render_entries(case_id: str | None, entries: list[dict]) -> str:
    """Shared markdown renderer used by both to_markdown() and export()."""
    lines = [f"# Execution Trace — {case_id or 'unknown'}\n"]
    for e in entries:
        ts = e.get("ts", "")
        t = e.get("type", "")
        cid = e.get("call_id", "")
        prefix = f"[#{cid}] " if cid else ""
        if t == "tool_call":
            status = "OK" if e.get("success") else "FAIL"
            retries = f" ({e['retries']} retries)" if e.get("retries") else ""
            trunc = " [TRUNCATED]" if e.get("truncated") else ""
            elapsed = f" {e['elapsed_seconds']}s" if e.get("elapsed_seconds") else ""
            lines.append(f"- `{ts}` {prefix}**TOOL** `{e.get('cmd', '')}`  → {status}{retries}{trunc}{elapsed}")
            if not e.get("success") and e.get("stderr"):
                lines.append(f"  - stderr: {e['stderr'][:200]}")
            if e.get("stdout_excerpt"):
                lines.append(f"  - output: {e['stdout_excerpt'][:300]}")
        elif t == "reason_call":
            status = "OK" if e.get("success") else "FAIL"
            tok_in = e.get("input_tokens", 0)
            tok_out = e.get("output_tokens", 0)
            tok_str = f" tokens: in={tok_in} out={tok_out}" if tok_in or tok_out else ""
            lines.append(f"- `{ts}` {prefix}**REASON** `{e.get('tool', '')}`  → {status}{tok_str}")
            if e.get("conclusion"):
                lines.append(f"  - conclusion: {e['conclusion'][:400]}")
            if e.get("directives", {}).get("priority_tools"):
                lines.append(f"  - priority_tools: {e['directives']['priority_tools']}")
            for i, audit in enumerate(e.get("evidence_audit") or []):
                not_provided = sum(
                    1 for v in audit.values()
                    if isinstance(v, str) and v.upper() == "NOT PROVIDED"
                )
                flag = f" ⚠ {not_provided}×NOT_PROVIDED" if not_provided >= 2 else ""
                lines.append(
                    f"  - audit[{i}]: claim=\"{audit.get('claim', '')[:80]}\" "
                    f"tool={audit.get('tool', '?')}{flag}"
                )
        elif t == "investigation_narration":
            refs = (
                f" [from #{', #'.join(str(i) for i in e['input_call_ids'])}]"
                if e.get("input_call_ids") else ""
            )
            lines.append(f"- `{ts}` {prefix}**AGENT**{refs} {e.get('content', '')[:300]}")
        elif t == "finding":
            conf = e.get("confidence", "").upper()
            linked = e.get("linked_call_id", 0)
            link_str = f" ← tool call #{linked}" if linked else ""
            lines.append(f"- `{ts}` {prefix}**FINDING** [{conf}] {e.get('description', '')}{link_str}")
            if e.get("source"):
                lines.append(f"  - source: {e['source']}")
    return "\n".join(lines) + "\n"


class ExecutionLog:
    def __init__(self):
        self._entries: list[dict] = []
        self._path: Optional[str] = None
        self._case_id: Optional[str] = None
        self._seq: int = 0

    def _next_id(self) -> int:
        self._seq += 1
        return self._seq

    def configure(self, case_id: str, path: str) -> int:
        """Open or resume the trace log for case_id at path.

        If a valid trace file already exists at path with a matching case_id,
        rehydrates in-memory state and resumes appending without overwriting.
        Otherwise starts fresh. Returns the number of entries recovered (0 for
        a new case).
        """
        try:
            with open(path) as f:
                data = json.load(f)
            if data.get("case_id") == case_id:
                entries = data.get("entries", [])
                self._entries = entries
                self._seq = max((e.get("call_id", 0) for e in entries), default=0)
                self._case_id = case_id
                self._path = path
                self._save_session()
                return len(entries)
        except (OSError, json.JSONDecodeError, ValueError):
            pass
        self._entries = []
        self._seq = 0
        self._case_id = case_id
        self._path = path
        self._save_session()
        self._flush()
        return 0

    def _save_session(self) -> None:
        """Persist case_id + path so the singleton can auto-recover after a restart."""
        try:
            os.makedirs(os.path.dirname(_SESSION_FILE), exist_ok=True)
            with open(_SESSION_FILE, "w") as f:
                json.dump({"case_id": self._case_id, "path": self._path}, f)
        except OSError:
            pass

    def _auto_recover(self) -> None:
        """If _path is None (server restarted), reconnect to the last known trace."""
        if self._path is not None:
            return
        try:
            with open(_SESSION_FILE) as f:
                s = json.load(f)
            case_id, path = s.get("case_id"), s.get("path")
            if case_id and path:
                self.configure(case_id, path)
        except (OSError, json.JSONDecodeError, ValueError):
            pass

    def record_tool_call(
        self,
        cmd: str,
        success: bool,
        truncated: bool,
        retries: int,
        exit_code: int,
        stderr: str = "",
        elapsed_seconds: float = 0.0,
        stdout_excerpt: str = "",
    ) -> int:
        self._auto_recover()
        if self._path is None:
            return 0
        entry: dict = {
            "call_id": self._next_id(),
            "type": "tool_call",
            "ts": _utcnow(),
            "cmd": cmd,
            "success": success,
            "truncated": truncated,
            "retries": retries,
            "exit_code": exit_code,
            "elapsed_seconds": elapsed_seconds,
            "stderr": stderr[:512] if stderr else "",
        }
        if stdout_excerpt:
            entry["stdout_excerpt"] = stdout_excerpt[:600]
        self._entries.append(entry)
        self._flush()
        return entry["call_id"]

    def record_reason_call(
        self,
        tool: str,
        success: bool,
        conclusion: str,
        directives: dict,
        evidence_audit: list | None = None,
        input_tokens: int = 0,
        output_tokens: int = 0,
    ) -> int:
        self._auto_recover()
        if self._path is None:
            return 0
        cid = self._next_id()
        entry: dict = {
            "call_id": cid,
            "type": "reason_call",
            "ts": _utcnow(),
            "tool": tool,
            "success": success,
            "conclusion": conclusion or "",
            "directives": directives,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
        }
        if evidence_audit:
            entry["evidence_audit"] = evidence_audit
        self._entries.append(entry)
        self._flush()
        return cid

    def record_finding(
        self,
        description: str,
        confidence: str,
        source: str = "",
        linked_call_id: int = 0,
    ) -> int:
        self._auto_recover()
        if self._path is None:
            return 0
        cid = self._next_id()
        self._entries.append({
            "call_id": cid,
            "type": "finding",
            "ts": _utcnow(),
            "description": description,
            "confidence": confidence,
            "source": source,
            "linked_call_id": linked_call_id,
        })
        self._flush()
        return cid

    def record_agent_message(
        self,
        content: str,
        input_call_ids: list[int] | None = None,
    ) -> int:
        self._auto_recover()
        if self._path is None:
            return 0
        entry: dict = {
            "call_id": self._next_id(),
            "type": "investigation_narration",
            "ts": _utcnow(),
            "content": content[:2000],
        }
        if input_call_ids:
            entry["input_call_ids"] = input_call_ids
        self._entries.append(entry)
        self._flush()
        return entry["call_id"]

    def to_json(self) -> dict:
        return {
            "schema_version": "2.0",
            "case_id": self._case_id,
            "entry_count": len(self._entries),
            "entries": self._entries,
        }

    def to_markdown(self) -> str:
        return _render_entries(self._case_id, self._entries)

    def export(self, path: str) -> dict:
        """Write JSON and Markdown to <path>.json and <path>.md.

        Falls back to reading the flushed analysis JSON file when the in-memory
        log is empty — handles MCP server restarts mid-investigation where the
        singleton state is lost but the on-disk file survives.
        """
        data = self.to_json()

        if data["entry_count"] == 0 and self._path:
            try:
                with open(self._path) as f:
                    data = json.load(f)
            except OSError:
                pass

        entry_count = data.get("entry_count", 0)
        try:
            with open(path + ".json", "w") as f:
                json.dump(data, f, indent=2)
            with open(path + ".md", "w") as f:
                f.write(_render_entries(data.get("case_id"), data.get("entries", [])))
        except OSError:
            pass

        return {"entry_count": entry_count}

    def _flush(self) -> None:
        if not self._path:
            return
        try:
            with open(self._path, "w") as f:
                json.dump(self.to_json(), f, indent=2)
        except OSError:
            pass


log = ExecutionLog()  # module-level singleton
