"""Execution trace log — records tool calls, reason calls, and findings per case."""
import json
import datetime
from typing import Optional


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


class ExecutionLog:
    def __init__(self):
        self._entries: list[dict] = []
        self._path: Optional[str] = None
        self._case_id: Optional[str] = None

    def configure(self, case_id: str, path: str) -> None:
        """Reset and reconfigure for a new case. Clears all prior entries."""
        self._entries = []
        self._case_id = case_id
        self._path = path
        self._flush()

    def record_tool_call(
        self,
        cmd: str,
        success: bool,
        truncated: bool,
        retries: int,
        exit_code: int,
        stderr: str = "",
        elapsed_seconds: float = 0.0,
        progress_lines: list | None = None,
    ) -> None:
        if self._path is None:
            return
        entry: dict = {
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
        if progress_lines:
            entry["progress_lines"] = progress_lines
        self._entries.append(entry)
        self._flush()

    def record_reason_call(
        self,
        tool: str,
        success: bool,
        conclusion: str,
        directives: dict,
    ) -> None:
        if self._path is None:
            return
        self._entries.append({
            "type": "reason_call",
            "ts": _utcnow(),
            "tool": tool,
            "success": success,
            "conclusion": conclusion or "",
            "directives": directives,
        })
        self._flush()

    def record_finding(
        self,
        description: str,
        confidence: str,
        source: str = "",
    ) -> None:
        if self._path is None:
            return
        self._entries.append({
            "type": "finding",
            "ts": _utcnow(),
            "description": description,
            "confidence": confidence,
            "source": source,
        })
        self._flush()

    def to_json(self) -> dict:
        return {
            "case_id": self._case_id,
            "entry_count": len(self._entries),
            "entries": self._entries,
        }

    def to_markdown(self) -> str:
        lines = [f"# Execution Trace — {self._case_id or 'unknown'}\n"]
        for e in self._entries:
            ts = e.get("ts", "")
            t = e.get("type", "")
            if t == "tool_call":
                status = "OK" if e["success"] else "FAIL"
                retries = f" ({e['retries']} retries)" if e.get("retries") else ""
                trunc = " [TRUNCATED]" if e.get("truncated") else ""
                elapsed = f" {e['elapsed_seconds']}s" if e.get("elapsed_seconds") else ""
                lines.append(f"- `{ts}` **TOOL** `{e['cmd']}`  → {status}{retries}{trunc}{elapsed}")
                if not e["success"] and e.get("stderr"):
                    lines.append(f"  - stderr: {e['stderr'][:200]}")
            elif t == "reason_call":
                status = "OK" if e["success"] else "FAIL"
                lines.append(f"- `{ts}` **REASON** `{e['tool']}`  → {status}")
                if e.get("conclusion"):
                    lines.append(f"  - {e['conclusion'][:200]}")
                if e.get("directives", {}).get("priority_tools"):
                    lines.append(f"  - priority_tools: {e['directives']['priority_tools']}")
            elif t == "finding":
                lines.append(
                    f"- `{ts}` **FINDING** [{e['confidence'].upper()}] {e['description']}"
                )
                if e.get("source"):
                    lines.append(f"  - source: {e['source']}")
        return "\n".join(lines) + "\n"

    def export(self, path: str) -> None:
        """Write JSON and Markdown to <path>.json and <path>.md."""
        try:
            with open(path + ".json", "w") as f:
                json.dump(self.to_json(), f, indent=2)
            with open(path + ".md", "w") as f:
                f.write(self.to_markdown())
        except OSError:
            pass

    def _flush(self) -> None:
        if not self._path:
            return
        try:
            with open(self._path, "w") as f:
                json.dump(self.to_json(), f, indent=2)
        except OSError:
            pass


log = ExecutionLog()  # module-level singleton
