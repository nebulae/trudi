"""Response-ledger coordination shared by ingest, MCP tools, and reporting."""
from contextlib import contextmanager
import fcntl
import json
from pathlib import Path


@contextmanager
def transaction(case_dir: Path):
    directory = case_dir / "monitoring" / "response"
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / ".lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def find_alert(case_dir: Path, alert_id: str) -> dict | None:
    for path in (case_dir / "monitoring" / "alerts").glob("*_*.json"):
        try:
            alert = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if alert.get("alert_id") == alert_id:
            return alert
    return None


def investigation_for_alerts(case_dir: Path, alert_ids: list[str]) -> str | None:
    try:
        rec = json.loads((case_dir / "monitoring" / "_open_investigation.json").read_text())
    except (OSError, ValueError):
        return None
    if set(alert_ids) & set(rec.get("alert_ids") or []):
        return rec.get("investigation_id")
    return None


def attach_actions(case_dir: Path, investigation_id: str, alert_ids: list[str]) -> None:
    """Adopt responses that ran before this investigation opened; never by time."""
    with transaction(case_dir):
        for kind in ("suggestions", "executions"):
            for path in (case_dir / "monitoring" / "response" / kind).glob("ACT-*.json"):
                try:
                    rec = json.loads(path.read_text())
                except (OSError, ValueError):
                    continue
                if not rec.get("investigation_id") and set(alert_ids) & set(rec.get("alert_ids") or []):
                    rec["investigation_id"] = investigation_id
                    tmp = path.with_suffix(".json.tmp")
                    tmp.write_text(json.dumps(rec, indent=2))
                    tmp.replace(path)
