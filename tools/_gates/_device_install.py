"""Shared predicate: was a COMPLETE structured device-install inventory produced?

Detection of removable-media / keystroke-injection initial access does not depend
on a search matching the right string in a possibly-truncated, possibly-windowed
dump — a search over a bounded artifact can always miss. Instead the
device-initial-access gates require that `misc.device_install_inventory` actually
RAN: it parses the whole setupapi.dev.log into a complete, de-duplicated device
table and stamps three structured markers onto its trace entry —
`device_install_inventory: True`, a `coverage_window`, and a `flagged_count`.

- A finding crediting interactive human authorship, or a "no BadUSB" negative, is
  grounded only when such an inventory ran with coverage spanning the claim's
  window. A keyword grep no longer counts.
- If the inventory FLAGGED any device (the structural keystroke-injector profile —
  a device exposing both HID/keyboard and mass-storage interfaces), neither the
  "human-authored, not injected" positive nor the "no BadUSB" negative may stand
  until the flagged device is dispositioned or the finding downgraded.

The markers are set by the trusted MCP tool via annotate_tool_call; the agent
cannot fabricate them in a finding's prose.
"""
import re

_DATE_RE = re.compile(r"\b(\d{4})[-/](\d{1,2})[-/](\d{1,2})\b")


def claim_dates(text: str) -> list:
    """Dates (YYYY-MM-DD) mentioned in a finding/claim — the window it asserts over."""
    out = []
    for y, m, d in _DATE_RE.findall(text or ""):
        try:
            out.append(f"{int(y):04d}-{int(m):02d}-{int(d):02d}")
        except ValueError:
            pass
    return out


def _is_inventory(e) -> bool:
    return (isinstance(e, dict)
            and e.get("device_install_inventory") is True
            and e.get("success") is not False)


def _inventory_entries(ctx) -> list:
    by_type = getattr(ctx.idx, "by_type", {}) or {}
    out = [e for e in by_type.get("tool_call", []) if _is_inventory(e)]
    # Also honour an inventory cited via this finding's input_call_ids.
    by_id = getattr(ctx.idx, "by_call_id", {}) or {}
    for cid in (getattr(ctx, "input_call_ids", None) or []):
        e = by_id.get(cid)
        if _is_inventory(e) and e not in out:
            out.append(e)
    return out


def _spans(cw, day: str) -> bool:
    if not isinstance(cw, dict):
        return False
    s = (cw.get("start") or "")[:10]
    e = (cw.get("end") or "")[:10]
    return bool(s and e and s <= day <= e)


def inventory_for(ctx, dates=None):
    """Return the inventory entry that grounds a claim: a successful
    device-install inventory whose coverage spans `dates` (any of them). When
    `dates` is empty, any successful inventory qualifies. None ⇒ none qualifies
    (either it never ran, or it ran but is silent about the claim window)."""
    entries = _inventory_entries(ctx)
    if not entries:
        return None
    if not dates:
        return entries[0]
    for e in entries:
        if any(_spans(e.get("coverage_window"), d) for d in dates):
            return e
    return None


def flagged_count(entry) -> int:
    if not isinstance(entry, dict):
        return 0
    try:
        return int(entry.get("flagged_count") or 0)
    except (TypeError, ValueError):
        return 0
