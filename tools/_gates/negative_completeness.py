"""Gate: a negative/absence finding must search its claim's COMPLETE source set,
and the searched logs must cover the claim's time window.

Fires only on UNCONFIRMED findings (negatives are recorded UNCONFIRMED) whose
description matches a known case-inverting category (logon/auth, identity,
persistence, exfil — see _manifests.py). A manifest source is satisfied if the
trace shows a tool_call touched it OR an explicit "<source> absent from evidence"
note. STRICT: any unsatisfied source, or a claim window outside every searched
log's coverage, is a hard refusal.
"""
import re
from typing import Optional

from ._device_install import claim_dates, flagged_count, inventory_for
from ._manifests import MANIFESTS, classify

# Names the device-install log / USB device class — used only to honour the
# explicit "<source> absent from evidence" escape for DEVICE_INITIAL_ACCESS.
_DEVLOG_NAME_RE = re.compile(
    r"setupapi(?:\.dev)?\.log|usbdeviceforensics|device[- ]install log|usb device[- ]class",
    re.IGNORECASE,
)

# A date in the claim description → the window the negative is asserted over.
_DATE_RE = re.compile(r"\b(\d{4})[-/](\d{1,2})[-/](\d{1,2})\b")

# Explicit "this source is genuinely absent from the evidence" escape.
_ABSENT_RE = re.compile(
    r"(?:absent from evidence|not (?:present|collected)|not in (?:the )?(?:evidence|image|collection)"
    r"|no (?:such )?(?:log|artifact|channel|store)\b)",
    re.IGNORECASE,
)


def _tool_cmds(ctx) -> list:
    by_type = getattr(ctx.idx, "by_type", {}) or {}
    return [e for e in by_type.get("tool_call", []) if isinstance(e.get("cmd"), str)]


def _claim_dates(text: str) -> list:
    out = []
    for y, m, d in _DATE_RE.findall(text or ""):
        try:
            out.append(f"{int(y):04d}-{int(m):02d}-{int(d):02d}")
        except ValueError:
            pass
    return out


def check(ctx) -> Optional[dict]:
    if ctx.tier != "UNCONFIRMED":
        return None
    desc = ctx.description or ""
    category = classify(desc)
    if not category:
        return None

    spec = MANIFESTS[category]
    cmds = _tool_cmds(ctx)
    blob = desc + " " + (ctx.supporting_evidence or "")

    # OS / channel alternative that waives the required list (e.g. a Linux host
    # satisfies LOGON_AUTH via wtmp/last instead of the Windows event channels).
    alt = spec.get("alt_satisfies")
    if alt and any(alt.search(e["cmd"]) for e in cmds):
        return None

    # DEVICE_INITIAL_ACCESS: a "no BadUSB" negative must be grounded on a COMPLETE
    # structured device-install inventory (misc.device_install_inventory parses the
    # whole setupapi.dev.log), not a keyword grep over a truncated/windowed dump.
    # And the negative cannot stand if that inventory FLAGGED a device. An explicit
    # "<log> absent from evidence" note still escapes.
    if category == "DEVICE_INITIAL_ACCESS":
        if _ABSENT_RE.search(blob) and _DEVLOG_NAME_RE.search(blob):
            return None
        inv = inventory_for(ctx, claim_dates(blob))
        if inv is None:
            return {
                "success": False,
                "error": (
                    f"Refusing UNCONFIRMED {category} finding: it asserts no BadUSB / "
                    f"HID-injection device, but no COMPLETE device-install inventory "
                    f"covering the window exists in the trace. USBSTOR / mass-storage "
                    f"enumeration and keyword greps over setupapi.dev.log can silently "
                    f"miss a device — run misc.device_install_inventory to enumerate "
                    f"every device, or record an explicit 'setupapi.dev.log absent from "
                    f"evidence' finding, before concluding absence."
                ),
                "description": ctx.description,
                "confidence": ctx.confidence,
                "gate": "negative_completeness",
            }
        fc = flagged_count(inv)
        if fc > 0:
            return {
                "success": False,
                "error": (
                    f"Refusing UNCONFIRMED {category} finding: it asserts no BadUSB, "
                    f"but the structured device-install inventory FLAGGED {fc} "
                    f"keystroke-injection-capable device(s) in the window (a device "
                    f"exposing both HID/keyboard and mass-storage interfaces). "
                    f"A 'no BadUSB' negative cannot stand over an inventory that "
                    f"flagged a device — disposition the flagged device(s) explicitly "
                    f"(benign, with reasons) or record it as a positive finding."
                ),
                "description": ctx.description,
                "confidence": ctx.confidence,
                "gate": "negative_completeness",
            }
        return None

    # 1) Manifest completeness — every required source touched or proven absent.
    missing = []
    for _sid, rx, hint in spec["required"]:
        if any(rx.search(e["cmd"]) for e in cmds):
            continue
        if _ABSENT_RE.search(blob) and rx.search(blob):
            continue
        missing.append(hint)
    if missing:
        return {
            "success": False,
            "error": (
                f"Refusing UNCONFIRMED {category} finding: it asserts absence but the "
                f"trace never searched {len(missing)} required source(s) — "
                f"{'; '.join(missing)}. A negative is only valid over the COMPLETE "
                f"source set for the claim; absence from the subset you happened to "
                f"search is not evidence of absence. Search {spec['where']}, or record "
                f"an explicit '<source> absent from evidence' finding, before "
                f"concluding absence."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "negative_completeness",
        }

    # 2) Coverage window — if the claim names a date, at least one searched source
    #    carrying a coverage_window must span it. A silent (out-of-coverage) log
    #    cannot ground a negative.
    dates = _claim_dates(blob)
    covered = [e for e in cmds if isinstance(e.get("coverage_window"), dict)]
    if dates and covered:
        def _spans(cw: dict, day: str) -> bool:
            s = (cw.get("start") or "")[:10]
            e = (cw.get("end") or "")[:10]
            return bool(s and e and s <= day <= e)

        if not any(_spans(e["coverage_window"], day) for e in covered for day in dates):
            ranges = ", ".join(
                f"{(e['coverage_window'].get('start') or '?')[:10]}→"
                f"{(e['coverage_window'].get('end') or '?')[:10]}"
                for e in covered[:4]
            )
            claim = ", ".join(dates[:4])
            return {
                "success": False,
                "error": (
                    f"Refusing UNCONFIRMED {category} finding: the searched log(s) cover "
                    f"{ranges} but the claim window ({claim}) is OUTSIDE that coverage — a "
                    f"negative cannot be drawn from a log that is silent about the window. "
                    f"Search a source that covers it: TerminalServices logs, Volume Shadow "
                    f"Copies, or carved EVTX from unallocated/pagefile/hiberfil."
                ),
                "description": ctx.description,
                "confidence": ctx.confidence,
                "gate": "negative_completeness",
            }

    return None
