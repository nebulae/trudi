"""Gate: a negative/absence finding must search its claim's COMPLETE source set,
and the searched logs must cover the claim's time window.

Fires only on UNCONFIRMED findings whose DECLARED claim is a negative in a
case-inverting category (claim_kind="negative", category ∈ logon_auth /
identity / persistence / exfil / device_initial_access — see _manifests.py).
Nothing here reads the description: the category comes from the typed claim,
the window from claim.window, and a source that genuinely is not in the
evidence is settled by a typed disposition
(misc.record_disposition(target_kind="source", target_id=<source_id>,
reason="absent_from_evidence"|"inapplicable"|"out_of_scope")). STRICT: any
unsatisfied source, or a claim window outside every searched log's coverage, is
a hard refusal.
"""
from typing import Optional

from ._device_install import flagged_count, inventory_for
from ._dispositions import disposition_call, find_disposition
from ._entities import norm_entity
from ._manifests import MANIFESTS, SOURCE_WAIVER_REASONS, manifest_for_claim


def _tool_cmds(ctx) -> list:
    by_type = getattr(ctx.idx, "by_type", {}) or {}
    return [e for e in by_type.get("tool_call", []) if isinstance(e.get("cmd"), str)]


def _claim_window_days(claim: dict) -> list:
    w = (claim or {}).get("window") or {}
    return [str(w[k])[:10] for k in ("start", "end") if w.get(k)]


def _waived(ctx, source_id: str) -> bool:
    return find_disposition(ctx.idx, "source", source_id, reasons=SOURCE_WAIVER_REASONS) is not None


def _device_addressed(ctx, dev: str) -> bool:
    """A registry-only device ('vid:pid') is addressed by any device disposition
    or by an active finding naming it in its typed entities."""
    if find_disposition(ctx.idx, "device", dev) is not None:
        return True
    vid, _, pid = dev.partition(":")
    want = {norm_entity(dev), norm_entity(f"vid_{vid}&pid_{pid}")}
    by_type = getattr(ctx.idx, "by_type", {}) or {}
    for f in by_type.get("finding", []):
        ents = ((f.get("claim") or {}).get("entities") or [])
        if want & {norm_entity(str(x)) for x in ents}:
            return True
    return False


def check(ctx) -> Optional[dict]:
    if ctx.tier != "UNCONFIRMED":
        return None
    claim = getattr(ctx, "claim", None) or {}
    category = manifest_for_claim(claim)
    if not category:
        return None

    spec = MANIFESTS[category]
    cmds = _tool_cmds(ctx)

    # OS / channel alternative that waives the required list (e.g. a Linux host
    # satisfies LOGON_AUTH via wtmp/last instead of the Windows event channels).
    alt = spec.get("alt_satisfies")
    if alt and any(alt.search(e["cmd"]) for e in cmds):
        return None

    # DEVICE_INITIAL_ACCESS: a "no BadUSB" negative must be grounded on a COMPLETE
    # structured device-install inventory (misc.device_install_inventory parses the
    # whole setupapi.dev.log), not a keyword grep over a truncated/windowed dump.
    # And the negative cannot stand if that inventory FLAGGED a device. A typed
    # "device_inventory absent_from_evidence" disposition still escapes.
    if category == "DEVICE_INITIAL_ACCESS":
        if _waived(ctx, "device_inventory"):
            return None
        inv = inventory_for(ctx, _claim_window_days(claim))
        if inv is None:
            return {
                "success": False,
                "error": (
                    f"Refusing UNCONFIRMED {category} finding: it asserts no BadUSB / "
                    f"HID-injection device, but no COMPLETE device-install inventory "
                    f"covering the window exists in the trace. USBSTOR / mass-storage "
                    f"enumeration and keyword greps over setupapi.dev.log can silently "
                    f"miss a device — run misc.device_install_inventory to enumerate "
                    f"every device, or record "
                    f"{disposition_call('source', 'device_inventory', 'absent_from_evidence')} "
                    f"if setupapi.dev.log is genuinely not in evidence."
                ),
                "description": ctx.description,
                "confidence": ctx.confidence,
                "gate": "negative_completeness",
                "missing_sources": ["device_inventory"],
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
                    f"flagged a device — rule the device out with evidence "
                    f"({disposition_call('device', '<VID:PID>', 'ruled_out', evidence=True)}) "
                    f"or record it as a positive finding."
                ),
                "description": ctx.description,
                "confidence": ctx.confidence,
                "gate": "negative_completeness",
            }
        # setupapi.dev.log rotates and can be cleared: a device negative also needs
        # the SYSTEM hive's USB history, and every device the registry holds that
        # the install log lacks must be addressed (finding or device disposition).
        if not inv.get("registry_checked") and not _waived(ctx, "usb_registry"):
            return {
                "success": False,
                "error": (
                    f"Refusing UNCONFIRMED {category} finding: the device inventory covers "
                    f"setupapi.dev.log only — the SYSTEM hive's Enum\\USB / Enum\\USBSTOR "
                    f"history was not merged, and the install log is not a complete device "
                    f"history (it rotates and can be cleared). Re-run "
                    f"misc.device_install_inventory with system_hive_path=<SYSTEM hive>, or "
                    f"record {disposition_call('source', 'usb_registry', 'absent_from_evidence')} "
                    f"if no SYSTEM hive is in evidence."
                ),
                "description": ctx.description,
                "confidence": ctx.confidence,
                "gate": "negative_completeness",
                "missing_sources": ["usb_registry"],
            }
        open_devs = [d for d in (inv.get("registry_only") or [])
                     if not _device_addressed(ctx, d)]
        if open_devs:
            return {
                "success": False,
                "error": (
                    f"Refusing UNCONFIRMED {category} finding: the SYSTEM hive's USB "
                    f"history holds {len(open_devs)} device(s) absent from setupapi.dev.log "
                    f"({', '.join(open_devs[:6])}) — the install log is incomplete, so a "
                    f"device negative drawn from it does not hold. Identify each device "
                    f"(it may be exactly what the negative denies) and record a finding "
                    f"naming it in entities, or "
                    f"{disposition_call('device', '<VID:PID>', 'ruled_out', evidence=True)}."
                ),
                "description": ctx.description,
                "confidence": ctx.confidence,
                "gate": "negative_completeness",
                "registry_only_devices": open_devs,
            }
        return None

    # 1) Manifest completeness — every required source touched or dispositioned.
    missing, hints = [], []
    for sid, rx, hint in spec["required"]:
        if any(rx.search(e["cmd"]) for e in cmds):
            continue
        if _waived(ctx, sid):
            continue
        missing.append(sid)
        hints.append(f"{sid} ({hint})")
    if missing:
        calls = "; ".join(disposition_call("source", sid, "absent_from_evidence") for sid in missing[:3])
        return {
            "success": False,
            "error": (
                f"Refusing UNCONFIRMED {category} finding: it asserts absence but the "
                f"trace never searched {len(missing)} required source(s) — "
                f"{'; '.join(hints)}. A negative is only valid over the COMPLETE "
                f"source set for the claim; absence from the subset you happened to "
                f"search is not evidence of absence. Search {spec['where']}, or — only if "
                f"a source is genuinely not in the evidence — settle it with a typed "
                f"disposition: {calls}."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "negative_completeness",
            "missing_sources": missing,
        }

    # 2) Coverage window — when the claim declares a window, at least one searched
    #    source carrying a coverage_window must span it. A silent (out-of-coverage)
    #    log cannot ground a negative.
    dates = _claim_window_days(claim)
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
            return {
                "success": False,
                "error": (
                    f"Refusing UNCONFIRMED {category} finding: the searched log(s) cover "
                    f"{ranges} but the claim window ({', '.join(dates)}) is OUTSIDE that "
                    f"coverage — a negative cannot be drawn from a log that is silent about "
                    f"the window. Search a source that covers it: TerminalServices logs, "
                    f"Volume Shadow Copies, or carved EVTX from unallocated/pagefile/hiberfil."
                ),
                "description": ctx.description,
                "confidence": ctx.confidence,
                "gate": "negative_completeness",
            }

    return None
