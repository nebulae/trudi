"""Structured parser for the Windows device-install log (setupapi.dev.log).

The complete set of every device that ever touched a host is bounded and fully
recoverable from this log. The robust way to use it is to ENUMERATE, not search:
parse the whole log into one structured record per device, so a device cannot be
missed because a keyword/regex didn't match, a dump was truncated, or a
time-windowed grep anchored on the wrong line. A keyword search over a bounded
artifact can always miss; a complete enumeration cannot.

Detection rests on that completeness — every device is returned as a row (class,
vendor, product, VID:PID, interfaces, first/last seen), so even a device this
module does not classify is present and visible for the agent or a human to judge.
On top of the full inventory it raises a keystroke-injector flag via two lenses:
(1) a vendor-agnostic STRUCTURAL profile — a single physical device exposing BOTH
a keyboard/HID interface AND mass storage (a BadUSB with an on-board payload
partition); and (2) an IDENTITY profile — a self-identifying injector product/
vendor name (Rubber Ducky, Bash Bunny, Malduino, …) or a known BadUSB VID:PID,
which catches a storage-only device whose HID interface was never separately
logged. The flag is a hint; the inventory completeness is what's load-bearing.
"""
from __future__ import annotations

import re

# A device-event header: `>>>  [<Action> - <DeviceInstancePath>]`. The device
# IDENTITY lives on THIS line; the timestamp is on the FOLLOWING `Section start`
# line — i.e. the header precedes the section-start. We pair header -> next
# section-start, so a search anchored forward on "Section start" (which skips the
# header) cannot cause the device name to be lost.
_HEADER_RE = re.compile(r"^>>>\s+\[(.+?)\s+-\s+(.+)\]\s*$")
_SECTION_START_RE = re.compile(r"^>>>\s+Section start\s+(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)")

# Device-identity fields, extracted from the instance path.
_VID_RE = re.compile(r"VID_([0-9A-Fa-f]{4})")
_PID_RE = re.compile(r"PID_([0-9A-Fa-f]{4})")
_VEN_RE = re.compile(r"Ven_([^&#\\]+)", re.IGNORECASE)
_PROD_RE = re.compile(r"Prod_([^&#\\]+)", re.IGNORECASE)
_MI_RE = re.compile(r"&MI_([0-9A-Fa-f]{2})")

# Only these header actions denote a device being present/installed/removed.
_DEVICE_ACTIONS = ("device install", "delete device", "update device driver",
                    "restart device")


def _device_class(path: str) -> str:
    """Coarse device class from the instance-path prefix."""
    head = path.split("\\", 1)[0].upper()
    if head == "HID":
        return "HID"
    if head == "USBSTOR" or "USBSTOR#" in path.upper():
        return "USBSTOR"
    if head == "USB":
        return "USB"
    if head == "SWD":
        return "SWD"
    if head.startswith("STORAGE"):
        return "STORAGE"
    if head.startswith("SCSI"):
        return "SCSI"
    return head or "?"


def _identity_key(vid: str, pid: str, vendor: str, product: str, path: str) -> str:
    """Collapse the many interface/volume records for one physical device into a
    single inventory row. VID:PID groups composite interfaces; else fall back to
    vendor/product; else the raw path."""
    if vid:
        return f"vidpid:{vid}:{pid}"
    if vendor or product:
        return f"venprod:{vendor.lower()}:{product.lower()}"
    return f"path:{path.lower()}"


def parse_device_install_log(path: str) -> dict:
    """Parse setupapi.dev.log into a COMPLETE, de-duplicated device inventory.

    Returns:
        success: bool
        device_count: int                    # unique physical devices
        event_count: int                     # raw install/remove events parsed
        coverage_window: {start, end} | None # min/max event timestamp
                                             # ("YYYY-MM-DD HH:MM:SS", local log time)
        devices: [ {identity, device_class, vendor, product, vid, pid,
                    interfaces:[...], first_seen, last_seen, actions:[...]} ]
        flagged: [ subset of devices matching the structural keystroke-injector
                   profile, each with `flag_reasons` ]
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        return {"success": False, "error": str(exc)}

    events: list[dict] = []
    i = 0
    n = len(lines)
    while i < n:
        m = _HEADER_RE.match(lines[i])
        if not m:
            i += 1
            continue
        action, dev_path = m.group(1).strip(), m.group(2).strip()
        if not any(a in action.lower() for a in _DEVICE_ACTIONS):
            i += 1
            continue
        # Exclude driver-PACKAGE operations (DiInstallDriver on a .inf file path) —
        # those are driver installs, not device instances. A device instance path
        # never starts with a drive letter or ends in .inf.
        if re.match(r"^[A-Za-z]:\\", dev_path) or dev_path.lower().endswith(".inf"):
            i += 1
            continue
        # Timestamp is on the following Section start line (within a few lines).
        ts = None
        for j in range(i + 1, min(i + 4, n)):
            sm = _SECTION_START_RE.match(lines[j])
            if sm:
                ts = sm.group(1).replace("/", "-")
                break
        events.append({"action": action, "path": dev_path, "ts": ts})
        i += 1

    # Fold events into unique devices.
    devices: dict[str, dict] = {}
    for ev in events:
        p = ev["path"]
        vid = (_VID_RE.search(p).group(1).lower() if _VID_RE.search(p) else "")
        pid = (_PID_RE.search(p).group(1).lower() if _PID_RE.search(p) else "")
        vendor = (_VEN_RE.search(p).group(1) if _VEN_RE.search(p) else "")
        product = (_PROD_RE.search(p).group(1) if _PROD_RE.search(p) else "")
        key = _identity_key(vid, pid, vendor, product, p)
        d = devices.get(key)
        if d is None:
            d = devices[key] = {
                "identity": key, "vid": vid, "pid": pid,
                "vendor": vendor, "product": product,
                "device_class": _device_class(p),
                "interfaces": set(), "classes": set(),
                "first_seen": None, "last_seen": None, "actions": set(),
            }
        d["classes"].add(_device_class(p))
        mi = _MI_RE.search(p)
        if mi:
            d["interfaces"].add(mi.group(1))
        d["actions"].add(ev["action"])
        ts = ev["ts"]
        if ts:
            if d["first_seen"] is None or ts < d["first_seen"]:
                d["first_seen"] = ts
            if d["last_seen"] is None or ts > d["last_seen"]:
                d["last_seen"] = ts

    all_ts = sorted(ev["ts"] for ev in events if ev["ts"])
    coverage = {"start": all_ts[0], "end": all_ts[-1]} if all_ts else None

    out_devices = []
    flagged = []
    for d in devices.values():
        classes = d.pop("classes")
        d["device_class"] = "+".join(sorted(classes)) if classes else d["device_class"]
        d["interfaces"] = sorted(d["interfaces"])
        d["actions"] = sorted(d["actions"])
        reasons = _flag_reasons(classes, d)
        if reasons:
            d = {**d, "flag_reasons": reasons}
            flagged.append(d)
        out_devices.append(d)

    out_devices.sort(key=lambda x: (x.get("first_seen") or "", x["identity"]))
    return {
        "success": True,
        "device_count": len(out_devices),
        "event_count": len(events),
        "coverage_window": coverage,
        "devices": out_devices,
        "flagged": flagged,
    }


# Self-identifying keystroke-injector / BadUSB product & vendor name tokens.
# Such devices frequently enumerate ONLY as mass storage — their HID/keyboard
# interface is often not separately logged in setupapi.dev.log — so the structural
# HID+storage lens alone cannot see them. A self-identifying label is a reliable,
# low-false-positive catch: ordinary storage is not named "Rubber Ducky" or "Bash
# Bunny". Recall-first by design: a flag is a HINT that forces the analyst to
# disposition the device, not an automatic conviction, so occasionally surfacing a
# legitimately injector-branded peripheral for a one-line benign disposition is the
# safe trade.
_INJECTOR_NAME_RE = re.compile(
    r"(rubber[\s_-]?ducky|ducky[\s_-]?storage|\bducky\b|hak5|bash[\s_-]?bunny"
    r"|shark[\s_-]?jack|malduino|digispark|\bo\.?mg\b|omg[\s_-]?cable"
    r"|\bwhid\b|cactus[\s_-]?whid|pico[\s_-]?ducky|evil[\s_-]?crow"
    r"|usb[\s_-]?ninja|p4wnp1)",
    re.IGNORECASE,
)

# Extensible hook for known BadUSB VID:PID pairs (a device presents these
# regardless of the label it advertises). Deliberately EMPTY by default: a VID
# alone is never sufficient — injector firmware often presents a generic
# chip-vendor or shared hobby-board VID used by many benign devices, so shipping
# unverified pairs would tar legitimate hardware. Add specific, verified lowercase
# (vid, pid) pairs here per environment.
_INJECTOR_VIDPID: set[tuple[str, str]] = set()


def _flag_reasons(classes: set, device: dict) -> list[str]:
    """Reasons a device matches a keystroke-injector / BadUSB profile.

    Two independent lenses (a device need match only one):
      1. STRUCTURAL (vendor-agnostic): one physical device exposing BOTH a
         keyboard/HID interface AND mass storage — an injector with an on-board
         payload partition.
      2. IDENTITY: a self-identifying injector product/vendor name token, or a
         known BadUSB VID:PID. Catches a storage-only device whose HID interface
         was never separately logged — which the structural lens cannot see.
    """
    reasons: list[str] = []
    has_hid = "HID" in classes
    has_storage = bool({"USBSTOR", "STORAGE"} & classes)
    if has_hid and has_storage:
        reasons.append("composite HID + mass-storage device (keystroke-injector profile)")

    haystack = " ".join(str(device.get(k, "")) for k in ("vendor", "product", "identity"))
    nm = _INJECTOR_NAME_RE.search(haystack)
    if nm:
        reasons.append(f"self-identifying keystroke-injector name token: '{nm.group(1)}'")

    if (device.get("vid", ""), device.get("pid", "")) in _INJECTOR_VIDPID:
        reasons.append(f"known BadUSB VID:PID {device.get('vid')}:{device.get('pid')}")

    return reasons
