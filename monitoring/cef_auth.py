"""Authenticated CEF envelopes, preserved verbatim through forwarding relays.

Raw vendor syslog remains usable for collection. Automatic response requires
a signed envelope from a configured sender AND an explicit source/decoy binding.
Keys are files, never values in command lines or alert records.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import sqlite3
import time
import uuid
from pathlib import Path

from monitoring import cef


def _message(sender: str, timestamp: int, nonce: str, line: str) -> bytes:
    return f"TRUDI-CEF-1\n{sender}\n{timestamp}\n{nonce}\n{line}".encode("utf-8")


def sign(line: str, sender: str, key: bytes, *, timestamp: int | None = None,
         nonce: str | None = None) -> str:
    if len(key) < 32 or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", sender):
        raise ValueError("CEF signing requires a sender id and at least 32 key bytes")
    ts = int(time.time()) if timestamp is None else timestamp
    nonce = nonce or uuid.uuid4().hex
    signature = hmac.new(key, _message(sender, ts, nonce, line), hashlib.sha256).hexdigest()
    return json.dumps({"trudi_cef": 1, "sender": sender, "timestamp": ts,
                       "nonce": nonce, "cef": line, "signature": signature}, ensure_ascii=False)


def sender_config(case_dir: Path, sender: str) -> dict:
    try:
        cfg = json.loads((case_dir / "monitoring" / "config.json").read_text())
        config = cfg["cef_ingest"]["senders"][sender]
        return config if isinstance(config, dict) else {}
    except (OSError, ValueError, KeyError, TypeError):
        return {}


def verify(envelope: dict, case_dir: Path, *, freshness: bool = True) -> dict:
    """Verify signature; live callers also persist nonce claims before processing.

    A saved alert can be re-authorized later without imposing a new delivery
    deadline. Its signature and current sender/endpoint configuration still apply.
    """
    sender, ts, nonce, line = (envelope.get(k) for k in ("sender", "timestamp", "nonce", "cef"))
    if envelope.get("trudi_cef") != 1 or not isinstance(sender, str) \
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", sender) \
            or type(ts) is not int or not isinstance(nonce, str) \
            or not re.fullmatch(r"[0-9a-f]{32}", nonce) or not isinstance(line, str):
        raise ValueError("invalid CEF envelope")
    config = sender_config(case_dir, sender)
    try:
        key = Path(config["key_file"]).expanduser().read_bytes().strip()
    except (OSError, KeyError, TypeError):
        raise ValueError("unknown CEF sender or unavailable key") from None
    expected = hmac.new(key, _message(sender, ts, nonce, line), hashlib.sha256).hexdigest()
    signature = envelope.get("signature")
    if len(key) < 32 or not isinstance(signature, str) or not hmac.compare_digest(expected, signature):
        raise ValueError("invalid CEF signature")
    if freshness and abs(time.time() - ts) > 300:
        raise ValueError("stale CEF envelope")
    return config


def claim_nonce(envelope: dict, case_dir: Path) -> None:
    """Persist replay protection across ingest restarts and concurrent listeners."""
    path = case_dir / "monitoring" / "cef-replays.sqlite"
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path, timeout=10) as db:
        db.execute("CREATE TABLE IF NOT EXISTS seen (sender TEXT, nonce TEXT, ts INTEGER, PRIMARY KEY(sender,nonce))")
        db.execute("DELETE FROM seen WHERE ts < ?", (int(time.time()) - 600,))
        try:
            db.execute("INSERT INTO seen VALUES (?,?,?)",
                       (envelope["sender"], envelope["nonce"], envelope["timestamp"]))
        except sqlite3.IntegrityError:
            raise ValueError("replayed CEF envelope") from None


def is_shadowplex(parsed: dict) -> bool:
    h, f = parsed["header"], parsed["fields"]
    return h.get("device_vendor") == "Acalvio" and h.get("device_product") == "ShadowPlex" \
        and h.get("event_class_id") == "DETECT_AND_RESPOND" \
        and h.get("name") in {"ENDPOINT_COMPROMISE", "DISCOVERY", "SERVICE_INTERACTION"} \
        and bool(f.get("incidentID"))


def bound_client(parsed: dict, config: dict) -> str | None:
    """Only a fused, valid incident bound to this sensor can authorize response."""
    if not is_shadowplex(parsed) or cef.is_service_interaction(parsed):
        return None
    ev = cef.shadowplex_to_evidence(parsed)
    try:
        ipaddress.ip_address(ev["source_ip"])
        ipaddress.ip_address(ev["remote_ip"])
        if not 0 < ev["remote_port"] <= 65535:
            return None
    except (ValueError, TypeError):
        return None
    clients = config.get("source_clients") or {}
    client = clients.get(ev["source_ip"]) if isinstance(clients, dict) else None
    if not isinstance(client, str) or not re.fullmatch(r"C\.[A-Za-z0-9_-]+", client):
        return None
    if f"{ev['remote_ip']}:{ev['remote_port']}" not in (config.get("decoy_endpoints") or []):
        return None
    return client


def authorize_alert(case_dir: Path, alert: dict, evidence: dict,
                     client_id: str | None) -> bool:
    """Recompute trust from the signature, not an agent-supplied boolean."""
    try:
        if alert.get("replay"):
            return False
        envelope = alert["ingress_envelope"]
        config = verify(envelope, case_dir, freshness=False)
        parsed = cef.parse_cef(envelope["cef"])
        client = bound_client(parsed, config)
        signed = cef.shadowplex_to_evidence(parsed)
        return bool(client) and client == client_id == alert.get("client_id") \
            and signed.get("incident_id") == (alert.get("evidence") or {}).get("incident_id") \
            and all(str(evidence.get(k)) == str(signed.get(k))
                    for k in ("source_ip", "remote_ip", "remote_port", "incident_id"))
    except (KeyError, ValueError, TypeError, AttributeError):
        return False
