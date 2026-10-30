"""Tests for the Acalvio ShadowPlex CEF → TRUDI alert ingest path:
monitoring/cef.py (parser + mapping + client resolution + emitter) and
bin/trudi-cef-ingest.py (the merge/queue sidecar, loaded via importlib because
the filename is hyphenated)."""
import importlib.util
import json
from pathlib import Path

import pytest

from monitoring import cef

_INGEST = Path(__file__).resolve().parents[2] / "bin" / "trudi-cef-ingest.py"


@pytest.fixture(scope="module")
def ingest():
    spec = importlib.util.spec_from_file_location("trudi_cef_ingest", _INGEST)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── The exact records from the published Splunk sample ───────────────────────

FUSED = (
    '<114>2026-07-10T11:37:57.010Z us-west '
    'CEF:0|Acalvio|ShadowPlex|2026.8.2.0|DETECT_AND_RESPOND|ENDPOINT_COMPROMISE|9|'
    'cat="Endpoint Compromise" cs2Label=incidentID cs2=9f1ffe81-1bb1-4018-bfec-349ddde4270a '
    'start="July 10 2026 11:36:57.130 UTC" end="July 10 2026 11:37:56.930 UTC" '
    'cs3Label=incidentStatus cs3=Active cs8Label=tacticName cs8="Lateral Movement,Discovery" '
    'cs10Label=techniqueName cs10="Remote Services.Remote Desktop Protocol,Network Service Discovery" '
    'cs15Label=srcIP cs15="192.0.2.97" cs25Label=dstIP cs25="192.0.2.59" '
    'cs26Label=dstEndpointName cs26="DESKTOP-GN-806" cs35Label=dstPort cs35=3389 '
    'cs52Label=userIdAttempted cs52="linda" cs67Label=callbackURL '
    'cs67="https://233.252.0.91/#/incidents?incidentID=9f1ffe81-1bb1-4018-bfec-349ddde4270a"'
)

# cs78's JSON is pretty-printed over several lines in the PDF; a real syslog
# record is one line. The parser must handle both — test the one-line form.
SERVICE = (
    'CEF:0|Acalvio|ShadowPlex|2026.8.2.0|DETECT_AND_RESPOND|SERVICE_INTERACTION|9|'
    'cs2Label=incidentID cs2=9f1ffe81-1bb1-4018-bfec-349ddde4270a cs78Label=event_data '
    'cs78={"user_name":"jsmith","service_details":{"host_mac":"98:90:96:a7:58:45",'
    '"remote_port":16817,"service_name":"MS-WBT-SERVER","service_port":3389,'
    '"auth_attempted":true,"client_host_ip":"172.16.0.2","remote_address":"192.0.2.215",'
    '"client_host_name":"WIN10-JSM","service_host_name":"DESKTOP-OU-060",'
    '"service_host_address":"198.51.100.102"}}'
)


class TestParse:
    def test_syslog_and_header(self):
        p = cef.parse_cef(FUSED)
        assert p["syslog"] == {"pri": 114, "timestamp": "2026-07-10T11:37:57.010Z", "host": "us-west"}
        assert p["header"]["device_vendor"] == "Acalvio"
        assert p["header"]["device_product"] == "ShadowPlex"
        assert p["header"]["event_class_id"] == "DETECT_AND_RESPOND"
        assert p["header"]["name"] == "ENDPOINT_COMPROMISE"
        assert p["header"]["severity"] == 9

    def test_label_resolution(self):
        f = cef.parse_cef(FUSED)["fields"]
        assert f["incidentID"] == "9f1ffe81-1bb1-4018-bfec-349ddde4270a"
        assert f["srcIP"] == "192.0.2.97"
        assert f["dstEndpointName"] == "DESKTOP-GN-806"
        assert f["userIdAttempted"] == "linda"
        assert f["dstPort"] == "3389"
        # the Label keys themselves must not leak into resolved fields
        assert "cs2Label" not in f and "cs2" not in f

    def test_callback_url_with_equals_and_fragment(self):
        f = cef.parse_cef(FUSED)["fields"]
        assert f["callbackURL"] == (
            "https://233.252.0.91/#/incidents?incidentID=9f1ffe81-1bb1-4018-bfec-349ddde4270a")

    def test_no_cef_marker_raises(self):
        with pytest.raises(ValueError):
            cef.parse_cef("<13>plain syslog, no CEF here")

    def test_multiline_cs78(self):
        # The PDF pretty-prints cs78 across lines; collapsed whitespace must still parse.
        multiline = SERVICE.replace('{"user_name"', '{\n  "user_name"').replace(',"remote_port"', ',\n  "remote_port"')
        q = cef.parse_cef(multiline)
        assert cef.is_service_interaction(q)
        fp = cef.service_interaction_to_fingerprint(q)
        assert fp["user_name"] == "jsmith"


class TestMapping:
    def test_evidence_fields(self):
        ev = cef.shadowplex_to_evidence(cef.parse_cef(FUSED))
        assert ev["source_ip"] == "192.0.2.97"          # the touching host
        assert ev["remote_ip"] == "192.0.2.59"          # the decoy (remote endpoint)
        assert ev["remote_port"] == 3389
        assert ev["decoy_name"] == "DESKTOP-GN-806"
        assert ev["honey_credential"] == "linda"
        assert ev["incident_id"] == "9f1ffe81-1bb1-4018-bfec-349ddde4270a"
        assert ev["attack_tactics"] == ["Lateral Movement", "Discovery"]

    def test_technique_name_to_id(self):
        ev = cef.shadowplex_to_evidence(cef.parse_cef(FUSED))
        assert ev["attack_technique_ids"] == ["T1021.001", "T1046"]

    def test_timestamp_normalised_to_utc_iso(self):
        ev = cef.shadowplex_to_evidence(cef.parse_cef(FUSED))
        assert ev["start_utc"] == "2026-07-10T11:36:57Z"
        assert ev["end_utc"] == "2026-07-10T11:37:56Z"
        assert ev["timestamp_utc"] == "2026-07-10T11:37:56Z"

    def test_severity_mapping(self):
        assert cef.severity_from_cef(9) == "high"
        assert cef.severity_from_cef(6) == "medium"
        assert cef.severity_from_cef(2) == "low"
        assert cef.severity_from_cef("garbage") == "medium"

    def test_fingerprint_and_merge(self):
        ev = cef.shadowplex_to_evidence(cef.parse_cef(FUSED))
        fp = cef.service_interaction_to_fingerprint(cef.parse_cef(SERVICE))
        assert fp["user_name"] == "jsmith"
        assert fp["host_mac"] == "98:90:96:a7:58:45"
        assert fp["source_port"] == 16817
        merged = cef.merge_fingerprint(ev, fp)
        assert merged["client_fingerprint"]["client_host_name"] == "WIN10-JSM"
        assert merged["source_port"] == 16817          # filled from fingerprint

    def test_unparsable_timestamp_returns_none(self):
        assert cef.to_utc_iso("not a date") is None
        assert cef.to_utc_iso(None) is None


class TestResolveClient:
    CLIENTS = [
        {"client_id": "C.aaa", "hostname": "victim-a", "last_ip": "172.20.0.4:5555", "last_seen_at": "100"},
        {"client_id": "C.bbb", "hostname": "victim-b", "last_ip": "172.20.0.5:5555", "last_seen_at": "200"},
        {"client_id": "C.old", "hostname": "victim-a", "last_ip": "172.20.0.9:5555", "last_seen_at": "50"},
    ]

    def test_source_map_wins(self):
        r = cef.resolve_client(self.CLIENTS, source_ip="10.73.0.3", client_host_name="victim-a",
                               source_map={"10.73.0.3": "C.mapped"})
        assert r["client_id"] == "C.mapped" and r["method"] == "source_map"

    def test_source_map_by_hostname_label(self):
        r = cef.resolve_client(self.CLIENTS, source_ip=None, client_host_name="trudi-victim-a.lan",
                               source_map={"victim-a": "C.mapped"})
        assert r["client_id"] == "C.mapped"

    def test_hostname_match_prefers_recent(self):
        r = cef.resolve_client(self.CLIENTS, source_ip=None, client_host_name="victim-a")
        assert r["client_id"] == "C.aaa" and r["method"] == "hostname"

    def test_last_ip_fallback(self):
        r = cef.resolve_client(self.CLIENTS, source_ip="172.20.0.5", client_host_name="unknown-host")
        assert r["client_id"] == "C.bbb" and r["method"] == "last_ip"

    def test_unresolved(self):
        r = cef.resolve_client(self.CLIENTS, source_ip="203.0.113.7", client_host_name="nope")
        assert r["client_id"] is None and r["matched"] is False
        assert "note" in r


class TestEmitRoundTrip:
    def test_format_then_parse(self):
        line = cef.format_cef(
            vendor="Acalvio", product="ShadowPlex", version="2026.8.2.0",
            event_class_id="DETECT_AND_RESPOND", name="ENDPOINT_COMPROMISE", severity=9,
            extension=[("cat", "Endpoint Compromise"), ("cs15Label", "srcIP"),
                       ("cs15", "10.73.0.3"), ("cs35Label", "dstPort"), ("cs35", 3389)])
        f = cef.parse_cef(line)["fields"]
        assert f["srcIP"] == "10.73.0.3"
        assert f["dstPort"] == "3389"
        assert f["cat"] == "Endpoint Compromise"


class TestIncidentBuffer:
    def _buffer(self, ingest, tmp_path):
        alerts = tmp_path / "monitoring" / "alerts"
        alerts.mkdir(parents=True)
        resolver = ingest.ClientResolver(api_config=None, velo_bin="velociraptor",
                                         source_map={"192.0.2.97": "C.src"}, enabled=False)
        # enabled=False → no velo call; but source_map still resolves.
        resolver.enabled = True   # allow source_map path (which never shells out)
        resolver._clients = []    # and no clients → only source_map can match
        buf = ingest.IncidentBuffer(alerts, "CASE", resolver, merge_window=0.0)
        return alerts, buf

    def test_two_records_merge_into_one_alert(self, ingest, tmp_path):
        alerts, buf = self._buffer(ingest, tmp_path)
        buf.ingest_line(FUSED)
        buf.ingest_line(SERVICE)      # same incidentID → merged immediately
        buf.flush_all()
        files = sorted(alerts.glob("*_DecoyTouch.json"))
        assert len(files) == 1, f"expected one merged alert, got {[f.name for f in files]}"
        alert = json.loads(files[0].read_text())
        assert alert["detector"] == "Custom.TRUDI.DecoyTouch"
        assert alert["severity"] == "high"
        ev = alert["evidence"]
        assert ev["source_ip"] == "192.0.2.97"
        assert ev["honey_credential"] == "linda"
        assert ev["client_fingerprint"]["user_name"] == "jsmith"
        assert alert["client_id"] == "C.src"            # resolved via source_map
        assert len(alert["raw_cef"]) == 2

    def test_fused_only_still_alerts(self, ingest, tmp_path):
        alerts, buf = self._buffer(ingest, tmp_path)
        buf.ingest_line(FUSED)
        buf.flush_all()
        files = sorted(alerts.glob("*_DecoyTouch.json"))
        assert len(files) == 1
        alert = json.loads(files[0].read_text())
        assert alert["evidence"]["honey_credential"] == "linda"
        assert "client_fingerprint" not in alert["evidence"] or \
               alert["evidence"].get("client_fingerprint") is None

    def test_late_fingerprint_folds_into_written_alert(self, ingest, tmp_path):
        alerts, buf = self._buffer(ingest, tmp_path)
        buf.ingest_line(FUSED)
        buf.flush_all()                 # alert written without fingerprint
        buf.ingest_line(SERVICE)        # arrives late, same incidentID
        files = sorted(alerts.glob("*_DecoyTouch.json"))
        assert len(files) == 1          # folded in place, not a second alert
        alert = json.loads(files[0].read_text())
        assert alert["evidence"]["client_fingerprint"]["user_name"] == "jsmith"
