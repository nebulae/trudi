"""Replay of the correspondent-exhaustion check over real finished traces.

The VANKO runs blocked Report on ~94-96 "engaged correspondents", almost all
false positives (pffexport header labels, spam To: lists, inbound-only mail).
These tests replay those traces (copied — the case dir is never written) with
the agent's correspondent dispositions stripped, so the count is what the
check itself flags. Skipped where the case traces are not present; point
TRUDI_REPLAY_TRACES at a colon-separated list of trace paths to override.
"""
import os

import pytest

_DEFAULT = ":".join([
    "/home/trin/cases/vanko-deepseek41/analysis/VANKO-2016-DEEPSEEK41_trace.json",
    "/home/trin/cases/vanko-deepseek41/.trace-backups/20260924T010832Z/analysis/"
    "VANKO-2016-DEEPSEEK41_trace.json",
])
TRACES = [t for t in os.environ.get("TRUDI_REPLAY_TRACES", _DEFAULT).split(":")
          if t and os.path.isfile(t)]

LABELS = {"address type", "recipient type", "recipients", "email address"}
# addresses the subject genuinely wrote to — two-way in the legacy stamps, so
# the conservative legacy fallback still treats them as engaged
MUST_ENGAGE = {"vladimir.bulgakov@titan-biotech.com", "nina_kwai@qq.com",
               "mmerr001@gmail.com", "kylie.normandy@gmail.com"}
NOISE = {"so.all.customer.questions@wholefoods.com", "soknwcontacts@wholefoods.com",
         "echo123", "live:anthony.vanko"}


@pytest.mark.skipif(not TRACES, reason="VANKO replay traces not present")
@pytest.mark.parametrize("trace", TRACES)
def test_vanko_replay_flags_only_engaged(trace):
    from tools.correspondent_replay import replay
    r = replay(trace)
    flagged = set(r["flagged"])
    assert r["flagged_count"] < 40, r["flagged"]        # was 96 / 102 before the fix
    assert not (flagged & LABELS)
    assert not (flagged & NOISE)
    assert not (set(r["engaged_any_reference_state"]) & (LABELS | NOISE))
    assert MUST_ENGAGE <= set(r["engaged_any_reference_state"])
    # near-alias lead is still surfaced
    assert {"a": "nina_kwa1@qq.com", "b": "nina_kwai@qq.com"} in r["alias_leads"]
