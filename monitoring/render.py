"""Render Custom.TRUDI.* artifact YAMLs by substituting baseline allowlists.

The artifact templates use ``string.Template``-style ``$identifier`` /
``${identifier}`` placeholders. The renderer takes a baseline dict (loaded
from ``<case>/monitoring/baselines/<client_id>.json``) and produces a fully
populated YAML string ready to pass to ``velo.upload_artifact_yaml``.

We intentionally avoid Jinja — stdlib only, audit-friendly. Allowlists are
inserted as JSON-encoded literal arrays so the VQL parser sees a valid
expression and operators never have to think about escaping.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
from string import Template
from typing import Any, Mapping

ARTIFACTS_DIR = Path(__file__).parent / "artifacts"

# Canonical persistence watch surface — the ONE source of truth shared by the
# Custom.TRUDI.NewPersistence detector (via ${watch_dirs}) and the
# Custom.TRUDI.PersistenceSnapshot baseline helper (via monitor.baseline_capture).
# Both must glob the SAME paths or the baseline allowlist won't match what the
# detector watches (the empty-allowlist false-positive bug).
PERSISTENCE_WATCH_GLOBS = [
    "/etc/crontab",
    "/etc/anacrontab",
    "/etc/cron.d/*",
    "/etc/cron.hourly/*",
    "/etc/cron.daily/*",
    "/etc/cron.weekly/*",
    "/etc/cron.monthly/*",
    "/etc/systemd/system/*",
    "/var/spool/cron/crontabs/*",
]


# Cron daemon images used when a baseline carries no `cron_daemon_images`
# (captured before the field existed, or no cron daemon was running).
DEFAULT_CRON_DAEMON_IMAGES = ["/usr/sbin/cron", "/usr/sbin/crond"]

# ── Scheduled-work exemption heuristics (single source of truth) ────────────
#
# These two regexes gate the NewProcess detector's scheduled-work exemption and
# are mirrored in Python by tools.monitor (verify_clean) — both import them from
# here so the live detector and the post-eradication sweep can never drift.
#
# TRUSTED_BIN_REGEX: the standard trusted-execution prefixes a cron-descended
# process may run from without alerting — the system bin dirs PLUS the
# operator-software locations real hosts use (/usr/local, /opt). A cron job
# launching a binary OUTSIDE these (e.g. from a home dir or a writable tmp dir)
# is not exempted. Narrower sets caused false positives on legitimate
# /usr/local and /opt scheduled jobs that were not running at baseline time.
#
# DROP_PATH_REGEX: world-writable / transient staging locations in a command
# line that VOID the exemption even for a trusted-bin interpreter — the classic
# "cron runs /usr/bin/python3 /tmp/payload" abuse. Restricted to genuinely
# world-writable dirs (/tmp, /var/tmp, /dev/shm); /home and /root were removed
# because legitimate user and root crontabs reference binaries there and are not
# attacker-staging locations.
#
# These are the DEFAULTS. Both are detector parameters, so an operator can
# override either per client without editing code.
TRUSTED_BIN_REGEX = r"^/(usr/(local/)?)?s?bin/|^/opt/"
DROP_PATH_REGEX = r"(^|\s)/(tmp|var/tmp|dev/shm)/"


def _vql_array(values) -> str:
    """Render a Python iterable as a VQL array literal."""
    return "[" + ", ".join(json.dumps(v) for v in values) + "]"


def render_template(name: str, baseline: Mapping[str, Any]) -> str:
    """Render the artifact whose source file is ``<name>.yaml.tmpl``.

    name: artifact name (e.g. "Custom.TRUDI.NewProcess").
    baseline: dict with the allowlist fields the template expects.

    The mapping the renderer feeds Template.substitute is built up from
    well-known baseline keys, falling back to empty arrays if absent so
    a partial baseline still produces a valid YAML (the resulting filter
    just allows nothing through, which is conservative).
    """
    src = ARTIFACTS_DIR / f"{name}.yaml.tmpl"
    if not src.exists():
        raise FileNotFoundError(f"artifact template not found: {src}")

    mapping = {
        "artifact_name": name,
        "baseline_proc_names": _vql_array(baseline.get("process_names") or []),
        "baseline_image_paths": _vql_array(baseline.get("image_paths") or []),
        "baseline_persistence_paths": _vql_array(
            baseline.get("persistence_paths") or []
        ),
        "baseline_persistence_fingerprints": _vql_array(
            baseline.get("persistence_fingerprints") or []),
        # Watch dirs come from the canonical constant, not the baseline, so the
        # detector and the PersistenceSnapshot helper always glob the same set.
        "watch_dirs": _vql_array(PERSISTENCE_WATCH_GLOBS),
        "baseline_endpoints_ips": _vql_array(
            (ep["remote_ip"] for ep in (baseline.get("endpoints") or []))
        ),
        "baseline_endpoints_dst_pairs": _vql_array(
            (f"{ep['remote_ip']}:{ep['remote_port']}"
             for ep in (baseline.get("endpoints") or []))
        ),
        # Lateral-movement / privesc detector allowlists (empty → the detector
        # allows nothing, which is conservative: a bare baseline still renders
        # valid VQL and just filters everything out).
        "baseline_logon_sources": _vql_array(baseline.get("logon_sources") or []),
        "baseline_root_image_paths": _vql_array(baseline.get("root_image_paths") or []),
        # Windows baseline allowlists (Custom.TRUDI.Win.* detectors). Empty on a
        # Linux baseline, which is fine — Windows templates are never rendered
        # for a Linux client (see list_detector_templates).
        "baseline_autoruns": _vql_array(baseline.get("autoruns") or []),
        # Cron daemon image(s) — the NewProcess scheduled-work exemption walks a
        # process's ancestry looking for one of these. Defaults to the stock
        # Debian/RHEL paths when the baseline predates the field.
        "baseline_cron_images": _vql_array(
            baseline.get("cron_daemon_images") or DEFAULT_CRON_DAEMON_IMAGES),
        # Scheduled-work exemption regexes — emitted as JSON-encoded (double-
        # quoted) YAML scalars so backslash escapes survive the YAML parse into
        # the VQL `=~` operand. The canonical patterns live above.
        "scheduled_work_bin_regex": json.dumps(TRUSTED_BIN_REGEX),
        "drop_path_regex": json.dumps(DROP_PATH_REGEX),
        "yara_rules_path": baseline.get("yara_rules_path") or "/rules/trudi-demo.yar",
    }

    template = Template(src.read_text())
    return template.safe_substitute(mapping)


def render_all(baseline: Mapping[str, Any], detectors: list[str]) -> dict[str, str]:
    """Render every requested detector template; return {name: yaml_text}."""
    out: dict[str, str] = {}
    for d in detectors:
        out[d] = render_template(d, baseline)
    return out


def detector_parameters(name: str, baseline: Mapping[str, Any]) -> dict[str, str]:
    """Extract per-client parameter values; shared definitions use empty defaults.

    Keep this derived from the rendered template so adding a detector parameter
    cannot silently drop it on the label-scoped deployment path.
    """
    import yaml
    doc = yaml.safe_load(render_template(name, baseline))
    return {p["name"]: str(p["default"]).strip() for p in doc.get("parameters", [])
            if "default" in p}


def list_detector_templates(os_family: str = "linux") -> list[str]:
    """Detector artifact names available under artifacts/, for one OS family.

    Windows detectors are namespaced `Custom.TRUDI.Win.*`; Linux detectors are
    the unprefixed `Custom.TRUDI.*`. A client only ever gets the set matching
    its OS, so a Linux host is never handed a Windows (`pslist()` / `watch_evtx`)
    detector and vice-versa. `Respond.*` remediation artifacts are never
    detectors.
    """
    names = [
        f.stem.replace(".yaml", "")
        for f in ARTIFACTS_DIR.glob("Custom.TRUDI.*.yaml.tmpl")
        if not f.stem.startswith("Custom.TRUDI.Respond")
    ]
    is_win = lambda n: n.startswith("Custom.TRUDI.Win.")
    if os_family == "windows":
        return sorted(n for n in names if is_win(n))
    return sorted(n for n in names if not is_win(n))


def list_respond_artifacts() -> list[str]:
    """Remediation artifact names available under artifacts/."""
    return sorted(
        f.stem.replace(".yaml", "")
        for f in ARTIFACTS_DIR.glob("Custom.TRUDI.Respond.*.yaml")
    )
