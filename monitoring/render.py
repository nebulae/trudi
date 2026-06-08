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
        "baseline_endpoints_ips": _vql_array(
            (ep["remote_ip"] for ep in (baseline.get("endpoints") or []))
        ),
        "baseline_endpoints_dst_pairs": _vql_array(
            (f"{ep['remote_ip']}:{ep['remote_port']}"
             for ep in (baseline.get("endpoints") or []))
        ),
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


def list_detector_templates() -> list[str]:
    """Detector artifact names available under artifacts/."""
    return sorted(
        f.stem.replace(".yaml", "")
        for f in ARTIFACTS_DIR.glob("Custom.TRUDI.*.yaml.tmpl")
        if not f.stem.startswith("Custom.TRUDI.Respond")
    )


def list_respond_artifacts() -> list[str]:
    """Remediation artifact names available under artifacts/."""
    return sorted(
        f.stem.replace(".yaml", "")
        for f in ARTIFACTS_DIR.glob("Custom.TRUDI.Respond.*.yaml")
    )
