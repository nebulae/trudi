"""TRUDI live-monitoring subsystem.

Contains:
  - artifacts/    Velociraptor artifact YAML templates for Custom.TRUDI.*
                  detectors (process exec, persistence, network, YARA) and
                  Custom.TRUDI.Respond.* remediation actions.
  - render.py     string.Template-based artifact rendering — substitutes
                  baseline allowlists into the parameterized VQL.
"""
