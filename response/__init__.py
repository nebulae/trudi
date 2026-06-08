"""Response subsystem — gated containment & eradication.

Three pieces:
  - recipes/<detector>.yaml   per-detector list of action templates
  - gates.py                  approval/scope checks for respond.* tools
  - (artifacts live under monitoring/artifacts/Custom.TRUDI.Respond.*.yaml
    so the renderer + uploader treat them the same as detectors)
"""
