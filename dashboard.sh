#!/usr/bin/env bash
# dashboard.sh — start the persistent multi-case TRUDI trace dashboard.
#
# Thin wrapper around bin/trudi-dashboard so you can launch from the repo
# root without needing the symlink in /usr/local/bin to be installed:
#
#   ./dashboard.sh                       # ~/cases on :8765
#   ./dashboard.sh --port 9090
#   ./dashboard.sh --cases-root /data/cases
#
# Environment:
#   TRUDI_CASES_ROOT      default cases root (fallback: ~/cases)
#   TRUDI_DASHBOARD_PORT  default port       (fallback: 8765)

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$HERE/bin/trudi-dashboard" "$@"
