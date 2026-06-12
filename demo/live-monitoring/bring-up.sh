#!/usr/bin/env bash
# TRUDI live-monitoring — one-command bring-up.
#
# Starts the compose stack (unless --no-up), then performs the manual
# post-boot steps the README otherwise lists by hand, idempotently:
#   1. wait for the Velociraptor server API config + pull it to the SIFT host
#   2. wait for the victim's TRUDI SSH key + pull it to ~/.ssh/
#   3. MERGE the trudi-victim entry into ~/cases/.common/live_hosts.json
#      (preserving any other hosts already registered)
#   4. smoke-test the SSH path live.* will use
#
# After `docker compose down -v`, the victim regenerates its keypair, so just
# re-run this script — it re-pulls the new key and leaves live.* working.
#
# Usage:
#   ./bring-up.sh                 # compose up --build, then wire everything
#   ./bring-up.sh --no-up         # skip compose up (stack already running)
#   ./bring-up.sh --no-build      # compose up without --build
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Connection facts — must match docker-compose.yaml (2222:22) and the victim
# Dockerfile (user "victim", key at /shared/trudi_live).
HOST_ALIAS="trudi-victim"
SSH_USER="victim"
SSH_HOST="localhost"
SSH_PORT="2222"
KEY_PATH="$HOME/.ssh/trudi_live"
HOSTS_CONFIG="$HOME/cases/.common/live_hosts.json"
API_CONFIG="$HOME/.config/trudi/velociraptor/api.config.yaml"

DO_UP=1
BUILD_FLAG="--build"
for arg in "$@"; do
    case "$arg" in
        --no-up)    DO_UP=0 ;;
        --no-build) BUILD_FLAG="" ;;
        -h|--help)  grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}  ✓${NC} $*"; }
warn() { echo -e "${YELLOW}  !${NC} $*"; }
fail() { echo -e "${RED}  ✗${NC} $*"; exit 1; }
step() { echo -e "\n${GREEN}▶${NC} $*"; }

command -v docker >/dev/null 2>&1 || fail "docker not found"
docker info >/dev/null 2>&1 || fail "docker daemon not reachable (permission or not running)"

# ── 1. Start the stack ────────────────────────────────────────────────────────
if [ "$DO_UP" -eq 1 ]; then
    step "Starting compose stack"
    # shellcheck disable=SC2086
    docker compose up -d $BUILD_FLAG
    ok "compose up issued"
else
    step "Skipping compose up (--no-up)"
fi

# ── 2. Velociraptor API config ────────────────────────────────────────────────
step "Pulling Velociraptor API config"
mkdir -p "$(dirname "$API_CONFIG")"
for i in $(seq 1 60); do
    if docker compose cp velo-server:/config/api.config.yaml "$API_CONFIG" 2>/dev/null; then
        ok "API config → $API_CONFIG"
        break
    fi
    [ "$i" -eq 60 ] && fail "timed out waiting for velo-server:/config/api.config.yaml"
    sleep 2
done

# ── 3. Victim SSH key ─────────────────────────────────────────────────────────
step "Pulling victim SSH key"
for i in $(seq 1 60); do
    if docker compose cp victim:/shared/trudi_live "$KEY_PATH" 2>/dev/null; then
        docker compose cp victim:/shared/trudi_live.pub "$KEY_PATH.pub" 2>/dev/null || true
        chmod 600 "$KEY_PATH"
        [ -f "$KEY_PATH.pub" ] && chmod 644 "$KEY_PATH.pub"
        ok "SSH key → $KEY_PATH"
        break
    fi
    [ "$i" -eq 60 ] && fail "timed out waiting for victim:/shared/trudi_live (first boot can take ~30s)"
    sleep 2
done

# ── 4. Register the host (merge, don't clobber) ───────────────────────────────
step "Registering $HOST_ALIAS in live_hosts.json"
mkdir -p "$(dirname "$HOSTS_CONFIG")"
HOSTS_CONFIG="$HOSTS_CONFIG" \
HOST_ALIAS="$HOST_ALIAS" SSH_USER="$SSH_USER" SSH_HOST="$SSH_HOST" \
SSH_PORT="$SSH_PORT" KEY_PATH="$KEY_PATH" \
python3 - <<'PYEOF'
import json, os
from pathlib import Path

cfg_path = Path(os.environ["HOSTS_CONFIG"])
hosts = {}
if cfg_path.exists():
    try:
        hosts = json.loads(cfg_path.read_text()) or {}
    except (json.JSONDecodeError, ValueError):
        # Don't silently wipe a malformed file — bail loudly.
        raise SystemExit(f"  ✗ {cfg_path} exists but is not valid JSON; fix or remove it")

alias = os.environ["HOST_ALIAS"]
# Store the key path with ~ for portability (core/ssh.py expanduser's it).
identity = os.environ["KEY_PATH"].replace(str(Path.home()), "~", 1)
entry = {
    "user": os.environ["SSH_USER"],
    "host": os.environ["SSH_HOST"],
    "port": int(os.environ["SSH_PORT"]),
    "identity": identity,
}
if hosts.get(alias) == entry:
    print(f"  {alias} already registered (unchanged)")
else:
    hosts[alias] = entry
    cfg_path.write_text(json.dumps(hosts, indent=2) + "\n")
    others = [k for k in hosts if k != alias]
    print(f"  wrote {alias} (preserved: {others or 'none'})")
PYEOF
ok "live_hosts.json updated"

# ── 5. Smoke test ─────────────────────────────────────────────────────────────
step "SSH smoke test"
if ssh -i "$KEY_PATH" \
       -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 \
       -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" 'hostname; id -un' 2>/dev/null; then
    ok "live.* SSH path is up ($SSH_USER@$SSH_HOST:$SSH_PORT)"
else
    warn "SSH smoke test failed — sshd may still be starting. Retry in a few seconds:"
    echo "    ssh -i $KEY_PATH -p $SSH_PORT $SSH_USER@$SSH_HOST id"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}  Live endpoint ready.${NC}"
echo "  Velociraptor client_id:"
echo "    velociraptor --api_config $API_CONFIG \\"
echo "        query --format=json \"SELECT client_id, os_info.hostname FROM clients()\""
echo "  Then update DEMO-LIVE/CLAUDE.md + ~/cases/.common/active_case if the client_id changed."
echo ""
