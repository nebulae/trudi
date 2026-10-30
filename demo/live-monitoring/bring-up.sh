#!/usr/bin/env bash
# TRUDI live-monitoring — one-command bring-up.
#
# Starts the compose stack (unless --no-up), then performs the manual
# post-boot steps the README otherwise lists by hand, idempotently:
#   1. wait for the Velociraptor server API config + pull it to the SIFT host
#   2. wait for the victim's TRUDI SSH key + pull it; clear the rotated host key
#   3. MERGE the trudi-victim entry into ~/cases/.common/live_hosts.json
#      (preserving any other hosts already registered)
#   4. smoke-test the SSH path live.* will use
#
# After `docker compose down -v` (or a rebuild) the victim regenerates its
# keypair AND its host identity, so just re-run this script — it re-pulls the
# new key, forgets the stale host key, and leaves live.* working.
#
# sudo: docker usually needs root (the invoking user often isn't in the docker
# group). This script is sudo-safe — it detects $SUDO_USER and writes all wired
# files into THAT user's home (not /root), chown'd back to them. So
# `sudo ./bring-up.sh` does the right thing.
#
# Usage:
#   ./bring-up.sh                 # compose up --build, then wire everything
#   sudo ./bring-up.sh            # same, when docker needs root
#   ./bring-up.sh --no-up         # skip compose up (stack already running)
#   ./bring-up.sh --no-build      # compose up without --build
#   ./bring-up.sh --profiles lateral,decoy   # bring up profiled hosts too;
#                                 # use this instead of COMPOSE_PROFILES=...,
#                                 # which sudo strips from the environment.
#   sudo ./bring-up.sh --profiles lateral,decoy   # the full lateral + decoy demo
#   sudo ./bring-up.sh --profiles lateral,winrdp  # lateral + the real Windows RDP victim
#                                 # (first Windows boot: ~6 GB pull + ~10-20 min
#                                 # install; the Velociraptor Windows client
#                                 # auto-enrolls — no SSH wiring needed)
#   sudo ./bring-up.sh --profiles lateral,winrdp,windecoy  # the real-Windows
#                                 # DECOY demo: adds the CEF relay; the Windows box
#                                 # is a honeypot touched with the honey credential
#                                 # 'linda' (drive with the WINDECOY-DEMO case)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Resolve the REAL (invoking) user + home, even under sudo ──────────────────
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    REAL_USER="$SUDO_USER"
    REAL_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
else
    REAL_USER="$(id -un)"
    REAL_HOME="$HOME"
fi
# Run a command as the real user (no-op when we're already that user).
as_user() {
    if [ "$(id -u)" -eq 0 ] && [ "$REAL_USER" != "root" ]; then
        sudo -u "$REAL_USER" "$@"
    else
        "$@"
    fi
}
# chown a path back to the real user (no-op when we're not root).
own() {
    if [ "$(id -u)" -eq 0 ] && [ "$REAL_USER" != "root" ]; then
        chown "$REAL_USER:" "$@" 2>/dev/null || true
    fi
}

# Connection facts — must match docker-compose.yaml (container names, 2222:22)
# and the victim Dockerfile (user "victim", key at /shared/trudi_live).
HOST_ALIAS="trudi-victim"
SSH_USER="victim"
SSH_HOST="localhost"
SSH_PORT="2222"
VICTIM_CTR="trudi-victim"
SERVER_CTR="trudi-velo-server"
KEY_PATH="$REAL_HOME/.ssh/trudi_live"
HOSTS_CONFIG="$REAL_HOME/cases/.common/live_hosts.json"
API_CONFIG="$REAL_HOME/.config/trudi/velociraptor/api.config.yaml"

DO_UP=1
BUILD_FLAG="--build"
# --profiles survives sudo, which strips COMPOSE_PROFILES from the environment
# (the usual reason `sudo COMPOSE_PROFILES=... ./bring-up.sh` brings up nothing
# profiled). When given, it sets COMPOSE_PROFILES for the compose calls below.
while [ $# -gt 0 ]; do
    case "$1" in
        --no-up)       DO_UP=0 ;;
        --no-build)    BUILD_FLAG="" ;;
        --profiles)    shift; export COMPOSE_PROFILES="${1:?--profiles needs a value, e.g. lateral,decoy}" ;;
        --profiles=*)  export COMPOSE_PROFILES="${1#*=}" ;;
        -h|--help)     grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
    shift
done

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}  ✓${NC} $*"; }
warn() { echo -e "${YELLOW}  !${NC} $*"; }
fail() { echo -e "${RED}  ✗${NC} $*"; exit 1; }
step() { echo -e "\n${GREEN}▶${NC} $*"; }

command -v docker >/dev/null 2>&1 || fail "docker not found"
docker info >/dev/null 2>&1 || fail "docker daemon not reachable (try: sudo ./bring-up.sh)"

echo "  wiring files into ${REAL_HOME} (user ${REAL_USER})"

# ── 1. Start the stack ────────────────────────────────────────────────────────
if [ "$DO_UP" -eq 1 ]; then
    step "Starting compose stack"
    # Profiles are read from COMPOSE_PROFILES (docker compose honors it natively):
    #   COMPOSE_PROFILES=lateral        ./bring-up.sh   # two-host lateral demo
    #   COMPOSE_PROFILES=lateral,decoy  ./bring-up.sh   # + the ShadowPlex decoy
    # The decoy needs no SIFT-side wiring (it only emits CEF/syslog); start the
    # ingest with monitor.start_cef_ingest / the DECOY-DEMO case.
    [ -n "${COMPOSE_PROFILES:-}" ] && echo "  compose profiles: ${COMPOSE_PROFILES}"
    as_user python3 "$SCRIPT_DIR/scripts/prepare-cef-keys.py"
    # shellcheck disable=SC2086
    docker compose up -d $BUILD_FLAG
    ok "compose up issued"
else
    step "Skipping compose up (--no-up)"
fi

# ── 2. Velociraptor API config ────────────────────────────────────────────────
# `docker cp <container>` (by name) is more robust than `docker compose cp
# <service>` — it doesn't depend on compose project resolution, which flaked
# under sudo.
step "Pulling Velociraptor API config"
as_user mkdir -p "$(dirname "$API_CONFIG")"
for i in $(seq 1 60); do
    if docker cp "$SERVER_CTR:/config/api.config.yaml" "$API_CONFIG" 2>/dev/null; then
        own "$API_CONFIG"
        ok "API config → $API_CONFIG"
        break
    fi
    [ "$i" -eq 60 ] && fail "timed out waiting for $SERVER_CTR:/config/api.config.yaml"
    sleep 2
done

# ── 3. Victim SSH key (+ forget the rotated host key) ─────────────────────────
step "Pulling victim SSH key"
as_user mkdir -p "$(dirname "$KEY_PATH")"
for i in $(seq 1 60); do
    if docker cp "$VICTIM_CTR:/shared/trudi_live" "$KEY_PATH" 2>/dev/null; then
        docker cp "$VICTIM_CTR:/shared/trudi_live.pub" "$KEY_PATH.pub" 2>/dev/null || true
        own "$KEY_PATH" "$KEY_PATH.pub"
        chmod 600 "$KEY_PATH"
        [ -f "$KEY_PATH.pub" ] && chmod 644 "$KEY_PATH.pub"
        ok "SSH key → $KEY_PATH"
        break
    fi
    [ "$i" -eq 60 ] && fail "timed out waiting for $VICTIM_CTR:/shared/trudi_live (first boot can take ~30s)"
    sleep 2
done
# The container's host key changes on rebuild; StrictHostKeyChecking=accept-new
# (used by core/ssh.py) FAILS on a changed key, so forget the old one.
as_user ssh-keygen -R "[$SSH_HOST]:$SSH_PORT" >/dev/null 2>&1 || true
ok "cleared stale host key for [$SSH_HOST]:$SSH_PORT"

# ── 4. Register the host (merge, don't clobber) ───────────────────────────────
step "Registering $HOST_ALIAS in live_hosts.json"
as_user mkdir -p "$(dirname "$HOSTS_CONFIG")"
as_user env HOSTS_CONFIG="$HOSTS_CONFIG" REAL_HOME="$REAL_HOME" \
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
        raise SystemExit(f"  ✗ {cfg_path} exists but is not valid JSON; fix or remove it")

alias = os.environ["HOST_ALIAS"]
# Store the key path with ~ for portability (core/ssh.py expanduser's it).
# Use the REAL home (not Path.home(), which is /root under sudo).
real_home = os.environ["REAL_HOME"]
identity = os.environ["KEY_PATH"]
if identity.startswith(real_home):
    identity = "~" + identity[len(real_home):]
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
own "$HOSTS_CONFIG"
ok "live_hosts.json updated"

# ── 5. Smoke test (as the real user, so it uses their ~/.ssh) ─────────────────
step "SSH smoke test"
if as_user ssh -i "$KEY_PATH" \
       -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 \
       -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" 'hostname; id -un' 2>/dev/null; then
    ok "live.* SSH path is up ($SSH_USER@$SSH_HOST:$SSH_PORT)"
else
    warn "SSH smoke test failed — sshd may still be starting. Retry in a few seconds:"
    echo "    ssh -i $KEY_PATH -p $SSH_PORT $SSH_USER@$SSH_HOST id"
fi

# ── 6. Lateral-movement hosts (compose profile "lateral", if running) ─────────
# victim-a / victim-b each enroll as their own Velociraptor client and each
# publish their own /shared/trudi_live key. Wire them exactly like trudi-victim
# (pull key → forget stale host key → merge into live_hosts.json → smoke test),
# but only when their containers are actually up.
wire_lateral_host() {  # $1=alias  $2=container  $3=ssh_port
    local alias="$1" ctr="$2" port="$3"
    local key="$REAL_HOME/.ssh/${ctr#trudi-}"   # ~/.ssh/victim-a, ~/.ssh/victim-b
    if ! docker inspect -f '{{.State.Running}}' "$ctr" >/dev/null 2>&1; then
        return 0
    fi
    step "Wiring lateral host $alias ($ctr:$port)"
    local got=0
    for i in $(seq 1 60); do
        if docker cp "$ctr:/shared/trudi_live" "$key" 2>/dev/null; then
            docker cp "$ctr:/shared/trudi_live.pub" "$key.pub" 2>/dev/null || true
            own "$key" "$key.pub"; chmod 600 "$key"; [ -f "$key.pub" ] && chmod 644 "$key.pub"
            got=1; ok "SSH key → $key"; break
        fi
        sleep 2
    done
    [ "$got" -eq 1 ] || { warn "timed out pulling $ctr key — skipping $alias"; return 0; }
    as_user ssh-keygen -R "[$SSH_HOST]:$port" >/dev/null 2>&1 || true
    as_user env HOSTS_CONFIG="$HOSTS_CONFIG" REAL_HOME="$REAL_HOME" \
        HOST_ALIAS="$alias" SSH_USER="$SSH_USER" SSH_HOST="$SSH_HOST" \
        SSH_PORT="$port" KEY_PATH="$key" python3 - <<'PYEOF'
import json, os
from pathlib import Path
cfg_path = Path(os.environ["HOSTS_CONFIG"]); hosts = {}
if cfg_path.exists():
    try: hosts = json.loads(cfg_path.read_text()) or {}
    except (json.JSONDecodeError, ValueError): raise SystemExit(f"  ✗ {cfg_path} invalid JSON")
alias = os.environ["HOST_ALIAS"]; real_home = os.environ["REAL_HOME"]; identity = os.environ["KEY_PATH"]
if identity.startswith(real_home): identity = "~" + identity[len(real_home):]
entry = {"user": os.environ["SSH_USER"], "host": os.environ["SSH_HOST"],
         "port": int(os.environ["SSH_PORT"]), "identity": identity}
if hosts.get(alias) == entry:
    print(f"  {alias} already registered (unchanged)")
else:
    hosts[alias] = entry; cfg_path.write_text(json.dumps(hosts, indent=2) + "\n")
    print(f"  wrote {alias}")
PYEOF
    own "$HOSTS_CONFIG"
    # The key was pulled from the running container's /shared and that container
    # authorized its matching pubkey, so auth should succeed once sshd is up.
    # A PERSISTENT publickey failure here means a stale/mismatched key — the
    # exact fault that silently broke victim-b in the INV-002 run — so retry a
    # few times (sshd may still be starting) and escalate rather than warn.
    local authed=0
    for i in $(seq 1 6); do
        if as_user ssh -i "$key" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
               -o ConnectTimeout=10 -p "$port" "$SSH_USER@$SSH_HOST" 'hostname' >/dev/null 2>&1; then
            authed=1; break
        fi
        sleep 3
    done
    if [ "$authed" -eq 1 ]; then
        ok "live.* SSH path up ($SSH_USER@$SSH_HOST:$port)"
    else
        LATERAL_FAIL=1
        warn "$alias SSH auth FAILED after key pull ($SSH_USER@$SSH_HOST:$port) —"
        echo    "      live.* cannot reach $alias. Verify by hand:"
        echo    "        ssh -i $key -p $port $SSH_USER@$SSH_HOST id"
        echo    "      If it says 'Permission denied (publickey)', the container key"
        echo    "      rotated; re-run this script, or 'docker compose --profile lateral"
        echo    "      down -v && ./bring-up.sh' for a clean keypair."
    fi
}
LATERAL_FAIL=0
wire_lateral_host "trudi-victim-a" "trudi-victim-a" "2223"
wire_lateral_host "trudi-victim-b" "trudi-victim-b" "2224"
if [ "$LATERAL_FAIL" -ne 0 ]; then
    fail "one or more lateral hosts failed SSH auth — fix before recording a run (see above)"
fi

# ── 7. Windows victim (compose profile "winrdp", if running) ──────────────────
# The Windows host is investigated over its Velociraptor client, NOT live.* SSH,
# so there is no key to pull. It also takes ~10-20 min to install on first boot.
# Just surface where to watch it and how to confirm enrollment — non-fatal, so a
# slow install never fails the bring-up of the rest of the stack.
if docker inspect -f '{{.State.Running}}' "trudi-victim-win" >/dev/null 2>&1; then
    step "Windows victim (victim-win)"
    ok "console: http://localhost:8006  (watch the unattended install / desktop)"
    echo "  First boot pulls ~6 GB of Server 2022 eval media and installs for"
    echo "  ~10-20 min. The OEM payload (win-oem-init) then auto-installs the"
    echo "  Velociraptor client, enables RDP, and creates the RDP account."
    echo "  Confirm the Windows client enrolled (may take a few min after install):"
    echo "    velociraptor --api_config $API_CONFIG \\"
    echo "        query --format=json \"SELECT client_id, os_info.hostname, os_info.system"
    echo "                              FROM clients() WHERE os_info.system =~ 'windows'\""
    echo "  Then: /trudi-start-watcher WINRDP-DEMO   (captures the Windows baseline,"
    echo "        pushes the Custom.TRUDI.Win.* detectors), and stage the attack with"
    echo "        docker exec trudi-victim-a /attacks/run win-rdp"
    if ! docker inspect -f '{{.State.Status}}' "trudi-win-oem-init" 2>/dev/null | grep -q exited; then
        warn "win-oem-init has not completed yet — enrollment payload may not be ready."
    fi
fi

# ── Windows deception decoy (compose profile "windecoy", if running) ──────────
# The CEF relay carries the on-decoy sensor's ShadowPlex incidents to the SIFT-
# host ingest. The decoy is the real Windows box (winrdp), touched with the honey
# credential 'linda'. Drive it with the WINDECOY-DEMO case.
if docker inspect -f '{{.State.Running}}' "trudi-windecoy-relay" >/dev/null 2>&1; then
    step "Windows deception decoy (windecoy)"
    ok "CEF relay up (lan-net 10.73.0.55:5514 → host ingest host.docker.internal:5514)"
    echo "  The on-decoy ShadowPlex sensor reports honey-account logons as CEF."
    echo "  Drive with the WINDECOY-DEMO case:"
    echo "    /trudi-start-watcher WINDECOY-DEMO   # starts the CEF ingest (cef_ingest in config)"
    echo "    /trudi-watch-alerts  WINDECOY-DEMO"
    echo "    docker exec trudi-victim-a /attacks/run win-decoy   # honey-credential RDP to the decoy"
    echo "  Start the ingest BEFORE the attack so the first touch is captured."
    echo "  The attacker attempts discovery, synthetic-file staging and HKCU persistence"
    echo "  as the standard-user honey account. Fast containment may interrupt it."
    echo "  See windecoy-demo-script.md for the explicit full-activity exercise mode."
    echo "  Relay traffic: docker logs trudi-windecoy-relay"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}  Live endpoint ready.${NC}"
echo "  Velociraptor client_id:"
echo "    velociraptor --api_config $API_CONFIG \\"
echo "        query --format=json \"SELECT client_id, os_info.hostname FROM clients()\""
echo "  Then update DEMO-LIVE/CLAUDE.md + ~/cases/.common/active_case if the client_id changed."
echo ""
