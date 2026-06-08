#!/usr/bin/env bash
# TRUDI install script — run this after Protocol SIFT setup is complete.
# https://github.com/teamdfir/protocol-sift
set -euo pipefail

TRUDI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_DIR="$HOME/.claude"
VENV_DIR="$HOME/.venv"
CLAUDE_MD_DEST="$CLAUDE_DIR/CLAUDE.md"
CLAUDE_MD_SRC="$TRUDI_DIR/claude/CLAUDE.md"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ok()   { echo -e "${GREEN}  ✓${NC} $*"; }
warn() { echo -e "${YELLOW}  !${NC} $*"; }
fail() { echo -e "${RED}  ✗${NC} $*"; exit 1; }
step() { echo -e "\n${GREEN}▶${NC} $*"; }

echo ""
echo "  TRUDI — Threat Response Unit for Digital Investigation"
echo "  ======================================================="
echo "  Installing into: $TRUDI_DIR"
echo ""

# ── 1. Prerequisites ──────────────────────────────────────────────────────────

step "Checking prerequisites"

python3 --version &>/dev/null || fail "python3 not found. SIFT Workstation required."
PYTHON_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
[ "$PYTHON_MINOR" -ge 10 ] || fail "Python 3.10+ required (found 3.$PYTHON_MINOR)."
ok "Python 3.$PYTHON_MINOR"

dotnet --version &>/dev/null || fail "dotnet not found — EZ Tools require the .NET runtime. Install SIFT Workstation first."
ok "dotnet $(dotnet --version)"

if ! command -v claude &>/dev/null && [ ! -x "$HOME/.local/bin/claude" ]; then
    fail "Claude Code CLI not found. Install Protocol SIFT first: https://github.com/teamdfir/protocol-sift"
fi
CLAUDE_BIN="$(command -v claude 2>/dev/null || echo "$HOME/.local/bin/claude")"
ok "Claude Code at $CLAUDE_BIN"

# ── 1b. System packages (apt) ─────────────────────────────────────────────────

step "Installing system forensic packages"

APT_PACKAGES=(
    pff-tools          # pffexport — PST/OST email extraction
    libpst-utils       # readpst — PST→mbox conversion
    binwalk            # firmware / embedded carving
    tcpxtract          # network stream carving (already covered)
    sleuthkit          # TSK tools
    ewf-tools          # ewfmount, ewfinfo, ewfverify
)

MISSING_PKGS=()
for pkg in "${APT_PACKAGES[@]}"; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        MISSING_PKGS+=("$pkg")
    fi
done
if [ "${#MISSING_PKGS[@]}" -gt 0 ]; then
    sudo apt-get update -qq
    sudo apt-get install -y "${MISSING_PKGS[@]}" || \
        warn "Some apt packages failed to install — see output above"
    ok "Installed: ${MISSING_PKGS[*]}"
else
    ok "All apt forensic packages already present"
fi


# ── 1c. Chainsaw (Sigma rule engine for EVTX) ────────────────────────────────

step "Installing chainsaw (optional: Sigma rule engine)"

CHAINSAW_BIN="/usr/local/bin/chainsaw"
CHAINSAW_VERSION="2.10.2"

if [ -x "$CHAINSAW_BIN" ]; then
    ok "chainsaw already installed at $CHAINSAW_BIN"
else
    CHAINSAW_URL="https://github.com/WithSecureLabs/chainsaw/releases/download/v${CHAINSAW_VERSION}/chainsaw_x86_64-unknown-linux-gnu.tar.gz"
    TMPDIR=$(mktemp -d)
    if curl -fsSL "$CHAINSAW_URL" -o "$TMPDIR/chainsaw.tgz" 2>/dev/null; then
        tar -xzf "$TMPDIR/chainsaw.tgz" -C "$TMPDIR"
        # Release ships as chainsaw/chainsaw + sigma rules
        if [ -f "$TMPDIR/chainsaw/chainsaw" ]; then
            sudo install -m 0755 "$TMPDIR/chainsaw/chainsaw" "$CHAINSAW_BIN"
            if [ -d "$TMPDIR/chainsaw/sigma" ]; then
                sudo mkdir -p /usr/local/share/chainsaw
                sudo cp -r "$TMPDIR/chainsaw/sigma" /usr/local/share/chainsaw/sigma
            fi
            if [ -d "$TMPDIR/chainsaw/mappings" ]; then
                sudo cp -r "$TMPDIR/chainsaw/mappings" /usr/local/share/chainsaw/mappings
            fi
            ok "Installed chainsaw v${CHAINSAW_VERSION} → $CHAINSAW_BIN"
        else
            warn "chainsaw archive layout unexpected; skipping"
        fi
    else
        warn "Could not download chainsaw (offline?). Skip — TRUDI works without it."
    fi
    rm -rf "$TMPDIR"
fi


# ── 1cc. Trace dashboard ─────────────────────────────────────────────────────

step "Verifying trace dashboard"

DASHBOARD_HTML="$TRUDI_DIR/dashboard/trace_viewer.html"
DASHBOARD_BIN_SRC="$TRUDI_DIR/bin/trudi-dashboard"
DASHBOARD_BIN_DEST="/usr/local/bin/trudi-dashboard"

if [ -f "$DASHBOARD_HTML" ]; then
    ok "Trace dashboard HTML at $DASHBOARD_HTML"
else
    warn "Trace dashboard HTML not found — dashboard will not work"
fi

if [ -f "$DASHBOARD_BIN_SRC" ]; then
    if [ -L "$DASHBOARD_BIN_DEST" ] || [ -f "$DASHBOARD_BIN_DEST" ]; then
        ok "trudi-dashboard already installed at $DASHBOARD_BIN_DEST"
    else
        sudo install -m 0755 "$DASHBOARD_BIN_SRC" "$DASHBOARD_BIN_DEST" 2>/dev/null \
            && ok "Installed trudi-dashboard → $DASHBOARD_BIN_DEST" \
            || warn "Could not install $DASHBOARD_BIN_DEST (sudo needed); use $DASHBOARD_BIN_SRC directly"
    fi
    echo "    Launch once:      trudi-dashboard           # serves ~/cases on :8765"
    echo "    Custom root:      trudi-dashboard --cases-root /path/to/cases"
    echo "    Pick case+trace in the dashboard dropdown."
else
    warn "trudi-dashboard wrapper missing at $DASHBOARD_BIN_SRC"
fi


# ── 1d. MITRE ATT&CK reference table ─────────────────────────────────────────

step "Installing MITRE ATT&CK reference table"

MITRE_DEST="$HOME/cases/.common/mitre_techniques.json"
MITRE_SRC="$TRUDI_DIR/cases/.common/mitre_techniques.json"
mkdir -p "$HOME/cases/.common"
# Prefer in-repo copy; fall back to the one bundled with TRUDI if cases/ is missing.
if [ -f "$MITRE_DEST" ]; then
    ok "MITRE reference table already at $MITRE_DEST"
elif [ -f "$MITRE_SRC" ]; then
    cp "$MITRE_SRC" "$MITRE_DEST"
    ok "Installed MITRE reference table → $MITRE_DEST"
elif [ -f "/home/trin/cases/.common/mitre_techniques.json" ]; then
    cp "/home/trin/cases/.common/mitre_techniques.json" "$MITRE_DEST"
    ok "Copied MITRE reference table → $MITRE_DEST"
else
    warn "MITRE reference table not found in repo; mitre_map will be a no-op"
fi


# ── 2. Passwordless sudo for forensic tools ───────────────────────────────────

step "Configuring passwordless sudo for forensic tools"

SUDOERS_FILE="/etc/sudoers.d/trudi"
CURRENT_USER="$(whoami)"

if sudo -n true 2>/dev/null; then
    ok "Passwordless sudo already available — skipping"
elif [ -f "$SUDOERS_FILE" ]; then
    ok "$SUDOERS_FILE already exists — skipping"
else
    echo "$CURRENT_USER ALL=(ALL) NOPASSWD: ALL" | sudo tee "$SUDOERS_FILE" > /dev/null
    sudo chmod 440 "$SUDOERS_FILE"
    ok "Configured passwordless sudo for $CURRENT_USER"
    warn "This grants root access without a password — appropriate for a dedicated lab VM only"
fi

# ── 3. Python virtual environment ─────────────────────────────────────────────

step "Setting up Python environment"

if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    ok "Created venv at $VENV_DIR"
else
    ok "Venv already exists at $VENV_DIR"
fi

"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet -r "$TRUDI_DIR/requirements.txt"
"$VENV_DIR/bin/pip" install --quiet -r "$TRUDI_DIR/requirements-dev.txt"
ok "Dependencies installed (fastmcp, httpx, anthropic, yara-python, flare-capa, flare-floss, oletools, pytest)"

# ── 4. Environment file ───────────────────────────────────────────────────────

step "Configuring environment"

if [ ! -f "$TRUDI_DIR/.env" ]; then
    cp "$TRUDI_DIR/.env.example" "$TRUDI_DIR/.env"
    ok "Created .env from .env.example"
    warn "Edit $TRUDI_DIR/.env to add API keys (VirusTotal, AbuseIPDB) and Foundation-Sec URL"
else
    ok ".env already exists — skipping"
fi

# ── 5. Global CLAUDE.md ───────────────────────────────────────────────────────

step "Installing TRUDI orchestrator (CLAUDE.md)"

mkdir -p "$CLAUDE_DIR"

if [ -f "$CLAUDE_MD_DEST" ]; then
    BACKUP="$CLAUDE_MD_DEST.$(date -u +%Y%m%dT%H%M%S).bak"
    cp "$CLAUDE_MD_DEST" "$BACKUP"
    ok "Backed up existing CLAUDE.md → $BACKUP"
fi

cp "$CLAUDE_MD_SRC" "$CLAUDE_MD_DEST"
ok "Installed TRUDI orchestrator to $CLAUDE_MD_DEST"

# ── 6. Claude Code hooks ─────────────────────────────────────────────────────

step "Installing Claude Code hooks"

HOOKS_SRC="$TRUDI_DIR/claude/hooks"
HOOKS_DEST="$CLAUDE_DIR/hooks"
SETTINGS_FILE="$CLAUDE_DIR/settings.json"

mkdir -p "$HOOKS_DEST"
cp "$HOOKS_SRC/"*.py "$HOOKS_DEST/"
ok "Installed hook scripts to $HOOKS_DEST/"

# Merge PostToolUse hook into settings.json
if [ ! -f "$SETTINGS_FILE" ]; then
    echo '{"hooks":{}}' > "$SETTINGS_FILE"
fi

python3 - <<'PYEOF'
import json, sys
from pathlib import Path

settings_path = Path.home() / ".claude/settings.json"
hooks_dest    = Path.home() / ".claude/hooks"

settings = json.loads(settings_path.read_text())
settings.setdefault("hooks", {})

narration_hook = {
    "hooks": [
        {
            "type": "command",
            "command": f"python3 {hooks_dest}/log_narration.py"
        }
    ]
}

existing = settings["hooks"].get("PostToolUse", [])
already  = any(
    h.get("hooks", [{}])[0].get("command", "").endswith("log_narration.py")
    for h in existing
    if h.get("hooks")
)
if not already:
    settings["hooks"].setdefault("PostToolUse", []).append(narration_hook)
    settings_path.write_text(json.dumps(settings, indent=2))
    print("  Registered PostToolUse hook")
else:
    print("  PostToolUse hook already registered — skipping")
PYEOF

ok "Claude Code hooks configured"

# ── 6b. Claude Code slash commands ────────────────────────────────────────────

step "Installing Claude Code slash commands"

COMMANDS_SRC="$TRUDI_DIR/claude/commands"
COMMANDS_DEST="$CLAUDE_DIR/commands"

if [ -d "$COMMANDS_SRC" ] && compgen -G "$COMMANDS_SRC/*.md" > /dev/null; then
    mkdir -p "$COMMANDS_DEST"
    for cmd in "$COMMANDS_SRC"/*.md; do
        name="$(basename "$cmd")"
        dest="$COMMANDS_DEST/$name"
        # Back up a pre-existing command of the same name before overwriting,
        # so a user's own customisations aren't silently clobbered.
        if [ -f "$dest" ] && ! cmp -s "$cmd" "$dest"; then
            cp "$dest" "$dest.$(date -u +%Y%m%dT%H%M%S).bak"
        fi
        cp "$cmd" "$dest"
    done
    ok "Installed $(ls "$COMMANDS_SRC"/*.md | wc -l) slash commands to $COMMANDS_DEST/ (/trudi-*)"
else
    warn "No commands at $COMMANDS_SRC — skipping slash command install"
fi

# ── 7. MCP server registration ────────────────────────────────────────────────

step "Registering TRUDI MCP server"

PYTHON_BIN="$VENV_DIR/bin/python3"
SERVER_PATH="$TRUDI_DIR/server.py"

if "$CLAUDE_BIN" mcp list 2>/dev/null | grep -q "trudi-sift"; then
    warn "trudi-sift already registered — removing old entry"
    "$CLAUDE_BIN" mcp remove trudi-sift --scope global 2>/dev/null || \
    "$CLAUDE_BIN" mcp remove trudi-sift 2>/dev/null || true
fi

"$CLAUDE_BIN" mcp add trudi-sift "$PYTHON_BIN" "$SERVER_PATH" --scope user 2>/dev/null || \
"$CLAUDE_BIN" mcp add trudi-sift "$PYTHON_BIN" "$SERVER_PATH" --scope global 2>/dev/null || true
ok "Registered trudi-sift MCP server (global scope)"

# ── 7. Verify ─────────────────────────────────────────────────────────────────

step "Running smoke test"

cd "$TRUDI_DIR"
"$VENV_DIR/bin/python3" -m pytest tests/ -q --tb=short 2>&1 | tail -5
ok "Tests passed"

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}  TRUDI is ready.${NC}"
echo ""
echo "  Next steps:"
echo "    1. Edit $TRUDI_DIR/.env — add API keys if you have them (optional)"
echo ""
echo "  Foundation-Sec-8B (adversarial reasoning):"
echo "    Local:  vllm serve \"fdtn-ai/Foundation-Sec-8B-Reasoning\" --reasoning-parser minimax_m2"
echo "    Set FOUNDATION_SEC_URL=http://localhost:8000 in .env"
echo ""
echo "  Start a new case:"
echo "    cp -r $TRUDI_DIR/case-template ~/cases/<CASE_ID>"
echo "    # Edit ~/cases/<CASE_ID>/CLAUDE.md with evidence paths"
echo "    cd ~/cases/<CASE_ID>"
echo "    claude"
echo ""
