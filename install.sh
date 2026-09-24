#!/usr/bin/env bash
# TRUDI install script — run on a SANS SIFT Workstation with the Claude Code CLI installed.
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
    fail "Claude Code CLI not found. Install it first: curl -fsSL https://claude.ai/install.sh | bash"
fi
CLAUDE_BIN="$(command -v claude 2>/dev/null || echo "$HOME/.local/bin/claude")"
ok "Claude Code at $CLAUDE_BIN"

# ── 1b. System packages (apt) ─────────────────────────────────────────────────

step "Installing system packages (Python base + forensic tools)"

APT_PACKAGES=(
    python3-venv       # ensurepip — required by `python3 -m venv` (NOT preinstalled on the SIFT base)
    python3-pip        # pip bootstrap for the venv
    pff-tools          # pffexport — PST/OST email extraction
    pst-utils          # readpst — PST→mbox conversion
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
    # pst-utils, pff-tools, and tcpxtract live in the 'universe' component.
    # SIFT normally enables it, but a bare Ubuntu base may not — make it explicit
    # so a fresh image doesn't fail with "unable to locate package".
    if ! grep -rq "^deb .* universe" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
        if command -v add-apt-repository &>/dev/null; then
            sudo add-apt-repository -y universe || warn "Could not enable 'universe' repo automatically"
        else
            warn "'universe' repo not enabled and add-apt-repository missing — pst-utils/pff-tools may not install"
        fi
    fi
    sudo apt-get update -qq
    sudo apt-get install -y "${MISSING_PKGS[@]}" || \
        warn "Some apt packages failed to install — see output above"

    # Verify the critical binaries actually landed — dpkg state alone can report
    # success while an apt failure (swallowed by '|| warn' above) left a tool absent.
    for bin in readpst pffexport; do
        command -v "$bin" &>/dev/null || warn "Expected binary '$bin' not found after install — email extraction (misc.readpst_extract / misc.pff_export) will fail"
    done
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
        # Guard extraction: a corrupt download must degrade to the optional-skip
        # path, not abort the whole install under `set -e`.
        # Release ships as chainsaw/chainsaw + sigma rules
        if ! tar -xzf "$TMPDIR/chainsaw.tgz" -C "$TMPDIR" 2>/dev/null; then
            warn "chainsaw archive corrupt — skipping (TRUDI works without it)"
        elif [ -f "$TMPDIR/chainsaw/chainsaw" ]; then
            sudo install -m 0755 "$TMPDIR/chainsaw/chainsaw" "$CHAINSAW_BIN"
            # Create the share dir once, before either optional copy — so a
            # release that ships mappings/ but no sigma/ (or vice versa) can't
            # leave the parent missing and fail a copy under `set -e`.
            sudo mkdir -p /usr/local/share/chainsaw
            if [ -d "$TMPDIR/chainsaw/sigma" ]; then
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


# ── 1cd. trudi umbrella command ──────────────────────────────────────────────

step "Installing trudi umbrella command"

TRUDI_BIN_SRC="$TRUDI_DIR/bin/trudi"
TRUDI_BIN_DEST="/usr/local/bin/trudi"

if [ -f "$TRUDI_BIN_SRC" ]; then
    if [ -L "$TRUDI_BIN_DEST" ] || [ -f "$TRUDI_BIN_DEST" ]; then
        ok "trudi already installed at $TRUDI_BIN_DEST"
    else
        sudo install -m 0755 "$TRUDI_BIN_SRC" "$TRUDI_BIN_DEST" 2>/dev/null \
            && ok "Installed trudi → $TRUDI_BIN_DEST" \
            || warn "Could not install $TRUDI_BIN_DEST (sudo needed); use $TRUDI_BIN_SRC directly"
    fi
    echo "    Agent mode:       cd <case dir> && trudi --mode agent"
    echo "    Pilot mode:       cd <case dir> && trudi --mode pilot"
else
    warn "trudi wrapper missing at $TRUDI_BIN_SRC"
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
else
    warn "MITRE reference table not found in repo; mitre_map will be a no-op"
fi


# ── 1e. Bundled case studies (traces + reports for the dashboard) ─────────────

step "Installing bundled case studies"

# Copy each bundled case (trace + reports + brief, NO evidence) into ~/cases so the
# trace dashboard can render them. A case already present in ~/cases is left alone —
# we never clobber a user's live investigation.
CASE_COUNT=0
for case_src in "$TRUDI_DIR"/cases/*/; do
    case_name="$(basename "$case_src")"
    [ "$case_name" = ".common" ] && continue
    case_dest="$HOME/cases/$case_name"
    if [ -e "$case_dest" ]; then
        warn "~/cases/$case_name already exists — leaving it untouched"
        continue
    fi
    cp -r "$case_src" "$case_dest"
    CASE_COUNT=$((CASE_COUNT + 1))
done
ok "Installed $CASE_COUNT bundled case studies to ~/cases/ (browse with: ./dashboard.sh)"


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

# A partial venv from a previous failed run (e.g. one that died at ensurepip)
# leaves the directory but no working pip — treat that as needing recreation,
# otherwise the pip steps below fail with a confusing error.
make_venv() { [ -d "$VENV_DIR" ] && rm -rf "$VENV_DIR"; python3 -m venv "$VENV_DIR" 2>/dev/null; }

if [ ! -x "$VENV_DIR/bin/pip" ]; then
    if ! make_venv; then
        # ensurepip is missing. The generic python3-venv metapackage tracks the
        # apt-default python, which on a multi-python box (e.g. SIFT's python3.12)
        # differs from the `python3` command — so install the venv package matching
        # THIS python3 by version, then retry.
        PYV="$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
        warn "venv creation failed (ensurepip missing) — installing python${PYV}-venv to match python3 $PYV"
        sudo apt-get install -y "python${PYV}-venv" python3-pip 2>/dev/null || \
            sudo apt-get install -y python3-venv python3-pip 2>/dev/null || true
        if ! make_venv; then
            fail "Failed to create venv even after installing python${PYV}-venv. Install it manually and re-run: sudo apt-get install -y python${PYV}-venv python3-pip"
        fi
    fi
    ok "Created venv at $VENV_DIR"
else
    ok "Venv already exists at $VENV_DIR"
fi

"$VENV_DIR/bin/pip" install --quiet --upgrade pip
# Do NOT use --quiet here: flare-capa/flare-floss (and yara-python, which compiles
# C) are large and can take several minutes. With --quiet the step produces zero
# output and looks hung; show pip's normal progress instead.
warn "Installing Python dependencies — this can take several minutes (flare-capa / flare-floss / yara-python are large). Progress shown below."
"$VENV_DIR/bin/pip" install -r "$TRUDI_DIR/requirements.txt"
"$VENV_DIR/bin/pip" install -r "$TRUDI_DIR/requirements-dev.txt"
ok "Dependencies installed (fastmcp, httpx, anthropic, yara-python, flare-capa, flare-floss, oletools, pytest)"

# vera (optional — pilot mode's record + UI) goes into the SAME venv the
# bin/trudi launcher uses. Library needs >=3.10; vera's own CLI needs
# python3.12 (PEP 701 f-strings) — the pilot mirror works either way.
if [ -d "$HOME/vera" ]; then
    if "$VENV_DIR/bin/python3" -c "import vera" 2>/dev/null; then
        ok "vera importable in venv (pilot mirror available)"
    else
        "$VENV_DIR/bin/pip" install --quiet -e "$HOME/vera" \
            && ok "Installed vera (editable) from ~/vera into venv" \
            || warn "vera present at ~/vera but pip install failed"
    fi
else
    echo "    vera not found at ~/vera — pilot mode runs without the .vera mirror."
    echo "    To enable: git clone https://github.com/nebulae/vera ~/vera && rerun install.sh"
fi

# ── 4. Environment file ───────────────────────────────────────────────────────

step "Configuring environment"

if [ ! -f "$TRUDI_DIR/.env" ]; then
    cp "$TRUDI_DIR/.env.example" "$TRUDI_DIR/.env"
    ok "Created .env from .env.example"
    warn "Edit $TRUDI_DIR/.env to add API keys (VirusTotal, AbuseIPDB); set REASON_URL / DAIR_URL for a local reasoning backend"
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
SETTINGS_FILE="$CLAUDE_DIR/settings.json"

# Hooks run directly from the repo (HOOKS_SRC) — the same convention as the
# MCP server (server.py) and the Stop/UserPromptSubmit hooks. We do NOT copy
# them into ~/.claude/hooks: a deployed copy silently drifts from the repo on
# every edit. One source of truth = no drift.

# Merge hook registrations into settings.json
if [ ! -f "$SETTINGS_FILE" ]; then
    echo '{"hooks":{}}' > "$SETTINGS_FILE"
fi

# Registration + self-heal (command path, matcher) lives in
# claude/hooks/_register_hooks.py so it is unit-tested; install.sh only calls it.
python3 "$HOOKS_SRC/_register_hooks.py" "$HOOKS_SRC" "$SETTINGS_FILE"

ok "Claude Code hooks configured (run from repo path)"

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

# ── 6c. OpenCode support (optional, side-by-side) ────────────────────────────

step "OpenCode support (optional)"

OPENCODE_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/opencode"
if command -v opencode &>/dev/null || [ -d "$OPENCODE_DIR" ]; then
    # Registers the trudi-sift MCP server, derives the forensic-binary bash
    # deny rules from the same ban list Claude Code uses, symlinks the
    # /trudi-* commands + the hook-adapter plugin (repo path — no drift), and
    # installs the orchestrator as AGENTS.md (existing file backed up).
    if python3 "$TRUDI_DIR/opencode/register_opencode.py" \
            "$OPENCODE_DIR" "$TRUDI_DIR" "$VENV_DIR/bin/python3"; then
        ok "OpenCode configured at $OPENCODE_DIR (side-by-side with Claude Code)"
    else
        warn "OpenCode registration failed — Claude Code setup is unaffected"
    fi
else
    ok "OpenCode not detected — skipping (re-run ./install.sh after installing it)"
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

# Register at user scope, falling back to global. Do NOT hide stderr or '|| true'
# the failure: the MCP server IS the product, so a silent registration failure
# would leave a hollow Claude with a misleading "ready" banner. Verify after.
if "$CLAUDE_BIN" mcp add trudi-sift "$PYTHON_BIN" "$SERVER_PATH" --scope user; then
    REG_SCOPE="user"
elif "$CLAUDE_BIN" mcp add trudi-sift "$PYTHON_BIN" "$SERVER_PATH" --scope global; then
    REG_SCOPE="global"
else
    REG_SCOPE=""
fi

if [ -n "$REG_SCOPE" ] && "$CLAUDE_BIN" mcp list 2>/dev/null | grep -q "trudi-sift"; then
    ok "Registered trudi-sift MCP server ($REG_SCOPE scope)"
else
    fail "Failed to register trudi-sift MCP server — TRUDI has no tools without it. Reproduce: $CLAUDE_BIN mcp add trudi-sift $PYTHON_BIN $SERVER_PATH --scope user"
fi

# ── 7. Verify ─────────────────────────────────────────────────────────────────

step "Running smoke test"

cd "$TRUDI_DIR"
# The install is already complete by this point — a failing test should not abort
# the script under `set -e` and hide the "TRUDI is ready" banner. Warn instead.
if "$VENV_DIR/bin/python3" -m pytest tests/ -q --tb=short; then
    ok "Tests passed"
else
    rc=$?
    warn "pytest reported failures (exit $rc) — the install itself is complete; review the output above before relying on this build"
fi

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}  TRUDI is ready.${NC}"
echo ""
echo "  Next steps:"
echo "    1. Edit $TRUDI_DIR/.env and set ANTHROPIC_API_KEY — REQUIRED for a full-quality run."
echo "       It powers the analyst, the reason.* reviewer, and the dair.* director."
echo "       Without it TRUDI degrades: reason.* / dair.* calls are skipped, so findings"
echo "       are never adversarially challenged. (VirusTotal / AbuseIPDB keys are optional.)"
echo "       Default: REASON_MODEL=claude-opus-4-8, DAIR_MODEL=claude-opus-4-8 (or a local model, below)."
echo ""
echo "  Browse a finished investigation now (no key, no evidence needed):"
echo "    ./dashboard.sh                 # serves ~/cases on http://127.0.0.1:8765"
echo ""
echo "  Start a new case:"
echo "    cp -r $TRUDI_DIR/case-template ~/cases/<CASE_ID>"
echo "    # Edit ~/cases/<CASE_ID>/CLAUDE.md with evidence paths"
echo "    cd ~/cases/<CASE_ID>"
echo "    claude"
echo ""
echo "  Local reasoning backend (optional) — run the reviewer + DAIR on your own model:"
echo "    a security-tuned GGUF (e.g. Titus-CybersecurityLLM) or a thinking model (Qwen3, DeepSeek-R1)"
echo "    over vLLM / SGLang / llama.cpp, then set REASON_BACKEND=openai-compat + REASON_URL in .env."
echo "    Details: README 'Running a local model'."
echo ""
echo "  Full walkthrough: docs/try-it-out.md"
echo ""
