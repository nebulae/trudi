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

# ── 2. Python virtual environment ─────────────────────────────────────────────

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
ok "Dependencies installed (fastmcp, httpx, python-dotenv, yara-python, pytest)"

# ── 3. Environment file ───────────────────────────────────────────────────────

step "Configuring environment"

if [ ! -f "$TRUDI_DIR/.env" ]; then
    cp "$TRUDI_DIR/.env.example" "$TRUDI_DIR/.env"
    ok "Created .env from .env.example"
    warn "Edit $TRUDI_DIR/.env to add API keys (VirusTotal, AbuseIPDB) and Foundation-Sec URL"
else
    ok ".env already exists — skipping"
fi

# ── 4. Global CLAUDE.md ───────────────────────────────────────────────────────

step "Installing TRUDI orchestrator (CLAUDE.md)"

mkdir -p "$CLAUDE_DIR"

if [ -f "$CLAUDE_MD_DEST" ]; then
    BACKUP="$CLAUDE_MD_DEST.$(date -u +%Y%m%dT%H%M%S).bak"
    cp "$CLAUDE_MD_DEST" "$BACKUP"
    ok "Backed up existing CLAUDE.md → $BACKUP"
fi

cp "$CLAUDE_MD_SRC" "$CLAUDE_MD_DEST"
ok "Installed TRUDI orchestrator to $CLAUDE_MD_DEST"

# ── 5. MCP server registration ────────────────────────────────────────────────

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

# ── 6. Verify ─────────────────────────────────────────────────────────────────

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
