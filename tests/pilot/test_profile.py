"""The pilot profile: two renderings, one contract.

claude/PILOT.md (full, appended to Claude Code's system prompt) and
opencode/agent/trudi-pilot.md (condensed, an OpenCode primary agent) must
stay in lockstep: same section headings, the explicit supersede of the
autonomous orchestrator, and hard size budgets (OpenCode renders AGENTS.md
+ the agent prompt into every request; a local model's context is the
constraint).
"""
import os
import re

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CLAUDE_PROFILE = os.path.join(REPO, "claude", "PILOT.md")
OPENCODE_PROFILE = os.path.join(REPO, "opencode", "agent", "trudi-pilot.md")

REQUIRED_HEADINGS = [
    "## Mode override",
    "## Conversational contract",
    "## Proposing commands",
    "## Opening playbook",
    "## DAIR, analyst-paced",
    "## Findings & dispositions",
    "## Coaching",
    "## Unchanged control plane",
]


def _read(path):
    return open(path, encoding="utf-8").read()


class TestProfiles:
    def test_both_renderings_exist(self):
        assert os.path.exists(CLAUDE_PROFILE)
        assert os.path.exists(OPENCODE_PROFILE)

    def test_heading_parity(self):
        for path in (CLAUDE_PROFILE, OPENCODE_PROFILE):
            text = _read(path)
            for heading in REQUIRED_HEADINGS:
                assert heading in text, f"{os.path.basename(path)}: {heading}"

    def test_supersede_statement_present(self):
        for path in (CLAUDE_PROFILE, OPENCODE_PROFILE):
            assert "upersede" in _read(path), path  # Supersedes/supersedes

    def test_size_budgets(self):
        # ~4 chars/token heuristic: full ≤ ~4k tokens, condensed ≤ ~3k
        assert len(_read(CLAUDE_PROFILE)) <= 16_000
        assert len(_read(OPENCODE_PROFILE)) <= 12_000

    def test_opencode_frontmatter_is_primary_agent(self):
        text = _read(OPENCODE_PROFILE)
        m = re.match(r"---\n(.*?)\n---\n", text, re.S)
        assert m, "missing YAML frontmatter"
        assert "mode: primary" in m.group(1)
        assert "description:" in m.group(1)

    def test_playbook_names_the_ritual(self):
        for path in (CLAUDE_PROFILE, OPENCODE_PROFILE):
            text = _read(path)
            for tool in ("reason.hypothesize", "reason.plan", "dair.assess",
                         "misc.knowns_pattern_generate",
                         "misc.record_finding"):
                assert tool in text, f"{os.path.basename(path)}: {tool}"


class TestModeContract:
    def test_both_orchestrators_carry_the_contract(self):
        for rel in ("claude/CLAUDE.md", "opencode/AGENTS.md"):
            text = _read(os.path.join(REPO, rel))
            assert "## Mode contract" in text, rel
            assert "OVERRIDE" in text, rel
