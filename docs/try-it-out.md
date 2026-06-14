# Try It Out

*Find Evil! Hackathon — submission component #7.*

Two ways to evaluate TRUDI, shortest first:

- **[Path A — Browse a finished investigation](#path-a--browse-a-finished-investigation)** (~2 min, **no evidence, no API key**). Install, launch the dashboard, and read a completed run's trace and report. This is the fastest way to see what TRUDI produces and how every finding links back to the tool call that produced it.
- **[Path B — Run a fresh investigation](#path-b--run-a-fresh-investigation)** (needs evidence + an `ANTHROPIC_API_KEY`). Drive TRUDI end-to-end on a real image and compare your run against the committed one.

> **Full-quality runs require Claude Code + an `ANTHROPIC_API_KEY`.** The submission runs the analyst, the `reason.*` adversarial reviewer, and the `dair.*` phase director all on Claude/Opus. **Without the key TRUDI degrades** — the `reason.*` and `dair.*` calls are skipped, so findings are never hypothesis-tested, confidence-scored, or citation-checked, and phase direction falls back to a static path. Path A needs no key (you are reading a finished run); Path B does.

---

## Prerequisites

| Need | For | Notes |
|------|-----|-------|
| **SANS SIFT Workstation** (Ubuntu 22.04 x86-64) | Path B (the forensic tools) | Path A only needs Python 3.10+ and a browser. [Download](https://www.sans.org/tools/sift-workstation/) |
| **Protocol SIFT** (Claude Code + skill playbooks) | Both | [github.com/teamdfir/protocol-sift](https://github.com/teamdfir/protocol-sift) |
| **Python 3.10+** and **dotnet** | Both | Included in SIFT |
| **`ANTHROPIC_API_KEY`** | Path B (full-quality) | Powers the analyst + `reason.*` + `dair.*`. See the degradation note above. |

---

## Install (both paths)

```bash
git clone https://github.com/nebulae/trudi ~/trudi
cd ~/trudi
./install.sh
```

`install.sh` is idempotent — safe to re-run. It will:

- Verify `python3`, `dotnet`, and the `claude` CLI
- Enable the `universe` apt component if missing, then install the forensic packages below and chainsaw
- Create a venv at `~/.venv` and install all Python dependencies
- Install the dashboard launcher (`trudi-dashboard` → `/usr/local/bin`)
- Copy the MITRE ATT&CK table and the **bundled case studies** into `~/cases/` (existing cases are never overwritten)
- Back up then install the TRUDI orchestrator to `~/.claude/CLAUDE.md`
- Register the Claude Code **hooks**, the 5 **`/trudi-*` slash commands**, and the 5 **skills** — all run from the repo path (no drift-prone copies)
- Register the **`trudi-sift` MCP server** globally
- Run the test suite (1,100+ tests) as a smoke check

When it finishes you have a working install and eight bundled runs to browse.

### System forensic packages

`install.sh` installs these from apt automatically. On a full SIFT Workstation most are already present; on a leaner base — or if the installer prints a `!` warning about one — install them by hand. The `universe` component must be enabled first (these packages live there):

```bash
sudo add-apt-repository -y universe
sudo apt-get update
sudo apt-get install -y pff-tools pst-utils binwalk tcpxtract sleuthkit ewf-tools
```

| apt package | Binary | TRUDI tools |
|-------------|--------|-------------|
| `pff-tools` | `pffexport` | `misc.pff_export` (PST/OST email) |
| `pst-utils` | `readpst` | `misc.readpst_extract` (PST→mbox) — **not** `libpst-utils` |
| `sleuthkit` | `fls`, `icat`, `mmls`, … | `tsk.*` |
| `ewf-tools` | `ewfmount`, `ewfverify` | `ewf.*`, `img.*` (E01) |
| `tcpxtract` | `tcpxtract` | `net.tcpxtract_streams` |
| `binwalk` | `binwalk` | embedded carving |

chainsaw (Sigma over EVTX, `misc.chainsaw_hunt`) is fetched from its GitHub release into `/usr/local/bin` and is optional — TRUDI runs without it. Verify the apt set landed:

```bash
for b in pffexport readpst fls ewfmount tcpxtract; do command -v "$b" || echo "MISSING: $b"; done
```

---

## Path A — Browse a finished investigation

No evidence, no API key. You are reading a run TRUDI already completed.

**1. Launch the dashboard** (serves every case under `~/cases`):

```bash
cd ~/trudi
./dashboard.sh                 # http://127.0.0.1:8765
# ./dashboard.sh --port 9090   # if 8765 is taken
```

**2. Open the VANKO-2016 run** — the demo-video case. In the dashboard, pick the case and trace from the dropdown (or open the link directly):

```
http://127.0.0.1:8765/reports/dashboard.html?trace=../analysis/VANKO-2016_trace.json
```

Three views, all reading the same trace:

| View | What you see |
|------|--------------|
| **Trace Viewer** | Every tool call, DAIR call, reason call, and finding in order — UTC timestamps, arguments, gate results |
| **Investigation Chain** | Each finding linked back through `input_call_ids` to the exact tool executions that produced it |
| **Investigation Graph** | The trace as a causal DAG — hypotheses, tool runs, findings as nodes; lineage as edges |

**3. Read the report** it produced:

```
~/cases/vanko/reports/VANKO-2016_final_report.md
```

**What to look for** (this is the submission in miniature):

- **Audit trail** — pick any CONFIRMED finding in the report, find it in the Trace Viewer, and follow its `linked_call_id` to the precise tool execution. Nothing is asserted without a traceable source.
- **Adversarial review** — the `reason.evaluate_finding` / `confidence_score` / `cite_check` calls that gate each finding, and at least one **self-correction** where TRUDI walked back a claim that didn't survive review.
- **Confidence tiers** — CONFIRMED vs LIKELY vs SUSPECTED stated explicitly (e.g. the BadUSB `defaultprinter` device-level finding is CONFIRMED; person-level intent is tiered down).

Every bundled case under [`cases/`](../cases/) ships its full trace and report — browse any of them the same way. See [docs/datasets.md](datasets.md) for what each one is and where its evidence comes from.

---

## Path B — Run a fresh investigation

This drives TRUDI end-to-end. It needs the evidence (not committed — it's large and better fetched from source) and an `ANTHROPIC_API_KEY`.

**1. Add your key.** Edit `~/trudi/.env`:

```bash
ANTHROPIC_API_KEY=sk-ant-...

# Submission default — Opus for both reasoning surfaces:
REASON_BACKEND=claude
DAIR_BACKEND=claude
REASON_MODEL=claude-opus-4-8
DAIR_MODEL=claude-opus-4-8
```

> Optional: `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` add IOC corroboration but never block a run. Everything else degrades gracefully — except the two keys above, whose absence skips the review/direction loop entirely.

**2. Get the evidence.** Each case in [docs/datasets.md](datasets.md) links to its authoritative source. The bundled case briefs (`~/cases/<CASE>/CLAUDE.md`) already have the evidence paths filled in, so the simplest reproduction is to drop the matching image into an existing bundled case:

```bash
# Example: NITROBA-2008 (a small ~54 MB PCAP — the lightest fresh run)
#   source: https://digitalcorpora.org/corpora/scenarios/nitroba-university-harassment-scenario/
cp /path/to/nitroba.pcap ~/cases/nitroba/evidence/
```

Or start a brand-new case from the template:

```bash
cp -r ~/trudi/case-template ~/cases/<CASE_ID>
# edit ~/cases/<CASE_ID>/CLAUDE.md — evidence paths, hostnames, the case question
cp /path/to/image.E01 ~/cases/<CASE_ID>/evidence/
```

**3. Run it.**

```bash
cd ~/cases/<CASE_ID>
claude
```

Then prompt:

```
Investigate this case. Start with the pre-enumeration triage, then follow the plan.
```

TRUDI runs autonomously — no confirmation between steps. It prints the **live dashboard URL** for this run at the start, so you can watch the trace fill in real time (`./dashboard.sh` in another terminal if it isn't already up).

**4. Read the output.**

```
~/cases/<CASE_ID>/reports/<CASE_ID>_investigation_report.md   ← analyst report
~/cases/<CASE_ID>/reports/<CASE_ID>_trace.{json,md}           ← exported audit trail (component #8)
~/cases/<CASE_ID>/analysis/<CASE_ID>_trace.json               ← live trace (dashboard input)
```

**5. (Optional) Score it.** For cases with a machine-readable answer key (CFReDS, DEMO-LIVE), compare automatically:

```
Ask TRUDI: "Score this run against ground_truth.json with accuracy.accuracy_compare."
```

For the others, the published answer keys and TRUDI's scored results are in the [accuracy report](accuracy-report.md).

---

## Verifying the install worked

```bash
# MCP server is registered
claude mcp list | grep trudi-sift

# Slash commands + skills are installed
ls ~/.claude/commands/trudi-*.md
ls ~/.claude/skills/

# The test suite passes (also run by install.sh)
cd ~/trudi && source ~/.venv/bin/activate && pytest -q

# The dashboard serves the bundled cases
./dashboard.sh           # then open http://127.0.0.1:8765
```

---

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `reason.*` / `dair.*` calls logged as **skipped** | No `ANTHROPIC_API_KEY` (or wrong backend). Add it to `~/trudi/.env`. This is the degraded mode — findings won't be challenged. |
| Dashboard shows no cases | `install.sh` copies bundled cases only if `~/cases/<name>` doesn't already exist. Confirm with `ls ~/cases`; point at another root with `./dashboard.sh --cases-root <path>`. |
| Port 8765 in use | `./dashboard.sh --port 9090` |
| Volatility plugin times out / `-1` exit | Symbols not cached — run `vol.symbol_check` on the image first; raise `TRUDI_VOL_TIMEOUT` in `.env` on slow hardware. |
| EZ Tools fail | `dotnet` missing — install the SIFT Workstation, which bundles the .NET runtime. |
| `claude: command not found` | Install Protocol SIFT first (it installs Claude Code). |
| `Unable to locate package <pst-utils/pff-tools/tcpxtract>` | `universe` apt component not enabled, or apt index stale on a fresh image. `sudo add-apt-repository -y universe && sudo apt-get update`, then re-run `./install.sh`. (The package is `pst-utils`, never `libpst-utils`.) |
| `misc.readpst_extract` / `misc.pff_export` fail with "not installed" | `pst-utils` / `pff-tools` missing — see [System forensic packages](#system-forensic-packages). |
| venv step fails: `ensurepip is not available` | The venv package matching your `python3` isn't installed — **the SIFT base does not ship it** (SIFT's `python3` is 3.12). Install the **version-matched** package, not just the metapackage: `sudo apt-get install -y python3.12-venv python3-pip` (replace `3.12` with `python3 --version`), then `rm -rf ~/.venv` and re-run `./install.sh`. (`install.sh` now auto-installs the matching `pythonX.Y-venv` and retries.) |
| Hooks not firing | Open `/hooks` in Claude Code once to reload, or restart the session. |

---

For the architecture behind what you're running, see [architecture.md](architecture.md); for how findings are kept honest, see the [accuracy report](accuracy-report.md).
