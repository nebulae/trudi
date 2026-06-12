# TRUDI

**Threat Response Unit for Digital Investigation**

Autonomous DFIR agent built on the SANS SIFT Workstation. TRUDI runs a complete incident response investigation — disk triage, memory forensics, Windows artifact parsing, IOC enrichment, YARA hunting — and produces a structured analyst report with a full audit trail, without prompting for confirmation at each step.

Every conclusion is challenged by an adversarial reviewer before it reaches the report. TRUDI only reports what survives both.

Built for the [Find Evil! hackathon](https://findevil.devpost.com/) — SANS Institute / Devpost, April–June 2026.

---

## How it works

TRUDI is a two-model system:

**Claude (primary analyst)** — orchestrates the investigation, selects tools, runs them via the TRUDI MCP server, interprets output, and writes the report.

**Adversarial reviewer** — a second model running against a different set of system prompts, playing two roles in every investigation:

1. **Upstream** — given the evidence profile at case open, it generates a prioritized investigation plan and directs which tools to run first.
2. **Downstream** — after findings are assembled, it challenges each conclusion before the report is written, flagging unsupported claims, logical gaps, and alternative explanations.

The reviewer backend is swappable via `REASON_BACKEND` in `.env` — Claude API (default), any OpenAI-compatible endpoint, or Foundation-Sec-8B-Reasoning. The two models exchange structured `DIRECTIVES` blocks that bind tool selection for the next phase. Disagreements are resolved by a capped self-correction loop (max 3 iterations); unresolved items are reported as `UNCERTAIN` rather than dropped.

### Execution flow

```
case opened
    │
    ├─ misc.start_execution_log         ← trace log initialized
    │
    ├─ [parallel] registry triage       ← ez.recmd_hive ×3 + strings.stat_file
    │
    ├─ reason.plan                      ← Foundation-Sec sets investigation priority
    │       └─ directives.priority_tools → manifest-backed bound tool sequence
    │
    ├─ [tool runs — disk, memory, artifacts, network, enrichment]
    │       └─ reason.hypothesize       ← called for each ambiguous finding
    │       └─ reason.evaluate_finding  ← called before any "confirmed" claim
    │
    ├─ reason.synthesize                ← cross-finding consistency check
    │
    ├─ misc.export_execution_log        ← trace written to reports/
    │
    └─ misc.write_final_report          ← gated final report write
```

Every tool call, reason call, and confirmed finding is written to a live JSON trace log throughout the investigation. The markdown export is human-readable.

---

## Prerequisites

1. **SANS SIFT Workstation** — Ubuntu 22.04 x86-64 with forensic tools (Volatility 3, EZ Tools, Sleuth Kit, Plaso, YARA, bulk_extractor, etc.)
   - Download: https://www.sans.org/tools/sift-workstation/

2. **Protocol SIFT** — installs Claude Code and the forensic skill playbooks
   - Install: https://github.com/teamdfir/protocol-sift

3. **Python 3.10+** and **dotnet** — both included in SIFT Workstation

4. **Reasoning backend** *(optional but required for adversarial review)*
   Set `REASON_BACKEND` in `.env` to select which model powers the review loop:

   | Backend | Config |
   |---------|--------|
   | `claude` (default) | `ANTHROPIC_API_KEY=sk-ant-...` — no server required |
   | `openai-compat` | `REASON_URL=https://api.openai.com/v1` + `REASON_API_KEY=sk-...` |
   | Foundation-Sec (local) | `REASON_BACKEND=openai-compat` + `REASON_URL=http://localhost:8000` |
   | Foundation-Sec (HF) | `REASON_BACKEND=openai-compat` + `REASON_URL=<hf-endpoint>` + `REASON_API_KEY=hf_...` |

   TRUDI degrades gracefully if no backend is configured — reason calls are logged as skipped.

---

## Setup

```bash
git clone https://github.com/nebulae/trudi ~/trudi
cd ~/trudi
./install.sh
```

`install.sh` does the following:

- Checks for `python3`, `dotnet`, and `claude` CLI
- Creates a Python venv at `~/.venv` and installs all dependencies
- Copies `.env.example` → `.env` (edit this to add API keys)
- **Backs up** any existing `~/.claude/CLAUDE.md` with a UTC timestamp, then installs the TRUDI orchestrator
- Registers the TRUDI MCP server globally with `claude mcp add --scope global`
- Runs the full test suite (403 tests) as a smoke check

If `~/.claude/CLAUDE.md` already exists (e.g. from a Protocol SIFT install), the backup is written to `~/.claude/CLAUDE.md.<YYYYMMDDTHHMMSS>.bak` — the original is never overwritten without a backup.

### API keys (optional)

Edit `~/trudi/.env`. All keys are optional — TRUDI degrades gracefully when they are absent.

```bash
# IOC enrichment
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here

# Reasoning backend (pick one)
REASON_BACKEND=claude
ANTHROPIC_API_KEY=sk-ant-...          # Claude API — recommended

# REASON_BACKEND=openai-compat
# REASON_URL=https://api.openai.com/v1   # or http://localhost:8000 for local vLLM
# REASON_API_KEY=sk-...
# REASON_MODEL=gpt-4o-mini
```

**Foundation-Sec (openai-compat backend, local vLLM):**
```bash
pip install vllm
vllm serve "fdtn-ai/Foundation-Sec-8B-Reasoning" \
  --reasoning-parser minimax_m2 \
  --quantization bitsandbytes --load-format bitsandbytes  # for <24 GB VRAM
# then set: REASON_BACKEND=openai-compat, REASON_URL=http://localhost:8000
```

---

## Starting a case

### 1. Create the case directory

```bash
cp -r ~/trudi/case-template ~/cases/<CASE_ID>
```

### 2. Edit the case CLAUDE.md

Fill in evidence paths, hostnames, and scope in `~/cases/<CASE_ID>/CLAUDE.md`. This is the only manual step — everything else is autonomous.

```
~/cases/<CASE_ID>/
├── CLAUDE.md                  ← edit this
├── .claude/
│   └── settings.json          ← MCP tool allowlist (pre-populated)
├── evidence/                  ← place disk images and memory captures here
├── analysis/                  ← intermediate artifacts (auto-created)
├── exports/                   ← tool output: CSV, JSON, bodyfiles (auto-created)
└── reports/                   ← final report + trace log (auto-created)
```

### 3. Place evidence

```bash
cp /path/to/image.E01 ~/cases/<CASE_ID>/evidence/
cp /path/to/memory.img ~/cases/<CASE_ID>/evidence/
```

### 4. Open Claude Code in the case directory

```bash
cd ~/cases/<CASE_ID>
claude
```

### 5. Start the investigation

```
Investigate this case. Start with the pre-enumeration triage, then follow the plan.
```

TRUDI will run autonomously from there. It will not ask for confirmation between steps. Final output is a structured report in `reports/` and a full execution trace in both JSON and markdown.

---

## What gets produced

| File | Contents |
|------|----------|
| `reports/<CASE_ID>_investigation_report.md` | Structured analyst report — executive summary, attack timeline, findings with confidence levels, environment caveats |
| `reports/<CASE_ID>_trace.md` | Human-readable audit trail — every tool call, reason call, and confirmed finding with UTC timestamps |
| `reports/<CASE_ID>_trace.json` | Machine-readable trace — same data, structured for ingestion |
| `analysis/<CASE_ID>_trace.json` | Live trace (written incrementally during the investigation) |
| `exports/` | Raw tool output — MFT CSV, EVTX exports, prefetch, registry, amcache, shimcache, USN journal, netscan, etc. |

## Submission artifacts

| File | Contents |
|------|----------|
| `docs/architecture.md` | Find Evil! architecture diagram covering MCP components, architectural guardrails, evidence boundaries, live monitoring, and traceability |
| `docs/architecture.mmd` | Raw Mermaid source for exporting the architecture diagram to SVG/PNG |

---

## Tool namespaces

All forensic execution goes through the TRUDI MCP server. Claude never calls binaries directly when an MCP tool exists.

| Namespace | Domain | Key tools |
|-----------|--------|-----------|
| `img.*` | Disk image mounting | `ewf_mount`, `vshadow_mount`, `bde_mount`, `xmount`, `photorec_carve`, `losetup_create` |
| `vol.*` | Memory forensics (Volatility 3) | `pstree`, `pslist`, `psscan`, `cmdline`, `netscan`, `dlllist`, `malfind`, `hollowprocesses`, `pebmasquerade`, `suspicious_threads`, `scheduled_tasks`, `registry_hivelist`, `dumpfiles` |
| `tsk.*` | Filesystem (Sleuth Kit) | `fls`, `icat`, `istat`, `ils`, `mactime`, `tsk_recover`, `sigfind`, `mmls`, `fsstat`, `jls`, `jcat` |
| `ewf.*` | E01 images | `ewf_mount`, `ewf_info`, `ewf_verify`, `mount_full_image`, `mount_ntfs` |
| `ez.*` | Windows artifacts (EZ Tools) | `mftecmd`, `evtxecmd`, `recmd_hive`, `amcacheparser`, `appcompatcacheparser`, `pecmd`, `lecmd`, `jlecmd`, `sbecmd`, `wxtcmd`, `sqlecmd`, `rbcmd` |
| `plaso.*` | Super-timeline | `plaso_create_timeline`, `plaso_export_csv`, `plaso_filter_incident_window`, `plaso_info` |
| `yara.*` | Threat hunting | `yara_scan_file`, `yara_scan_directory`, `yara_scan_memory_image`, `yara_scan_strings` |
| `hash.*` | Integrity / similarity | `hash_file`, `hash_directory`, `verify_evidence_hash`, `ssdeep_hash`, `hashdeep_compute` |
| `strings.*` | Static analysis | `strings_extract`, `strings_grep`, `hexdump`, `file_identify`, `exiftool_metadata`, `stat_file` |
| `carve.*` | File carving | `carve_bulk_extractor_scan`, `carve_foremost_carve`, `carve_scalpel_carve` |
| `net.*` | Network analysis | `tcpdump_read`, `tcpdump_extract_http`, `tcpdump_extract_dns`, `tcpdump_extract_ips`, `ngrep_search` |
| `enrich.*` | Threat intel | `vt_lookup_hash`, `vt_lookup_ip`, `vt_lookup_domain`, `abuseipdb_check` |
| `misc.*` | Windows artifacts | `evtx_dump`, `evtx_filter`, `regripper_hive`, `parse_scheduled_tasks`, `usbdeviceforensics`, `usnparser_parse`, `analyzeMFT_parse`, `hindsight_chrome`, `clamscan_file`, `pe_scanner`, `pdf_parser_analyze` |
| `reason.*` | Adversarial review | `reason_plan`, `reason_hypothesize`, `reason_evaluate_finding`, `reason_synthesize` |

---

## Bundled YARA rules

Located in `rules/` — used automatically by `yara.*` tool calls:

| Ruleset | Covers |
|---------|--------|
| `cobalt_strike/` | Default named pipes, reflective loader, stager patterns, beacon config |
| `persistence/` | Scheduled task XML anomalies, Run key patterns, service install signatures |
| `lateral_movement/` | Pass-the-hash, net use, SMB lateral movement indicators |
| `powershell/` | Obfuscated PowerShell, AMSI bypass, download cradles |
| `anti_forensics/` | Log clearing, timestomping, MFT manipulation indicators |

---

## Evidence constraints

TRUDI enforces read-only evidence handling at the executor level — not just by instruction. The `core/paths.py` module blocks any output write that resolves to `/cases/`, `/mnt/`, `/media/`, or any path containing an `evidence/` segment. This check runs before every subprocess call that takes an output path. It cannot be bypassed via prompt.

All tool output is capped at 50 KB / 150 lines before being returned to the agent to prevent context flooding. Truncation is flagged explicitly in the response.

---

## Running the test suite

```bash
cd ~/trudi
source ~/.venv/bin/activate
pytest --cov --tb=short
```

403 tests, ~89% coverage. All tool calls are mocked — tests run without SIFT tools installed.

---

## Repository layout

```
trudi/
├── server.py              ← FastMCP server — mounts all 14 tool namespaces
├── install.sh             ← one-command setup from a Protocol SIFT baseline
├── claude/
│   └── CLAUDE.md          ← global orchestrator (installed to ~/.claude/CLAUDE.md)
├── case-template/         ← starter case directory for new investigations
│   ├── CLAUDE.md
│   ├── .claude/settings.json
│   └── evidence/ analysis/ exports/ reports/
├── core/
│   ├── executor.py        ← safe subprocess runner (retry, timeout, line cap)
│   ├── execution_log.py   ← trace log singleton
│   └── paths.py           ← evidence path enforcement + tool binary locations
├── tools/                 ← one module per MCP namespace (14 total)
├── rules/                 ← bundled YARA rulesets (5 categories)
└── tests/                 ← full test suite (403 tests, mocked)
```

---

## License

Released under the [MIT License](LICENSE). © 2026 Trinity Harrison.
