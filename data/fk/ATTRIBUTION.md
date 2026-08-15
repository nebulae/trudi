# TRUDI Forensic-Knowledge Corpus — Source Attribution

TRUDI's tool-response enrichment sheets (`artifacts/**/*.yaml`,
`tools/**/*.yaml`) are **derived from** AppliedIR's `forensic-knowledge`
package, used under the MIT License. A verbatim copy of the upstream MIT
license and copyright notice is retained at
[`THIRD_PARTY/forensic-knowledge/LICENSE`](THIRD_PARTY/forensic-knowledge/LICENSE),
satisfying the MIT requirement that the notice travel with substantial
portions.

## Upstream Source

| Field | Value |
|-------|-------|
| Project | AppliedIR `forensic-knowledge` (part of `sift-mcp` / Valhuntir) |
| Repository | https://github.com/AppliedIR/sift-mcp |
| Package | `packages/forensic-knowledge`, version `0.6.1` |
| Commit | `c67a860ea70c38dc3c5243193a76f0bcbd6db18f` |
| License | MIT — Copyright (c) 2026 AppliedIncidentResponse.com |

## Modifications made in TRUDI's derivation

The underlying forensic knowledge (what an artifact does / does **not**
prove, common misinterpretations, field meanings, caveats) is universal
DFIR fact. TRUDI's sheets keep that knowledge and adapt the structure to
TRUDI's architecture:

- **Removed** Valhuntir platform-wiring fields: `cross_mcp_checks`,
  `related_tools`, `investigation_sequence`, and `(via sift-mcp)` asides
  — they reference MCP servers that do not exist in TRUDI.
- **Removed** `references:` (third-party course/citation lists).
- **Retargeted** `corroborate_with` values from bare artifact names to
  the TRUDI tool that produces each one (e.g. `prefetch` →
  `Prefetch (ez_pecmd)`).
- **Added** a `trudi_tools:` key mapping each sheet to the TRUDI tool
  names whose output it enriches.

Only the neutral forensic knowledge is retained; none of Valhuntir's
platform integration is reproduced.
