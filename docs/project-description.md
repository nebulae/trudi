# TRUDI — Threat Response Unit for Digital Investigation

*Find Evil! Hackathon — Written Project Description (Devpost story)*

> TRUDI is an autonomous DFIR agent that runs a full incident-response investigation on
> the SANS SIFT Workstation: disk triage, memory forensics, Windows artifacts, network
> and YARA hunting. It produces a court-defensible report where every conclusion has
> survived an adversarial reviewer and links back to the exact tool execution that
> produced it.

---

## Inspiration

AI adversaries already move at machine speed. CrowdStrike clocked a 7-minute fastest
breakout. Horizon3's autonomous agent went from foothold to full privilege escalation in
60 seconds. MIT's 2024 work measured AI-driven attacks running about 47× faster than human
operators. Incident response, meanwhile, is still paced by a human analyst typing `vol`,
reading the output, deciding the next command, and writing notes by hand.

TRUDI is my answer to that gap. It's an autonomous responder that keeps up with adversary
speed without giving up the two things that make forensic work admissible: evidence
integrity and analytical accuracy. The hard part was never running the tools fast. It was
running them fast while guaranteeing the agent can't tamper with evidence, can't hallucinate
a finding into a report, and can't make a claim that doesn't trace back to a specific
command. 

## What it does

You drop evidence into a case directory, open Claude Code, and TRUDI runs the whole
investigation on its own, with no per-step confirmation. It:

- **Triages and characterizes the system**: registry hives, OS build, users, timezone,
  attached devices.
- **Does deep memory forensics** with Volatility 3: process trees, injected code, network
  endpoints, masqueraded binaries.
- **Parses Windows artifacts** with the EZ Tools suite: MFT, event logs, ShimCache, Amcache,
  UserAssist, prefetch, jump lists.
- **Carves and recovers** deleted files, hunts with YARA, enriches IOCs against threat
  intel, and builds super-timelines with Plaso.
- **Cross-references every identity** it finds (emails, usernames, SIDs, cookie values)
  against any suspect roster in the case brief, normalizing usernames, separators, and email
  prefixes before it ever concludes "attribution unknown."
- **Writes a structured report** with findings tiered CONFIRMED / LIKELY / SUSPECTED /
  UNCONFIRMED, an attack narrative, an ATT&CK mapping, and a complete execution log.

Two real investigations show the range.

**NIST CFReDS "Data Leakage Case."** TRUDI reconstructed an insider conspiracy across five
exfil channels (email, two USBs, a CD-R, and Google Drive) and produced the smoking gun on
its own. A decoy-named file, `winter_whether_advisory.zip`, recovered from the deleted area
of an unauthorized USB, turned out to be byte-for-byte identical (SHA-256 match, 16,381,123
bytes) to a confidential design deck on the authorized device. The decoy *was* the stolen
presentation.

**SRL-2018 enterprise APT (CRIMSON OSPREY).** Across 8 hosts, TRUDI confirmed a Cobalt Strike
beacon (`p.exe`, PID 8260) running under a stolen Domain Admin token and beaconing to an
internal C2, with the full WMI→PowerShell→cmd→implant execution chain and lateral movement
traced through NTLM logon records.

## How I built it

TRUDI is a two-model system sitting behind a typed MCP boundary.

- **Claude (primary analyst)** orchestrates the investigation, selects tools, interprets
  output, and writes the report.
- **An adversarial reviewer** (`reason.*`, with a swappable backend: Claude API, any
  OpenAI-compatible endpoint, or a local Foundation-Sec-8B-Reasoning model) plays two roles.
  Upstream, it builds the investigation plan and binds which tools run next. Downstream, it
  challenges every conclusion before it reaches the report.
- **A DAIR phase director** keeps the investigation in a recursive state machine (Triage,
  Collect, Analyze, Scan, Report), prescribes the next tool batch, and pushes a new Triage
  loop whenever lateral movement points at a new host.

Everything the agent does crosses one boundary: the TRUDI MCP server, which mounts over 250
typed tools across 24 namespaces. The agent never shells out to `vol` or `RECmd.dll`
directly. It calls a typed wrapper, and a safe executor runs the court-vetted binary with
retry, timeout, and a line cap. What the boundary exposes:

- **Wrapped SIFT forensics.** The court-vetted CLI tools the Workstation ships with, surfaced
  as typed functions: Volatility 3 (`vol.*`), The Sleuth Kit (`tsk.*`), EZ Tools (`ez.*`),
  Plaso (`plaso.*`), YARA (`yara.*`), `bulk_extractor`/`foremost`/`scalpel` (`carve.*`),
  network tooling (`net.*`), EWF and image mounting (`ewf.*`, `img.*`), hashing (`hash.*`),
  static analysis (`strings.*`), and a `misc.*` namespace covering email, registry,
  event-log, and macro tooling.
- **Beyond static evidence.** TRUDI doesn't stop at dead-box images. `live.*` does read-only
  live endpoint analysis over argv-only SSH (processes, connections, persistence, open files,
  log tails). `velo.*` wraps the Velociraptor API surface (client enumeration, artifact
  collection, event tables, VQL queries). `monitor.*` drives a live-monitoring lifecycle
  (baseline capture, watchers, alert draining). TRUDI never runs containment or remediation
  itself. Response steps are printed as copy-pasteable commands in the report for the analyst
  to run, which keeps the agent strictly read-only and the human in the loop on anything that
  changes a system.
- **Added analysis tooling.** `enrich.*` (threat-intel lookups), `correlate.*` (cross-tool
  joins and ATT&CK mapping), `af.*` (anti-forensics detection), `attribution.*`,
  `accuracy.*`, and `coverage.*` for scoring and ground-truth comparison.
- **The agent's own decision-support is also MCP tools.** The DAIR phase director (`dair.*`)
  and the adversarial reviewer (`reason.*`) aren't external sidecars. They're mounted as typed
  MCP tool families on the same server, so the guidance that steers the investigation and the
  execution that carries it out cross the same audited boundary. Every `dair_assess`, every
  `reason.*` plan, hypothesis, and evaluation, and every forensic command lands in one trace
  under one `_trudi_call_id` scheme. The two families stay independent: Claude consumes both
  result streams, and neither calls the other.

The point of all of this is that the guardrails are architectural, not just prompt text (see
[architecture.md](architecture.md)):

| Guardrail | How it's enforced (not just asked) |
| --- | --- |
| Evidence stays read-only | `core/paths.py` + `core/executor.py` reject any output path resolving under `/cases/`, `/mnt/`, `/media/`, or an `evidence/` segment **before** the subprocess runs |
| Tools must route through MCP | middleware detects direct forensic-binary use; the `mcp_routing` gate refuses any finding citing a raw bash execution |
| Findings must be traceable | `misc.record_finding` requires a `linked_call_id` pointing at the producing `_trudi_call_id`. No link, no finding |
| Confirmed claims require review | confidence-score, citation-check, hypothesis, lineage, and adversarial-evaluate gates hard-block unsupported CONFIRMED/LIKELY findings |
| Response stays advisory | TRUDI runs no containment or remediation; recommended actions are printed as commands in the report for the analyst to run, keeping the human in the loop on every system-changing action |

Every tool call, reasoning call, DAIR transition, self-correction, and finding is written to a
live JSON/Markdown trace, rendered in a dashboard, and scored by an accuracy framework against
ground truth (precision, recall, F1, and negative-coverage).

## Challenges I ran into

Every one of these came out of an autonomous run that *failed*. I let TRUDI loose on real
forensic datasets, watched where it reached the wrong conclusion, and then hardened the
architecture so the same kind of mistake couldn't happen again. That diagnose-and-harden cycle
was most of what building TRUDI actually was.

- **It confidently concluded "no suspect," and it was wrong.** On the Nitroba harassment case,
  a two-hour autonomous run reported that no roster name appeared in the captured traffic and
  deferred attribution to legal process. The suspect's Gmail address was sitting in the PCAP in
  cleartext 116 times. The cause wasn't reasoning, it was a leaky tool. The `ngrep` wrapper
  printed one progress `#` per inspected packet, and on an 83,000-packet capture those markers
  filled the output buffer before any match line, so a real hit came back flagged
  `truncated: true`. The agent then recorded a negative finding citing that truncated scan as
  its evidence. I fixed the wrapper (suppress the progress dump, raise the buffer), but the real
  fix was architectural: a new `negative_from_truncated` gate that refuses any "we found
  nothing" finding whose evidence is a truncated result. The agent can't record that conclusion
  now even if it tries. Honest negatives have to come from a clean scan.
- **"Defensible" is not the same as "correct."** The adversarial-review gate was built to block
  unsupported findings, but it quietly rewarded a finding the agent could defend even when the
  right answer was elsewhere in the evidence. The agent would reword a wrong-but-defensible
  finding to get it past review instead of going back to look harder. So I added a
  `reformulation_depth_limit`. Re-evaluate the same finding twice with no new tool calls in
  between and the third attempt is refused, which forces the agent to gather fresh evidence or
  move on. It optimizes for answering the case question, not for surviving the gate.
- **The agent searched in the wrong direction.** Handed a suspect roster, it would enumerate the
  whole evidence set first and only then ask "does any of this match a known name?" That's slow,
  and it's easy to miss derived forms. I inverted it. When the case context contains an
  enumerable reference set (a roster, asset inventory, hash list, allowlist), Triage now derives
  search terms from the knowns and hunts them as IOCs in the first batch
  (`knowns_pattern_generate`). And because `Johnny Coach` shows up as `jcoach`, `coachj`, or
  `jcoachj@gmail.com`, identifier matching now normalizes both sides (case, separators,
  name-to-username derivations, email-prefix extraction, hash-family equivalence) before any
  "no match" is allowed to stand.
- **An investigation could finish without answering the question it was opened on.** The phase
  model would move to Report once artifact exhaustion was satisfied, so a run could catalogue
  every process, file, and connection and still never say who did what. Enumeration isn't
  attribution. I made the case question a first-class object. It's stated in the case context,
  turned into testable hypotheses at the start, and a pre-report gate refuses to call the
  investigation done unless at least one CONFIRMED or LIKELY finding actually addresses the
  question's key entities.
- **Keeping the audit trail a real causal graph.** For the trace to be evidence, every entry
  has to link back to whatever prescribed it. Early on, most tool calls and narration entries
  carried no lineage at all, and the DAG was inferred from text proximity. I threaded the
  prescribing `dair_assess` call ID through the executor and middleware so every tool call,
  narration, and finding stamps its parent, leaving exactly one root entry with no predecessor.
  The trace became a graph the synthesis step and accuracy report can walk by foreign key
  instead of by guesswork.

## Accomplishments I'm proud of

**A real autonomous self-correction, not a scripted one.** On the SRL-2018 APT case, TRUDI was
handed an initial-responder IOC briefing naming `STUN.exe`, `pssdnsvc.exe`, an `msedge.exe`
masquerade, an `atmfd.dll` phantom driver, an external C2 at `172.15.1.20`, and a 2023
timeline. Working from raw memory and disk, the agent refuted the briefing it was given. None
of those indicators held up on the host. Instead it surfaced the real implant
(`C:\Windows\Temp\Perfmon\p.exe`), the actual internal C2 (`172.16.4.10:8080`), the full
`WmiPrvSE → PowerShell → cmd → p.exe` execution chain, and the stolen Domain Admin account
(`spsql`), and it corrected the timeline to August and September 2018. The trace shows the
agent explicitly resisting the temptation to chase the named artifacts and verifying each
briefed IOC against raw evidence first. It trusted the evidence over the prompt.

**The failure that became the proof.** The Nitroba false-negative above didn't just get
patched. The hardened TRUDI re-ran the case end to end and got it right. It placed the harassing
web-mail submissions on a single device (a Mac at `192.168.15.4`, MAC `00:17:f2:e2:c0:ce`), tied
the same browser session to `jcoachj@gmail.com` and roster member Johnny Coach, and also
surfaced two more roster identities active on that device (`amy789smith`, `avabook3@gmail.com`)
that the first run never found. The whole diagnose-and-harden loop is sitting in the trace as a
working artifact, not a claim.

**It found a harassing email no prior account of the case included.** The Nitroba case is
usually told through the single `willselfdestruct.com` threat ("you can't find us… Stop
teaching. Start running."). Because the Exhaustive Evidence Rule says never stop at the first
artifact of a type, and one email is never all the email, TRUDI swept the entire capture for
web-mail submissions and recovered a previously unaccounted-for message sent through a different
anonymous service: a POST to `sendanonymousemail.net`, sender
`the_whole_world_is_watching@nitroba.org`, subject *"Your class stinks"*, to the same victim
`lilytuckrige@yahoo.com`, captured in full at packet #69924 and recorded as a CONFIRMED finding.
A second channel from the same device strengthens the attribution and widens the pattern of
conduct, and it only surfaced because the agent was told not to stop at the first message that
already explained the case.

**It knows what it doesn't know.** For accuracy, the thing I'm proudest of is restraint. On that
same Nitroba re-run, TRUDI rated device-level attribution CONFIRMED but person-level attribution
only LIKELY, and said why in the report: the open, passwordless dorm Wi-Fi and the multiple
personal accounts on the one device bind the act to a device and a logged-in account, "not a
specific pair of hands on the keyboard." On the CFReDS insider case it tiered with the same
discipline. The email thread was LIKELY (single-sided OST, and `X-Originating-IP` is a
client-inserted header rather than an authenticated `Received:` chain). The Google Drive channel
was only SUSPECTED (the sync databases were deleted and the evidence was genuinely exhausted).
The byte-for-byte SHA-256 match between a decoy-renamed deleted file and the stolen design deck
was CONFIRMED. An agent that says LIKELY when the evidence only supports likely is worth more
than one that always says CONFIRMED.

**Negative findings are scored, not skipped.** "We looked for X and found nothing" is real
forensic work, so TRUDI records it as evidence. On CFReDS it confirmed no timestomping (0 drift
across 98,904 `$SI`/`$FN` pairs) and no event-log clearing (0 × EID 1102/104), each as a tiered
finding linked to the tool that proved the absence. Those feed the accuracy framework's
negative-coverage metric.

**The same agent and the same guardrails across very different cases.** TRUDI has run an 8-host
enterprise APT (memory, disk, event logs), a multi-channel insider data theft (five exfil
channels across email, two USBs, a CD-R, and cloud, with per-device anti-forensics), and a
network-only harassment attribution from a single PCAP, plus M57, Schardt, and ROCBA. It's
depth, not just coverage: individual runs produced 16–28 tiered findings over traces of 100 to
350-plus fully linked entries.

**The system worked well enough that I extended it past dead-box forensics.** TRUDI started as a
post-incident, read-only investigator of static evidence: disk images, memory, PCAPs. Once it
had proven itself case after case, I extended the same architecture to live endpoints. There's
now a Velociraptor-backed live-monitoring loop that baselines a host, watches for drift, and
opens a focused, per-alert investigation when something fires, running the identical
`hypothesize → dair_assess → record_finding` chain it runs against a disk image, into the same
trace under the same gates. The read-only stance carries over without changes: monitoring
observes and recommends, and the analyst runs the printed remediation. The fact that the
guardrail architecture dropped cleanly onto a live host without loosening any of it is the best
evidence I have that the design generalizes beyond the cases it was built on.

**The constraint layer is architectural, not prose.** TRUDI physically can't write to an
evidence file or submit an unlinked finding, because the MCP boundary, the read-only path guard,
and the finding gates reject it before anything runs. The judges' distinction between
architectural and prompt-based guardrails is the whole design, and you can demonstrate it by
trying to violate it and watching the gate refuse.

## What I learned

Autonomy in forensics isn't "let the model run." It's building a structure that forces the model
to show its work: a phase director that won't let it skip ahead, an adversary that won't let weak
findings through, and a trace where every claim has a foreign key back to the command that
produced it. Once that structure exists, the speed comes for free. The slow part of IR was never
the tools.

## What's next

- Broaden the live-monitoring loop (Velociraptor-backed) from demo to a standing deployment,
  with richer printed-remediation playbooks for the analyst.
- Expand the ground-truth corpus so the accuracy framework reports FP/FN and negative-coverage
  across all bundled cases, not just the demo.
- Package additional reference datasets so any practitioner can reproduce a full investigation
  end-to-end on a fresh SIFT Workstation.

---

*Built on the SANS SIFT Workstation. Released under the [MIT License](../LICENSE).
Code: https://github.com/nebulae/trudi*
