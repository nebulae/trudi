# TRUDI — Threat Response Unit for Digital Investigation

*Find Evil! Hackathon — Written Project Description (Devpost story)*

## TL;DR

Most AI agents are a single model grading their own work, which is how a confident hallucination ends up in a report. TRUDI splits the job across three. Claude runs the tools, a DAIR director decides what to examine next, and an adversarial reviewer challenges every conclusion before it's written. Each finding is tagged CONFIRMED, LIKELY, or SUSPECTED, and server-enforced gates make integrity structural: a CONFIRMED finding cannot be recorded without a link to the tool call that proves it. Machine-speed investigation, conclusions you can defend.

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

TRUDI is a three-model system sitting behind a typed MCP boundary.

- **Claude (primary analyst)** orchestrates the investigation, selects tools, interprets
  output, and writes the report.
- **An adversarial reviewer** (`reason.*`, with a swappable backend: Claude API, any
  OpenAI-compatible endpoint, or a local Foundation-Sec-8B-Reasoning model) plays two roles.
  Upstream, it builds the investigation plan and binds which tools run next. Downstream, it
  challenges every conclusion before it reaches the report.
- **A DAIR phase director** keeps the investigation in a recursive state machine (Triage,
  Collect, Analyze, Scan, Report), prescribes the next tool batch, and pushes a new Triage
  loop whenever lateral movement points at a new host.

### How a conclusion gets earned

The reasoning isn't one "analyze" step. It's a loop with named checkpoints, and every checkpoint
leaves a row in the trace.

It starts with the **case question**. Before any tool runs, `reason.hypothesize` turns that
question ("who sent the harassing email?", "what was exfiltrated?") into a set of competing,
testable hypotheses, and it is *required* to produce at least one that isn't the obvious
narrative: a genuinely different actor or mechanism. Each hypothesis gets an ID (`H0007`), and the
call hands back the **discriminators**, the specific tool calls that would separate the top two
explanations (a logon type and source address, USB serials across user profiles, a
registry-to-account binding). Those become the work order. The goal is to attack the question from
more than one direction at once instead of locking onto the first plausible story, which is the
single most expensive failure mode in an investigation.

`reason.plan` runs at the top of every triage phase and turns the current evidence picture into a
prioritized, manifest-backed tool sequence, so the agent collects in a sensible order instead of
flailing. As artifacts come in, hypotheses are confirmed, refuted, or split, and a contested actor
can't just be left dangling: a competing principal rated medium-likelihood or higher has to be
driven to CONFIRMED or REFUTED (or explicitly parked as evidence-unavailable) before the case can
close.

There's a deliberate tension built into that loop. DAIR hands down a strict work order and the
agent runs exactly that, no improvising mid-batch, but a rigid agent misses the artifact nobody
told it to look for. So once the prescribed batch is done, DAIR also grants a **curiosity budget**:
a small, bounded number of read-only probes the agent may spend on its own hunches, a second user's
Recycle Bin, an untouched mailbox, a `setupapi.dev.log` nobody asked about, a weaker exfil channel
worth ruling out. Each probe is logged with the reason the agent looked
(`misc.record_curiosity_probe`), and crucially a probe is *not* a finding: it carries no
evidentiary weight until whatever it turns up is fed back through the same hypothesis-and-gate path
as everything else. It widens coverage without loosening a single gate, and the budget is zero in
the Report phase, so the agent can't go wandering when it should be writing up.

Before any strong claim is written, a finding has to survive a per-finding review chain:
`reason.evaluate_finding` (does the evidence actually support this, or is it CHALLENGED?),
`reason.confidence_score` (an evidence-grounded tier and a 0–1 score; if it comes back lower than
intended, the finding is downgraded), and `reason.cite_check` (does every concrete claim, every
path, IP, hash, and technique ID, cite a real artifact?). At the end, `reason.synthesize` checks
the whole finding set for cross-consistency and `reason.pre_report_check` refuses to let the report
be written while any blocking issue remains: an unresolved second principal, an attribution with no
logon/session evidence behind it, a case question left unanswered. Each finding carries the ID of
the hypothesis it tested, so the trace reads as hypothesis → evidence → verdict, not a flat list of
assertions.

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
- **Read-only by construction.** This submission investigates static evidence (disk images,
  memory captures, PCAPs). The agent has no write path to the system under analysis, and
  response is advisory only: recommended actions are printed as copy-pasteable commands in the
  report for the analyst to run, keeping the human in the loop on anything that changes a system.
  (An experimental live-endpoint layer, `live.*` / `velo.*` / `monitor.*`, extends the same
  read-only boundary to running hosts. It runs today but is still in progress and is **not part
  of this submission**, see *What's next*.)
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

### Gates that can refuse a finding

The checkpoints above are advice until something enforces them. What makes them real is that
`record_finding` (and the final report export) run through a set of **server-side gates** that
return a hard refusal, not a warning, when a finding doesn't clear the bar. The agent can't talk
its way past them, because they're computed from the trace and the finding's own metadata, not from
the prose of the request. A representative few:

- **`confirmed_requires_linked_call_id` / `linked_call_id_must_exist`** — a CONFIRMED finding must
  point at the real `_trudi_call_id` of the tool execution that produced it. No link, or a
  made-up one, no finding.
- **`confirmed_requires_supported_evaluate`** — if the most recent `reason.evaluate_finding` came
  back CHALLENGED or UNCERTAIN, the CONFIRMED claim is refused until it is supported or downgraded.
- **`confidence_and_citation`** — a CONFIRMED/LIKELY finding needs a fresh confidence score and
  citation check tied to *its own* text; one review can't be reused to wave a second finding
  through.
- **`hypothesize_required`** — a finding about a process, service, persistence, C2, or lateral
  movement has to trace back to a hypothesis, so conclusions stay tied to a question that was
  actually asked.
- **`principal_attribution_grounding` / `named_actor_attribution_grounding`** — binding an account
  or a named person to an action ("X exfiltrated…", "account Y is operated by Z") is refused
  unless the evidence includes an authentication/session artifact (a 4624/4625 logon by type and
  source, an RDP session, an SSH login). An account name is not a person.
- **`exfil_channel_grounding`** — claiming data left the host over a channel needs a transfer
  artifact (bytes moved, an FTP log, a USN write, a mail attachment), not just "the tool was
  installed" or "a file sat in a sync folder." Staging is not egress.
- **`mcp_routing`** — a finding that cites a raw shelled-out binary instead of the typed MCP
  wrapper is refused, which keeps the audit trail inside the boundary.
- **`negative_completeness` / `negative_from_truncated`** — an absence claim ("no RDP logons", "no
  persistence") is refused unless the trace searched the complete source set for that claim, and
  refused outright if its evidence was a truncated scan.
- **`mitre_technique_validation`** — any ATT&CK technique ID in a finding is validated against the
  real ATT&CK catalog; an invented `T####` is rejected with the offending string.
- **`reformulation_depth_limit`** — re-evaluating the same finding repeatedly with no new evidence
  in between is blocked, so the agent can't grind a weak finding through review by rewording it.

This is why "autonomous" doesn't mean "unaccountable." Most of the hardening work was finding a new
way to be wrong on a real case (below) and then turning the fix into a gate, so the same mistake
can't recur on the next case, or the next user's.

Every tool call, reasoning call, DAIR transition, self-correction, curiosity probe, and finding
is written to a live JSON/Markdown trace, rendered in a dashboard, and scored by an accuracy
framework against ground truth: precision, recall, $F_1 = 2 \cdot \frac{P \cdot R}{P + R}$, and a
negative-coverage metric that rewards the "we looked for X and found nothing" findings instead of
ignoring them.

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

But structure alone makes a rigid agent, and rigid agents miss things. The harder lesson was that
the two have to coexist: the same framework that refuses an ungrounded finding also has to give the
agent room to chase a hunch, as long as that exploration is logged and carries no weight until it
survives the gates. That's what the curiosity budget is for. Curiosity you can audit is the part
that turns a checklist-runner into an investigator.

## What's next

- Promote the experimental live-monitoring layer (Velociraptor-backed) from in-progress
  scaffolding to a supported, standing deployment. It already runs today (baselining a host and
  opening a per-alert investigation under the same gates) but is out of scope for this submission.
- Expand the ground-truth corpus so the accuracy framework reports FP/FN and negative-coverage
  across all bundled cases, not just the demo.
- Package additional reference datasets so any practitioner can reproduce a full investigation
  end-to-end on a fresh SIFT Workstation.

---

*Built on the SANS SIFT Workstation. Released under the [MIT License](../LICENSE).
Code: https://github.com/nebulae/trudi*
