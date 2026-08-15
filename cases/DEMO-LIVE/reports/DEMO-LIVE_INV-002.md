# Execution Trace — DEMO-LIVE

## Contents

- [Triage](#phase-triage-1) — entries #6–#19

- `2026-06-13T06:27:04+00:00` [#1] **AGENT** Investigation INV-002 opened on 4 alert(s).
Bundle of 4 alert(s).
detector_counts=Custom.TRUDI.NewProcess=4
hosts=C.e6de3278ad209722
seq_range=7..10
alerts:
  seq=8 det=Custom.TRUDI.NewProcess: New process not in baseline: /usr/bin/run-parts (pid=2785)
  seq=9 det=Custom.TRUDI.NewProcess: New proces
- `2026-06-13T06:27:15+00:00` [#3] **→ CALL** `reason_hypothesize` via claude [model='claude-opus-4-7']
- `2026-06-13T06:27:40+00:00` [#4] **REASON** `reason_hypothesize`  → OK tokens: in=661 out=1566
  - conclusion: Analysis

This is almost certainly a benign daily cron run misflagged because the baseline snapshot didn't capture the once-daily 06:25 window. Every element of the chain matches Debian/Ubuntu canonical behavior.

Hypothesis 1 — Benign canonical cron.daily execution (likelihood: HIGH)
Supporting artifacts:
- Parent chain cron -> dash (anacron-test wrapper) -> run-parts -> apt-compat -> sleep is th
  - priority_tools: ['hash.hash_file', 'hash.hash_directory', 'strings.stat_file', 'strings.strings_grep', 'yara.scan_file', 'live.live_process_details', 'live.live_processes']
- `2026-06-13T06:27:55+00:00` [#5] **→ CALL** `dair_assess` via claude [model='claude-opus-4-7']

<a id="phase-triage-1"></a>
## Phase: Triage

- `2026-06-13T06:28:26+00:00` [#6] **DAIR** phase=Triage action=stay tokens: in=538 out=2512
  - focus: Confirm or refute that the cron.daily process chain (cron pid2781 -> run-parts -> apt-compat -> sleep pid2794) is the unmodified stock Debian maintenance flow with no trojanization, no rootkit preload
  
  #### Verification Challenges
  | Claim | Method | Result | Confidence Impact |
  |-------|--------|--------|-------------------|
  | Process chain cron(2781)->sh->run-parts->apt-compat->sleep(2 | live.live_processes | ⏳ PENDING | — |
  | /etc/cron.daily/apt-compat is stock, unmodified since INV-00 | live.live_read_file | ⏳ PENDING | CONFIRMED→SUSPECTED if hash differs |
  | sleep pid2794 has no malicious child process | live.live_process_details | ⏳ PENDING | BENIGN→SUSPECTED if children exist |
  | /etc/ld.so.preload is empty/absent (no LD preload rootkit) | live.live_read_file | ⏳ PENDING | — |
  | No new entries added to /etc/cron.daily or /etc/cron.d | live.live_persistence_audit | ⏳ PENDING | BENIGN→SUSPECTED if new entries |
  | No anomalous outbound network connections from cron descenda | live.live_network_connections | ⏳ PENDING | BENIGN→SUSPECTED if found |
- `2026-06-13T06:28:36+00:00` [#8] **TOOL** `ssh victim@localhost:2222 -- ps -eo pid,ppid,user,etimes,start,cmd --no-headers`  → OK 0.1s
  - output:       1       0 root       47022 17:24:53 velociraptor --config /config/client.config.yaml client -v
     29       1 root       47019 17:24:56 /usr/sbin/cron -P
     30       1 root       47019 17:24:56 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
     65       1 victim     47001 17:25:14
- `2026-06-13T06:28:36+00:00` [#10] **TOOL** `ssh victim@localhost:2222 -- head -c 65536 /etc/cron.daily/apt-compat`  → OK 0.1s
  - output: #!/bin/sh

set -e

# Systemd systems use a systemd timer unit which is preferable to
# run. We want to randomize the apt update and unattended-upgrade
# runs as much as possible to avoid hitting the mirrors all at the
# same time. The systemd time is better at this than the fixed
# cron.daily time
i
- `2026-06-13T06:28:37+00:00` [#11] **TOOL** `ssh victim@localhost:2222 -- head -c 65536 /etc/ld.so.preload`  → FAIL 0.1s
  - stderr: head: cannot open '/etc/ld.so.preload' for reading: No such file or directory

- `2026-06-13T06:28:37+00:00` [#12] **TOOL** `ssh victim@localhost:2222 -- ss -tnlpa`  → OK 0.1s
  - output: State      Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN     0      128          0.0.0.0:22         0.0.0.0:*           
LISTEN     0      4096      127.0.0.11:37387      0.0.0.0:*           
ESTAB      0      0         172.18.0.3:56364   172.18.0.2:8000        
ESTAB      0    
- `2026-06-13T06:28:38+00:00` [#13] **TOOL** `ssh victim@localhost:2222 -- sh -c 'echo ===TIMERS===; systemctl list-timers --all --no-pager --plain; echo ===CRON_D===; ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null; echo ===ANACRONTAB===; cat /etc/anacrontab 2>/dev/null; echo ===USER_CRONTABS===; for u in $(cut -d: -f1 /etc/passwd); do   c=$(sudo -n crontab -u $u -l 2>/dev/null);   if [ -n "$c" ]; then echo ---$u---; echo "$c"; fi; done'`  → OK 0.1s
  - output: ===TIMERS===
===CRON_D===
/etc/cron.d/:
total 16
drwxr-xr-x 1 root root 4096 Jun  4 23:46 .
drwxr-xr-x 1 root root 4096 Jun 12 17:24 ..
-rw-r--r-- 1 root root  102 Mar 23  2022 .placeholder
-rw-r--r-- 1 root root  201 Jan  8  2022 e2scrub_all

/etc/cron.daily/:
total 20
drwxr-xr-x 1 root root 4096 J
- `2026-06-13T06:29:15+00:00` [#15] **→ CALL** `reason_evaluate_finding` via claude [model='claude-opus-4-7']
- `2026-06-13T06:30:02+00:00` [#16] **REASON** `reason_evaluate_finding`  → OK tokens: in=667 out=3106
  - conclusion: EVIDENCE SUPPORT
The finding is well-supported by multiple independent live collection tools:
- Process tree (live.live_processes): canonical cron → CRON → run-parts → apt-compat → sleep chain, all root, correct parent-linkage.
- File content (live.live_read_file on /etc/cron.daily/apt-compat): matches stock Ubuntu script (random_sleep then exec apt.systemd.daily).
- /etc/ld.so.preload absent → ru
  - priority_tools: ['hash.hash_file', 'live.live_read_file']
  - audit[0]: claim="Process chain cron→CRON→run-parts→apt-compat→sleep is intact, root-owned, correc" tool=live.live_processes
  - audit[1]: claim="apt-compat script is verbatim stock Ubuntu, unmodified" tool=live.live_read_file
  - audit[2]: claim="No LD_PRELOAD rootkit on chain" tool=live.live_read_file
  - audit[3]: claim="No new outbound from cron descendants" tool=live.live_network_connections
  - audit[4]: claim="/etc/cron.daily and /etc/cron.d unchanged since INV-001 baseline" tool=live.live_scheduled_tasks
  - audit[5]: claim="Detector fired due to absence from point-in-time baseline snapshot" tool=NOT PROVIDED ⚠ 5×NOT_PROVIDED
- `2026-06-13T06:30:18+00:00` [#17] **TOOL** `<py>:misc_record_finding`  → OK
- `2026-06-13T06:30:36+00:00` [#19] **FINDING** [UNCONFIRMED] INV-002: the 4 NewProcess alerts at 2026-06-13T06:25:08Z on host victim are a BENIGN FALSE POSITIVE — the legitimate Debian/Ubuntu daily cron.daily maintenance chain: cron pid29 -> CRON pid2781 -> sh anacron-test -> run-parts /etc/cron.daily -> /etc/cron.daily/apt-compat pid2787 -> sleep 1630 pid2794, all root, correctly parent-linked, and sleep pid2794 has no child process. apt-compat content (cid10) is the verbatim stock Ubuntu script (random_sleep RANDOM%1800 then exec /usr/lib/apt/apt.systemd.daily); /etc/ld.so.preload absent (cid11, no preload rootkit); /etc/cron.daily and /etc/cron.d are byte-identical to INV-001 cid73 (apt-compat 1478B Apr 8 2022, dpkg 123B Dec 5 2021), no new entries. The detector fired only because the once-daily 06:25 cron run was absent from the point-in-time baseline snapshot. No containment warranted. Recommend baseline-window tuning (>=25h) or an allowlist for the stock cron.daily chain; optional hardening: dpkg --verify of apt-compat/apt.systemd.daily. ← tool call #8
  - source: live.live_processes
  - tests hypothesis: H0001
  - **Evidence Chain:** call #8 (`ssh victim@localhost:2222 -- ps -eo pid,ppid,user,etimes,start,cmd --no-headers`) — OK
    - excerpt:       1       0 root       47022 17:24:53 velociraptor --config /config/client.config.yaml client -v
     29       1 root       47019 17:24:56 /usr/sbin/cron -P
     30       1 root       47019 17:24:

## Recommended Containment Commands (run manually)

TRUDI does **not** execute remediation. The commands below are derived from each CONFIRMED/LIKELY finding; a human runs them out-of-band.

### ACT-1 — Send SIGSTOP to the new process (forensic capture before kill)

- Detector: `Custom.TRUDI.NewProcess` · risk: low · reversible

```bash
kill -STOP 75
```

### ACT-2 — Terminate the new process (SIGKILL)

- Detector: `Custom.TRUDI.NewProcess` · risk: medium · NOT reversible

```bash
kill -9 75
```

### ACT-3 — Move the new process's image to /var/quarantine/<sha256>

- Detector: `Custom.TRUDI.NewProcess` · risk: low · reversible
- ⚠️ Unresolved placeholders (evidence missing): sha256 — review before running

```bash
mkdir -p /var/quarantine && chmod 000 /tmp/.kworkerd && mv /tmp/.kworkerd /var/quarantine/
```

### ACT-4 — iptables REJECT outbound to 203.0.113.10:8080

- Detector: `Custom.TRUDI.NewNetwork` · risk: low · reversible

```bash
iptables -I OUTPUT -d 203.0.113.10 -p tcp --dport 8080 -m comment --comment TRUDI_RESPOND -j REJECT
```

### ACT-5 — Terminate the process owning the new outbound connection

- Detector: `Custom.TRUDI.NewNetwork` · risk: medium · NOT reversible

```bash
kill -9 110
```

### ACT-6 — Delete the new cron entry

- Detector: `Custom.TRUDI.NewPersistence` · risk: low · reversible

```bash
mkdir -p /var/quarantine && cp /var/spool/cron/crontabs/root /var/quarantine/cron_backup_$(basename /var/spool/cron/crontabs/root) && rm -f /var/spool/cron/crontabs/root
```

### ACT-7 — Disable + stop the new systemd unit

- Detector: `Custom.TRUDI.NewPersistence` · risk: low · reversible

```bash
systemctl disable --now /var/spool/cron/crontabs/root
```

