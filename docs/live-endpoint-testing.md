# Live endpoint testing with TRUDI

TRUDI's `live.*` namespace lets the agent investigate a running endpoint over
SSH, using the same audit/gate/attribution pipeline as static evidence. Every
`live.*` tool routes through `core.ssh.ssh_run` with a fixed-argv command —
no remote shell parsing, no agent-controlled command string.

This doc walks through setting up the simplest reproducible test bed: **a
second WSL2 distro as the endpoint**, with **Atomic Red Team** detonating
known ATT&CK techniques so the agent has unambiguous ground truth to find.

---

## 1. Stand up the endpoint (one-time, ~10 min)

From PowerShell on the WSL2 host:

```powershell
wsl --install -d Ubuntu-22.04
# (after the OS boots and you've created a user)
```

Inside the new distro:

```bash
sudo apt update && sudo apt install -y openssh-server lsof net-tools yara
sudo systemctl enable --now ssh

# Allow your TRUDI key in. Replace with your actual pubkey from the TRUDI side.
mkdir -p ~/.ssh && chmod 700 ~/.ssh
cat >> ~/.ssh/authorized_keys <<'EOF'
ssh-ed25519 AAAA... trudi-live
EOF
chmod 600 ~/.ssh/authorized_keys
```

Find the endpoint's address (usable from TRUDI side):

```bash
hostname -I    # note the first IPv4 — typically 172.x.x.x for WSL2
```

Smoke test from the TRUDI distro:

```bash
ssh -i ~/.ssh/trudi_live trudi@172.x.x.x 'hostname && uname -a'
```

If that prints output, the transport is good. Otherwise: check that
`Get-NetIPInterface | ? {$_.InterfaceAlias -like 'vEthernet (WSL*)'}`
shows the WSL bridge is up (Windows side).

---

## 2. Generate a TRUDI SSH key (one-time)

On the **TRUDI host** (not the endpoint):

```bash
ssh-keygen -t ed25519 -f ~/.ssh/trudi_live -N '' -C 'trudi-live'
# pubkey to paste into endpoint's ~/.ssh/authorized_keys:
cat ~/.ssh/trudi_live.pub
```

---

## 3. Register the endpoint with TRUDI

TRUDI looks up endpoint connection details in
`~/cases/.common/live_hosts.json`. The agent never sees the file — it only
sees host names — so connection details stay server-side.

```bash
mkdir -p ~/cases/.common
cat > ~/cases/.common/live_hosts.json <<'JSON'
{
  "ubuntu-endpoint": {
    "user": "trudi",
    "host": "172.x.x.x",
    "identity": "~/.ssh/trudi_live",
    "port": 22
  }
}
JSON
```

Verify TRUDI sees it:

```bash
python -c "from core.ssh import list_configured_hosts; print(list_configured_hosts())"
# → ['ubuntu-endpoint']
```

End-to-end smoke from a TRUDI Python prompt (no MCP server needed):

```python
from tools.live import live_processes
r = live_processes("ubuntu-endpoint")
print(r["success"], r["stdout"][:200])
```

---

## 4. Install Atomic Red Team on the endpoint (5 min)

Atomic Red Team gives you reproducible TTP detonations mapped 1:1 to MITRE
T-IDs — perfect ground truth for testing TRUDI's attribution + coverage
tools. https://atomicredteam.io/

On the endpoint:

```bash
sudo apt install -y curl
sudo mkdir -p /opt/atomic-red-team
sudo chown $USER /opt/atomic-red-team
git clone --depth=1 https://github.com/redcanaryco/atomic-red-team.git /opt/atomic-red-team

# Invoke Atomics use PowerShell on Windows; on Linux you run them as shell
# directly. Each atomic test lives under
# /opt/atomic-red-team/atomics/T<NNNN>/<testname>.yaml
```

---

## 5. Starter detonations

Pick a handful of techniques that exercise different live tools:

| T-ID | Atomic | What the endpoint state looks like after |
|------|--------|--------------------------------|
| **T1059.004** Bash | encode + decode base64 payload | recently-run bash with suspicious argv |
| **T1003.008** /etc/shadow | `sudo cat /etc/shadow > /tmp/.shadow_dump` | file in /tmp; recent root shell |
| **T1547.006** Kernel module | `sudo modprobe pcspkr` (benign module load) | `lsmod` shows new entry |
| **T1053.003** Cron persistence | `echo "* * * * * /bin/true" | crontab -` | user crontab entry |
| **T1071.001** Web-protocol C2 stand-in | `python3 -m http.server 8888 &` + curl loop | listening port + persistent connection |
| **T1057** Process discovery | `ps -ef && netstat -an && id` (signal-only) | shell history + recent process |

Run them by hand for the demo or wrap in a `detonate.sh` script:

```bash
#!/usr/bin/env bash
set -x
echo "dGVzdA==" | base64 -d > /tmp/payload                   # T1059.004
sudo cat /etc/shadow > /tmp/.shadow_dump 2>/dev/null         # T1003.008
sudo modprobe pcspkr                                         # T1547.006
(crontab -l 2>/dev/null; echo "* * * * * /bin/true") | crontab -  # T1053.003
python3 -m http.server 8888 &                                # T1071.001
sleep 2; curl -s http://localhost:8888/ > /dev/null
```

---

## 6. Run a TRUDI investigation against the live endpoint

From the TRUDI agent session:

```
misc.start_execution_log("LIVE-TEST-001", "./analysis/LIVE-TEST-001_trace.json")
# … then per the DAIR loop:
live.live_processes(host="ubuntu-endpoint")
live.live_network_connections(host="ubuntu-endpoint")
live.live_persistence_audit(host="ubuntu-endpoint")
# pass results into reason.plan → dair_assess → ...
```

The agent's findings should cite the exact T-IDs you detonated. After a few
findings land:

```
attribution.attribute_actors()
# → ranks MITRE groups by overlap with your detonated TTPs
coverage.coverage_report()
# → markdown checklist: found T1003.008, T1547.006, T1053.003, … gaps T1190, …
```

---

## 7. What to verify in the trace

After the run, open the chain view (`reports/chain_view.html`) and confirm:

1. **Live tool calls appear in the chain.** Each `live_*` call shows up as a
   `tool_batch` with `source: "ssh_runner"` in the trace JSON entries.
2. **Phase strip is populated.** `STATE 1 · Triage` exists from entry #1
   (Triage defaulting works for live data too).
3. **Findings link to live tool calls.** Each finding's `linked_call_id`
   points at the `_trudi_call_id` of the relevant `live_*` call.
4. **Attribution wires up.** The `attribute_actors` block has incoming
   `consumes` wires from the findings whose T-IDs informed it.
5. **No `mcp_routing` gate refusals.** Live tool calls have
   `source: "ssh_runner"` (not `claude_code_bash`), so the routing gate
   doesn't fire.

---

## 8. Security boundary cheat-sheet

| Layer | Guarantee | Enforcement |
|-------|-----------|-------------|
| Argv-only commands | No remote shell parsing of operands | `core.ssh.ssh_run` rejects `str` cmd_argv at the boundary |
| No mutation tools | Read-only by design | No write tools exist in `tools/live.py` |
| Pinned hosts | Agent can only address pre-configured endpoints | `~/cases/.common/live_hosts.json` lookup, agent passes host name only |
| Identity-only auth | No password prompts, BatchMode | `_SSH_OPTS` in `core/ssh.py` |
| Fixed fingerprint after first touch | Endpoint identity change → SSH fails | `StrictHostKeyChecking=accept-new` |
| Trace + audit | Every command logged with `_trudi_call_id` | `_log_ssh_tool` mirrors `_log_tool` from `core/executor.py` |

---

## 9. Tear-down

On the endpoint:

```bash
crontab -r                          # remove T1053.003 entry
rm -f /tmp/payload /tmp/.shadow_dump
pkill -f 'python3 -m http.server'
sudo rmmod pcspkr 2>/dev/null
```

On the TRUDI side:

```bash
# Just remove the host from live_hosts.json to deny further connections
rm ~/cases/.common/live_hosts.json
```

The endpoint distro can be removed entirely with `wsl --unregister Ubuntu-22.04`.
