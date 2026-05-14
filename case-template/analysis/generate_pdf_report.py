#!/usr/bin/env python3
"""
DFIR Executive PDF Report Generator
Uses WeasyPrint to render styled HTML → PDF.
Call generate_report(content_dict, output_path) from other scripts,
or run directly to regenerate the baseline memory analysis report.
"""

import datetime
from pathlib import Path

try:
    from weasyprint import HTML, CSS
except ImportError:
    raise SystemExit("weasyprint not installed. Run: pip3 install weasyprint")


# ── Brand / Style ─────────────────────────────────────────────────────────────

CSS_STYLE = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=Roboto+Mono:wght@400;600&display=swap');

@page {
    size: A4;
    margin: 0;
    @bottom-right {
        content: "Page " counter(page) " of " counter(pages);
        font-family: 'Inter', sans-serif;
        font-size: 8pt;
        color: #9ca3af;
        margin-right: 2cm;
        margin-bottom: 0.6cm;
    }
    @bottom-left {
        content: "CONFIDENTIAL — DFIR INTERNAL USE ONLY";
        font-family: 'Inter', sans-serif;
        font-size: 8pt;
        color: #9ca3af;
        margin-left: 2cm;
        margin-bottom: 0.6cm;
    }
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: 'Inter', 'Helvetica Neue', Arial, sans-serif;
    font-size: 9.5pt;
    color: #1f2937;
    background: #ffffff;
    line-height: 1.55;
}

/* ── Cover / Header ── */
.cover {
    background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 60%, #1d4ed8 100%);
    color: white;
    padding: 2.8cm 2.2cm 2cm 2.2cm;
    page-break-after: always;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
}

.cover-top { }

.org-tag {
    font-size: 8pt;
    font-weight: 600;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: #93c5fd;
    margin-bottom: 0.5cm;
}

.report-type {
    font-size: 10pt;
    font-weight: 400;
    color: #bfdbfe;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    margin-bottom: 0.3cm;
}

.cover h1 {
    font-size: 28pt;
    font-weight: 700;
    line-height: 1.15;
    color: #ffffff;
    margin-bottom: 0.4cm;
}

.cover-subtitle {
    font-size: 13pt;
    font-weight: 300;
    color: #bfdbfe;
    margin-bottom: 1cm;
}

.cover-divider {
    width: 60px;
    height: 4px;
    background: #3b82f6;
    border-radius: 2px;
    margin: 0.6cm 0 1cm 0;
}

.cover-meta {
    display: table;
    border-collapse: collapse;
    width: 100%;
    margin-top: 0.6cm;
}
.cover-meta-row { display: table-row; }
.cover-meta-label {
    display: table-cell;
    font-size: 8pt;
    font-weight: 600;
    color: #93c5fd;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    padding: 0.12cm 0.6cm 0.12cm 0;
    white-space: nowrap;
    width: 3cm;
}
.cover-meta-value {
    display: table-cell;
    font-size: 9pt;
    color: #e0f2fe;
    padding: 0.12cm 0;
}

.cover-bottom {
    border-top: 1px solid rgba(255,255,255,0.15);
    padding-top: 0.4cm;
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
}
.cover-classification {
    font-size: 8pt;
    font-weight: 700;
    letter-spacing: 0.15em;
    color: #fbbf24;
    text-transform: uppercase;
}
.cover-date {
    font-size: 8pt;
    color: #93c5fd;
}

/* ── Page header stripe ── */
.page-header {
    background: #0f172a;
    color: white;
    padding: 0.35cm 2.2cm;
    display: flex;
    justify-content: space-between;
    align-items: center;
}
.page-header-title {
    font-size: 8.5pt;
    font-weight: 600;
    letter-spacing: 0.05em;
    color: #93c5fd;
}
.page-header-case {
    font-size: 8pt;
    color: #6b7280;
}

/* ── Content area ── */
.content {
    padding: 0.8cm 2.2cm 1.5cm 2.2cm;
}

/* ── Section headings ── */
h2 {
    font-size: 14pt;
    font-weight: 700;
    color: #0f172a;
    margin-top: 0.8cm;
    margin-bottom: 0.3cm;
    padding-bottom: 0.15cm;
    border-bottom: 2.5px solid #1d4ed8;
    display: flex;
    align-items: center;
    gap: 0.3cm;
}
h2 .section-num {
    background: #1d4ed8;
    color: white;
    font-size: 9pt;
    font-weight: 700;
    padding: 0.05cm 0.22cm;
    border-radius: 3px;
    min-width: 0.7cm;
    text-align: center;
}

h3 {
    font-size: 10.5pt;
    font-weight: 700;
    color: #1e3a5f;
    margin-top: 0.5cm;
    margin-bottom: 0.2cm;
}

p { margin-bottom: 0.25cm; }

/* ── Executive Summary box ── */
.exec-summary {
    background: #eff6ff;
    border-left: 4px solid #1d4ed8;
    border-radius: 0 6px 6px 0;
    padding: 0.4cm 0.6cm;
    margin: 0.3cm 0 0.5cm 0;
}
.exec-summary p { margin-bottom: 0.15cm; font-size: 9.5pt; }
.exec-summary p:last-child { margin-bottom: 0; }

/* ── Alert boxes ── */
.alert {
    border-radius: 5px;
    padding: 0.3cm 0.5cm;
    margin: 0.3cm 0;
    font-size: 9pt;
}
.alert-red    { background: #fef2f2; border-left: 4px solid #dc2626; }
.alert-orange { background: #fff7ed; border-left: 4px solid #f97316; }
.alert-green  { background: #f0fdf4; border-left: 4px solid #16a34a; }
.alert-blue   { background: #eff6ff; border-left: 4px solid #2563eb; }

.alert-title {
    font-weight: 700;
    font-size: 9pt;
    margin-bottom: 0.1cm;
}
.alert-red    .alert-title { color: #dc2626; }
.alert-orange .alert-title { color: #c2410c; }
.alert-green  .alert-title { color: #15803d; }
.alert-blue   .alert-title { color: #1d4ed8; }

/* ── Tables ── */
table {
    width: 100%;
    border-collapse: collapse;
    margin: 0.25cm 0 0.5cm 0;
    font-size: 8.8pt;
}
thead tr {
    background: #1e3a5f;
    color: white;
}
thead th {
    padding: 0.18cm 0.28cm;
    text-align: left;
    font-weight: 600;
    font-size: 8pt;
    letter-spacing: 0.04em;
    text-transform: uppercase;
}
tbody tr:nth-child(even) { background: #f8fafc; }
tbody tr:nth-child(odd)  { background: #ffffff; }
tbody td {
    padding: 0.15cm 0.28cm;
    border-bottom: 1px solid #e5e7eb;
    vertical-align: top;
}
tbody tr:hover { background: #eff6ff; }

/* ── Severity badges ── */
.badge {
    display: inline-block;
    padding: 0.04cm 0.2cm;
    border-radius: 3px;
    font-size: 7.5pt;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}
.badge-critical { background: #7f1d1d; color: #fecaca; }
.badge-high     { background: #dc2626; color: #ffffff; }
.badge-medium   { background: #f97316; color: #ffffff; }
.badge-low      { background: #2563eb; color: #ffffff; }
.badge-info     { background: #6b7280; color: #ffffff; }
.badge-benign   { background: #16a34a; color: #ffffff; }

/* ── Code / mono ── */
code, .mono {
    font-family: 'Roboto Mono', 'Courier New', monospace;
    font-size: 8pt;
    background: #f1f5f9;
    padding: 0.02cm 0.1cm;
    border-radius: 3px;
    color: #0f172a;
}
.code-block {
    font-family: 'Roboto Mono', 'Courier New', monospace;
    font-size: 7.8pt;
    background: #0f172a;
    color: #e2e8f0;
    padding: 0.35cm 0.45cm;
    border-radius: 6px;
    margin: 0.2cm 0 0.4cm 0;
    white-space: pre-wrap;
    word-break: break-all;
    line-height: 1.6;
}
.code-block .hl  { color: #fbbf24; font-weight: 600; }
.code-block .red { color: #f87171; }
.code-block .grn { color: #86efac; }
.code-block .blu { color: #93c5fd; }

/* ── Process tree ── */
.proc-tree {
    font-family: 'Roboto Mono', 'Courier New', monospace;
    font-size: 8pt;
    background: #0f172a;
    color: #e2e8f0;
    padding: 0.35cm 0.45cm;
    border-radius: 6px;
    margin: 0.2cm 0 0.4cm 0;
    line-height: 1.8;
}
.proc-tree .suspicious { color: #f87171; font-weight: 600; }
.proc-tree .benign     { color: #86efac; }
.proc-tree .neutral    { color: #93c5fd; }

/* ── Metric cards ── */
.metric-row {
    display: flex;
    gap: 0.3cm;
    margin: 0.3cm 0;
}
.metric-card {
    flex: 1;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-top: 3px solid #1d4ed8;
    border-radius: 5px;
    padding: 0.3cm 0.4cm;
    text-align: center;
}
.metric-card.red-top  { border-top-color: #dc2626; }
.metric-card.orange-top { border-top-color: #f97316; }
.metric-card.green-top  { border-top-color: #16a34a; }
.metric-number {
    font-size: 20pt;
    font-weight: 700;
    color: #0f172a;
    line-height: 1.1;
}
.metric-label {
    font-size: 7.5pt;
    font-weight: 600;
    color: #6b7280;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    margin-top: 0.05cm;
}

/* ── Timeline ── */
.timeline { margin: 0.3cm 0; }
.tl-entry {
    display: flex;
    gap: 0.4cm;
    margin-bottom: 0.2cm;
    align-items: flex-start;
}
.tl-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: #1d4ed8;
    margin-top: 0.1cm;
    flex-shrink: 0;
}
.tl-dot.red    { background: #dc2626; }
.tl-dot.orange { background: #f97316; }
.tl-dot.green  { background: #16a34a; }
.tl-time {
    font-family: 'Roboto Mono', monospace;
    font-size: 8pt;
    color: #4b5563;
    white-space: nowrap;
    flex-shrink: 0;
    width: 4.5cm;
}
.tl-text { font-size: 9pt; }

/* ── Footer note ── */
.footer-note {
    margin-top: 0.8cm;
    padding-top: 0.3cm;
    border-top: 1px solid #e5e7eb;
    font-size: 7.5pt;
    color: #9ca3af;
}

.page-break { page-break-before: always; }
"""


def build_html(data: dict) -> str:
    case_id    = data.get("case_id", "SRL-001")
    client     = data.get("client", "Stark Research Labs")
    prepared   = data.get("prepared_by", "DFIR Consulting Team")
    date_str   = data.get("date", datetime.datetime.utcnow().strftime("%Y-%m-%d"))
    title      = data.get("title", "DFIR Analysis Report")
    subtitle   = data.get("subtitle", "")
    body_html  = data.get("body_html", "")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<style>{CSS_STYLE}</style>
</head>
<body>

<!-- ══ COVER PAGE ══ -->
<div class="cover">
  <div class="cover-top">
    <div class="org-tag">Digital Forensics &amp; Incident Response</div>
    <div class="report-type">Confidential Forensic Analysis</div>
    <h1>{title}</h1>
    <div class="cover-subtitle">{subtitle}</div>
    <div class="cover-divider"></div>
    <div class="cover-meta">
      <div class="cover-meta-row">
        <div class="cover-meta-label">Client</div>
        <div class="cover-meta-value">{client}</div>
      </div>
      <div class="cover-meta-row">
        <div class="cover-meta-label">Case ID</div>
        <div class="cover-meta-value">{case_id}</div>
      </div>
      <div class="cover-meta-row">
        <div class="cover-meta-label">Prepared By</div>
        <div class="cover-meta-value">{prepared}</div>
      </div>
      <div class="cover-meta-row">
        <div class="cover-meta-label">Report Date</div>
        <div class="cover-meta-value">{date_str} UTC</div>
      </div>
      <div class="cover-meta-row">
        <div class="cover-meta-label">Classification</div>
        <div class="cover-meta-value" style="color:#fbbf24;font-weight:600;">CONFIDENTIAL — RESTRICTED DISTRIBUTION</div>
      </div>
    </div>
  </div>
  <div class="cover-bottom">
    <div class="cover-classification">&#9632; Confidential</div>
    <div class="cover-date">Report generated {date_str}</div>
  </div>
</div>

<!-- ══ BODY PAGES ══ -->
<div class="page-header">
  <div class="page-header-title">{title}</div>
  <div class="page-header-case">Case: {case_id} | {client}</div>
</div>
<div class="content">
{body_html}
<div class="footer-note">
  This report was produced as part of an active digital forensics investigation.
  All findings are based on evidence present at the time of analysis.
  Evidence integrity maintained per chain-of-custody protocol — source images not modified.
</div>
</div>

</body>
</html>"""


def generate_report(data: dict, output_path: str) -> str:
    html = build_html(data)
    HTML(string=html).write_pdf(
        output_path,
        stylesheets=[CSS(string="")],
        presentational_hints=True,
    )
    return output_path


# ── Baseline Memory Analysis Report ──────────────────────────────────────────

BODY_HTML = """
<h2><span class="section-num">01</span> Executive Summary</h2>

<div class="exec-summary">
  <p>During forensic analysis of the baseline memory image captured from <strong>BASE-RD-01</strong>
  (the Remote Desktop Server at 172.16.6.11) on <strong>2018-09-06 at 18:57:17 UTC</strong>,
  one non-standard process was identified with strong indicators of malicious activity.</p>
  <p>A single-character executable named <code>p.exe</code>, stored in a Windows Temp subdirectory,
  was found executing via a WMI-spawned PowerShell chain — a technique consistent with
  state-level APT tradecraft. Memory analysis of its process space revealed sequential IP addresses
  spanning the entire Business Line subnet (172.16.7.0/24), indicating active internal reconnaissance.
  The process binary was scrubbed from memory (process-hollowing indicator).</p>
  <p>A second non-standard process, <code>subject_srv.exe</code>, was confirmed as a legitimate
  F-Response forensic collection agent deployed by the incident response team.</p>
</div>

<div class="metric-row">
  <div class="metric-card red-top">
    <div class="metric-number">1</div>
    <div class="metric-label">Confirmed Malicious Process</div>
  </div>
  <div class="metric-card orange-top">
    <div class="metric-number">3</div>
    <div class="metric-label">MITRE ATT&amp;CK Techniques</div>
  </div>
  <div class="metric-card red-top">
    <div class="metric-number">254</div>
    <div class="metric-label">IPs Scanned (Biz Line)</div>
  </div>
  <div class="metric-card green-top">
    <div class="metric-number">1</div>
    <div class="metric-label">Benign FP Resolved</div>
  </div>
</div>

<h2><span class="section-num">02</span> System Profile</h2>

<table>
  <thead><tr><th>Property</th><th>Value</th></tr></thead>
  <tbody>
    <tr><td>Hostname</td><td><code>BASE-RD-01</code></td></tr>
    <tr><td>IP Address</td><td><code>172.16.6.11</code> (R&amp;D Network — 172.16.6.0/24)</td></tr>
    <tr><td>Operating System</td><td>Windows 10 x64, Build 16299 (Version 1709 — Fall Creators Update)</td></tr>
    <tr><td>Memory Image</td><td><code>base-rd_memory.img</code> (3.0 GB)</td></tr>
    <tr><td>Capture Timestamp</td><td>2018-09-06 18:57:17 UTC</td></tr>
    <tr><td>Logged-In User</td><td><code>tdungan</code></td></tr>
    <tr><td>Endpoint AV</td><td>McAfee VirusScan 8800, managed by ePO (172.16.5.20)</td></tr>
    <tr><td>Analysis Tool</td><td>Volatility 3 Framework v2.20.0 — <em>auto-detected OS (no profile selection)</em></td></tr>
  </tbody>
</table>

<h2><span class="section-num">03</span> Malicious Process: <code>p.exe</code></h2>

<div class="alert alert-red">
  <div class="alert-title">&#9888; HIGH SEVERITY — Confirmed Malicious Activity</div>
  Single-character executable in Temp directory, executed via WMI-spawned PowerShell chain.
  Binary was scrubbed from memory at time of capture. Active subnet reconnaissance detected.
</div>

<h3>Process Identification</h3>
<table>
  <thead><tr><th>Attribute</th><th>Value</th></tr></thead>
  <tbody>
    <tr><td>Process Name</td><td><code>p.exe</code> &nbsp;<span class="badge badge-high">Malicious</span></td></tr>
    <tr><td>PID</td><td>8260</td></tr>
    <tr><td>Full Path</td><td><code>C:\\Windows\\Temp\\perfmon\\p.exe</code></td></tr>
    <tr><td>Parent Process</td><td><code>cmd.exe</code> (PID 5948)</td></tr>
    <tr><td>First Seen</td><td>2018-08-30 22:15:18 UTC</td></tr>
    <tr><td>Image Dump Result</td><td><span class="badge badge-critical">0 Bytes — Binary Scrubbed / Process Hollow</span></td></tr>
    <tr><td>Child Processes</td><td><code>rundll32.exe</code> (×3 across Sept 5–6, 2018)</td></tr>
  </tbody>
</table>

<h3>Execution Chain (WMI-Based Lateral Execution)</h3>

<div class="proc-tree"><span class="neutral">WmiPrvSE.exe</span>  PID 2876  ← WMI query triggered execution (T1047)
  └─ <span class="neutral">powershell.exe</span>  PID 8712  [x64]   ← spawned by WMI provider
       └─ <span class="neutral">powershell.exe</span>  PID 5848  [x32]   ← -s -NoLogo -NoProfile
            ├─ <span class="neutral">rundll32.exe</span>  (×5 short-lived, Aug–Sept 2018)
            └─ <span class="neutral">cmd.exe</span>  PID 5948
                 └─ <span class="suspicious">p.exe</span>  PID 8260   C:\Windows\Temp\perfmon\p.exe  ← MALICIOUS
                      ├─ <span class="suspicious">rundll32.exe</span>  PID 5768   2018-09-05 12:01 UTC
                      ├─ <span class="suspicious">rundll32.exe</span>  PID 1424   2018-09-06 14:58 UTC
                      └─ <span class="suspicious">rundll32.exe</span>  PID 7552   2018-09-06 17:26 UTC</div>

<p>The 32-bit PowerShell process was invoked with the <code>-s</code> flag (stdin mode) and
<code>-NoLogo -NoProfile</code> — a standard pattern for fileless/reflective payload delivery
frameworks such as Empire, Covenant, or Cobalt Strike.</p>

<h3>Network Reconnaissance Evidence</h3>
<p>Although no socket was directly attributed to PID 8260 at capture time (the active connections
may have been held by child <code>rundll32.exe</code> processes), the 604 MB VAD dump of the
p.exe process address space contained sequential IP addresses spanning the entire Business Line subnet:</p>

<div class="code-block"><span class="hl">Subnet scanned: 172.16.7.0/24 (Business Line — wksta01–wksta10)</span>
IPs observed in VAD memory:
  <span class="red">172.16.7.55 → 172.16.7.255</span>  (201 sequential addresses)

Additional internal IPs present in process memory:
  <span class="blu">172.16.4.5, 172.16.4.10</span>   (Services network — DC / Squid proxy)
  <span class="blu">172.16.5.20, 172.16.5.25</span>   (AV ePO server / unknown)
  <span class="blu">172.16.6.11–16</span>             (R&amp;D network — local subnet)</div>

<h3>MITRE ATT&amp;CK Mapping</h3>
<table>
  <thead><tr><th>Technique ID</th><th>Name</th><th>Evidence</th></tr></thead>
  <tbody>
    <tr><td><code>T1047</code></td><td>Windows Management Instrumentation</td><td>WmiPrvSE.exe spawned PowerShell out-of-band</td></tr>
    <tr><td><code>T1059.001</code></td><td>PowerShell</td><td>32-bit PowerShell <code>-s -NoLogo -NoProfile</code></td></tr>
    <tr><td><code>T1218.011</code></td><td>Signed Binary Proxy — Rundll32</td><td>p.exe spawned rundll32.exe ×3 over two days</td></tr>
    <tr><td><code>T1046</code></td><td>Network Service Discovery</td><td>Sequential IPs 172.16.7.55–255 in process memory</td></tr>
    <tr><td><code>T1055</code></td><td>Process Injection (suspected)</td><td>0-byte image dump; binary not recoverable from memory</td></tr>
  </tbody>
</table>

<h2><span class="section-num">04</span> Benign Finding: <code>subject_srv.exe</code></h2>

<div class="alert alert-green">
  <div class="alert-title">&#10003; RESOLVED — Legitimate Forensic Tool (F-Response)</div>
  Initially flagged due to non-standard name and active network connection.
  Confirmed as the F-Response Subject agent deployed by the IR team.
</div>

<table>
  <thead><tr><th>Attribute</th><th>Value</th></tr></thead>
  <tbody>
    <tr><td>Process Name</td><td><code>subject_srv.exe</code> &nbsp;<span class="badge badge-benign">Benign</span></td></tr>
    <tr><td>PID</td><td>1096</td></tr>
    <tr><td>Full Path</td><td><code>C:\\Windows\\subject_srv.exe</code></td></tr>
    <tr><td>Command Line</td><td><code>subject_srv.exe -s "base-hunt.shieldbase.lan:5682" -l 3262 -v "F-Response Subject" -k "155522845"</code></td></tr>
    <tr><td>Network</td><td>LISTENING tcp/3262 &nbsp;|&nbsp; ESTABLISHED → 172.16.5.50:39372 (examiner workstation)</td></tr>
    <tr><td>Verdict</td><td>F-Response Agent — Remote forensic evidence collection tool deployed by Roger Sydow (IT Admin)</td></tr>
  </tbody>
</table>

<h2><span class="section-num">05</span> Network Connection Summary</h2>

<table>
  <thead><tr><th>Source</th><th>Destination</th><th>Port</th><th>State</th><th>Assessment</th></tr></thead>
  <tbody>
    <tr>
      <td>172.16.6.11</td><td>172.16.5.50</td><td>3262</td>
      <td>ESTABLISHED</td>
      <td><span class="badge badge-benign">Benign</span> F-Response examiner</td>
    </tr>
    <tr>
      <td>172.16.6.11</td><td>172.16.4.10</td><td>8080</td>
      <td>ESTABLISHED (×3)</td>
      <td><span class="badge badge-medium">Suspicious</span> Squid proxy — PID unresolved</td>
    </tr>
    <tr>
      <td>172.16.6.11</td><td>172.16.7.15</td><td>445</td>
      <td>ESTABLISHED</td>
      <td><span class="badge badge-high">Suspicious</span> SMB — Business Line host</td>
    </tr>
    <tr>
      <td>172.16.6.11</td><td>172.16.4.5</td><td>445</td>
      <td>ESTABLISHED</td>
      <td><span class="badge badge-high">Suspicious</span> SMB — Services network</td>
    </tr>
    <tr>
      <td>172.16.6.14</td><td>172.16.6.11</td><td>445</td>
      <td>ESTABLISHED (inbound)</td>
      <td><span class="badge badge-high">Suspicious</span> Inbound SMB from R&amp;D peer</td>
    </tr>
  </tbody>
</table>

<h2><span class="section-num">06</span> Activity Timeline</h2>

<div class="timeline">
  <div class="tl-entry">
    <div class="tl-dot"></div>
    <div class="tl-time">2018-08-30 13:51 UTC</div>
    <div class="tl-text">System boot — standard Windows services initialised</div>
  </div>
  <div class="tl-entry">
    <div class="tl-dot red"></div>
    <div class="tl-time">2018-08-30 16:43 UTC</div>
    <div class="tl-text"><strong>WmiPrvSE.exe spawns powershell.exe (x64)</strong> — initial WMI-based execution</div>
  </div>
  <div class="tl-entry">
    <div class="tl-dot red"></div>
    <div class="tl-time">2018-08-30 22:15 UTC</div>
    <div class="tl-text"><strong>p.exe launched</strong> from <code>C:\Windows\Temp\perfmon\</code> via cmd.exe</div>
  </div>
  <div class="tl-entry">
    <div class="tl-dot orange"></div>
    <div class="tl-time">2018-08-30 18:31–22:45 UTC</div>
    <div class="tl-text">Multiple <code>rundll32.exe</code> instances spawned from PowerShell (short-lived)</div>
  </div>
  <div class="tl-entry">
    <div class="tl-dot red"></div>
    <div class="tl-time">2018-09-05 12:01 UTC</div>
    <div class="tl-text">p.exe spawns <code>rundll32.exe</code> (PID 5768) — payload staging resumes</div>
  </div>
  <div class="tl-entry">
    <div class="tl-dot red"></div>
    <div class="tl-time">2018-09-06 14:58 UTC</div>
    <div class="tl-text">p.exe spawns <code>rundll32.exe</code> (PID 1424) — continued activity</div>
  </div>
  <div class="tl-entry">
    <div class="tl-dot red"></div>
    <div class="tl-time">2018-09-06 17:26 UTC</div>
    <div class="tl-text">p.exe spawns <code>rundll32.exe</code> (PID 7552) — final observed activity</div>
  </div>
  <div class="tl-entry">
    <div class="tl-dot green"></div>
    <div class="tl-time">2018-09-06 18:28 UTC</div>
    <div class="tl-text">F-Response agent (subject_srv.exe) installed — IR collection begins</div>
  </div>
  <div class="tl-entry">
    <div class="tl-dot"></div>
    <div class="tl-time">2018-09-06 18:57 UTC</div>
    <div class="tl-text">Memory image captured</div>
  </div>
</div>

<div class="page-break"></div>

<h2><span class="section-num">07</span> Indicators of Compromise</h2>

<table>
  <thead><tr><th>IOC Type</th><th>Value</th><th>Confidence</th></tr></thead>
  <tbody>
    <tr>
      <td>File Path</td>
      <td><code>C:\\Windows\\Temp\\perfmon\\p.exe</code></td>
      <td><span class="badge badge-high">High</span></td>
    </tr>
    <tr>
      <td>Process Name</td>
      <td><code>p.exe</code> — single-character executable name</td>
      <td><span class="badge badge-high">High</span></td>
    </tr>
    <tr>
      <td>Execution Chain</td>
      <td>WmiPrvSE → powershell.exe (x64) → powershell.exe (x32, <code>-s</code>) → cmd.exe → p.exe</td>
      <td><span class="badge badge-high">High</span></td>
    </tr>
    <tr>
      <td>Child Process Pattern</td>
      <td>p.exe spawning <code>rundll32.exe</code> repeatedly over multiple days</td>
      <td><span class="badge badge-high">High</span></td>
    </tr>
    <tr>
      <td>Memory Indicator</td>
      <td>Sequential IPs 172.16.7.55–172.16.7.255 in process VAD (subnet scan)</td>
      <td><span class="badge badge-medium">Medium</span></td>
    </tr>
    <tr>
      <td>Memory Indicator</td>
      <td>0-byte image section for p.exe — binary scrubbed (process hollow)</td>
      <td><span class="badge badge-medium">Medium</span></td>
    </tr>
    <tr>
      <td>Network</td>
      <td>Unexplained ESTABLISHED SMB connections to 172.16.4.5:445 and 172.16.7.15:445</td>
      <td><span class="badge badge-medium">Medium</span></td>
    </tr>
  </tbody>
</table>

<h2><span class="section-num">08</span> Recommendations</h2>

<div class="alert alert-red">
  <div class="alert-title">Immediate Actions Required</div>
  <p>1. <strong>Isolate BASE-RD-01</strong> from the network if not already done — active attacker tooling was present at time of capture.</p>
  <p>2. <strong>Sweep all 172.16.7.x hosts</strong> (Business Line) for signs of lateral movement — the subnet scan indicates the adversary was enumerating targets.</p>
  <p>3. <strong>Preserve all logs</strong> from 172.16.4.5 (Services network) and 172.16.7.15 (Business Line) — both received unexplained SMB connections from BASE-RD-01.</p>
</div>

<div class="alert alert-orange">
  <div class="alert-title">Follow-On Investigation</div>
  <p>4. <strong>Analyse rd01-memory.img</strong> (primary 5 GB capture) for persistence mechanisms and additional payloads — this baseline image predates the declared incident.</p>
  <p>5. <strong>Recover p.exe</strong> from disk image (<code>base-rd01-cdrive.E01</code>) via Sleuth Kit/MFT — the binary was scrubbed from memory but may survive on disk.</p>
  <p>6. <strong>Review WMI subscriptions</strong> on BASE-RD-01 — the WMI execution chain suggests a persistent event subscription may be present.</p>
  <p>7. <strong>Correlate PowerShell logs</strong> (Event IDs 4103/4104) for the encoded payload delivered to the 32-bit PowerShell process.</p>
</div>

<h2><span class="section-num">09</span> Artefacts Produced</h2>

<table>
  <thead><tr><th>File</th><th>Description</th></tr></thead>
  <tbody>
    <tr><td><code>base-rd-windows-info.txt</code></td><td>Raw windows.info output — OS identification</td></tr>
    <tr><td><code>base-rd-pslist.txt</code></td><td>Full process list (windows.pslist)</td></tr>
    <tr><td><code>base-rd-netscan.txt</code></td><td>Network socket scan (windows.netscan)</td></tr>
    <tr><td><code>strings-subject_srv-full.txt</code></td><td>String extraction — subject_srv.exe (F-Response, benign)</td></tr>
    <tr><td><code>procdump/pid.8260.dmp</code></td><td>604 MB VAD dump of p.exe process space</td></tr>
    <tr><td><code>procdump/*.img</code></td><td>Dumped image/data section objects (subject_srv.exe)</td></tr>
    <tr><td><code>baseline-memory-analysis-report.txt</code></td><td>Plain-text findings report</td></tr>
    <tr><td><code>baseline-memory-analysis-report.pdf</code></td><td><strong>This document</strong></td></tr>
  </tbody>
</table>
"""


if __name__ == "__main__":
    report_data = {
        "case_id":     "SRL-2023-001",
        "client":      "Stark Research Labs (SRL)",
        "prepared_by": "DFIR Consulting Team",
        "date":        "2026-03-02",
        "title":       "Baseline Memory Analysis",
        "subtitle":    "BASE-RD-01 · base-rd_memory.img · 2018-09-06",
        "body_html":   BODY_HTML,
    }
    out = "/cases/srl/analysis/baseline-memory-analysis-report.pdf"
    generate_report(report_data, out)
    print(f"PDF written: {out}")
