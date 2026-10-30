<#
  sensor.ps1 — WINDECOY-DEMO on-decoy deception sensor.

  Stands in for an Acalvio ShadowPlex agent instrumenting a high-interaction
  Windows decoy. It is NOT Acalvio software: it watches the Windows Security
  log for a logon that PRESENTS A HONEY ACCOUNT (the breadcrumb credential,
  e.g. "linda"), and on each such logon emits the two CEF records the published
  ShadowPlex Incident Mapping Guide (release 2026.8.2.0) documents — the fused
  incident and the per-protocol service interaction — as syslog over UDP to the
  TRUDI CEF relay / ingest. The format matches monitoring/cef.py exactly, so
  bin/trudi-cef-ingest.py turns it into a Custom.TRUDI.DecoyTouch alert
  unchanged.

  Nothing legitimate ever logs in as the honey account, so every such logon is
  an incident — the same "no baseline, no false positives" premise a real
  deception platform relies on. The logon IS the honeytoken trip.

  Config: sensor.config.json beside this script (written by win-oem-init), or
  the matching environment variables. Runs as a boot scheduled task under
  SYSTEM (Security-log read requires it).
#>

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# ── Configuration ────────────────────────────────────────────────────────────
$cfg = @{
  honey_accounts = @('linda')
  decoy_name     = $env:COMPUTERNAME
  decoy_ip       = '10.73.0.60'
  syslog_host    = '10.73.0.55'   # the lan-net CEF relay
  syslog_port    = 5514
  site           = 'lab'
  cef_version    = '2026.8.2.0'
  callback_base  = 'https://233.252.0.91/#/incidents'
  poll_seconds   = 3
  sender         = 'windows-decoy'
  key_file       = (Join-Path $ScriptDir 'cef.key')
}
$cfgPath = Join-Path $ScriptDir 'sensor.config.json'
if (Test-Path $cfgPath) {
  try {
    $j = Get-Content -Raw $cfgPath | ConvertFrom-Json
    foreach ($k in $cfg.Keys.Clone()) { if ($null -ne $j.$k) { $cfg[$k] = $j.$k } }
  } catch { Write-Host "[sensor] config parse failed, using defaults: $_" }
}
# Normalise honey accounts to a lowercase set.
$honey = @{}
foreach ($a in @($cfg.honey_accounts)) { $honey[("$a").ToLower()] = $true }

$StateFile = Join-Path $ScriptDir 'sensor.state'

function Write-Log($m) { Write-Host "[sensor] $m" }

# ── CEF formatting (matches monitoring/cef.py:format_cef) ─────────────────────
function Esc-Ext([string]$v) {
  # Escape backslash and '=' the way cef.py _esc_ext does; CR/LF not expected.
  return ($v -replace '\\','\\' -replace '=','\=')
}
function Kv([string]$key, $val, [bool]$quoteWhenSpace = $true) {
  if ($null -eq $val) { return $null }
  $s = Esc-Ext ([string]$val)
  if ($quoteWhenSpace -and ($s -match ' ' -or $s -eq '')) {
    $s = '"' + ($s -replace '"','\"') + '"'
  }
  return "$key=$s"
}
function Join-Ext([object[]]$pairs) { return (($pairs | Where-Object { $_ }) -join ' ') }

function Protect-Cef([string]$msg) {
  if (-not (Test-Path $cfg.key_file)) { return $msg }
  $key = [System.Text.Encoding]::UTF8.GetBytes((Get-Content -Raw $cfg.key_file).Trim())
  if ($key.Length -lt 32) { throw 'CEF signing key must have at least 32 bytes' }
  $stamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $nonce = [guid]::NewGuid().ToString('N')
  $material = "TRUDI-CEF-1`n$($cfg.sender)`n$stamp`n$nonce`n$msg"
  $hmac = [System.Security.Cryptography.HMACSHA256]::new($key)
  try {
    $sig = ([BitConverter]::ToString($hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($material)))).Replace('-','').ToLowerInvariant()
  } finally { $hmac.Dispose() }
  return (@{trudi_cef=1; sender=$cfg.sender; timestamp=$stamp; nonce=$nonce; cef=$msg; signature=$sig} | ConvertTo-Json -Compress)
}

function Send-Syslog([string]$cefLine) {
  $pri = 114
  $ts  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fff') + 'Z'
  $msg = "<$pri>$ts $($cfg.site) $cefLine"
  try {
    $msg = Protect-Cef $msg
    $udp = New-Object System.Net.Sockets.UdpClient
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($msg)
    [void]$udp.Send($bytes, $bytes.Length, [string]$cfg.syslog_host, [int]$cfg.syslog_port)
    $udp.Close()
  } catch {
    Write-Log "syslog send to $($cfg.syslog_host):$($cfg.syslog_port) failed: $_"
  }
}

function SpTime([datetime]$dt) {
  return $dt.ToUniversalTime().ToString('MMMM dd yyyy HH:mm:ss.fff', [System.Globalization.CultureInfo]::InvariantCulture) + ' UTC'
}

function Emit-Incident($srcIp, $user, $wks, $started, $ended) {
  $incidentId = [guid]::NewGuid().ToString()
  $clientHost = $null
  if ($wks) { $clientHost = $wks }
  $header = "CEF:0|Acalvio|ShadowPlex|$($cfg.cef_version)|DETECT_AND_RESPOND|ENDPOINT_COMPROMISE|9"
  $fusedExt = Join-Ext @(
    (Kv 'cat' 'Endpoint Compromise'),
    (Kv 'cs2Label' 'incidentID' $false), (Kv 'cs2' $incidentId $false),
    (Kv 'start' (SpTime $started)), (Kv 'end' (SpTime $ended)),
    (Kv 'cs3Label' 'incidentStatus' $false), (Kv 'cs3' 'Active' $false),
    (Kv 'cs8Label' 'tacticName' $false), (Kv 'cs8' 'Lateral Movement,Discovery'),
    (Kv 'cs10Label' 'techniqueName' $false),
    (Kv 'cs10' 'Remote Services.Remote Desktop Protocol,Network Service Discovery'),
    (Kv 'cs15Label' 'srcIP' $false), (Kv 'cs15' $srcIp),
    (Kv 'cs25Label' 'dstIP' $false), (Kv 'cs25' $cfg.decoy_ip),
    (Kv 'cs26Label' 'dstEndpointName' $false), (Kv 'cs26' $cfg.decoy_name),
    (Kv 'cs35Label' 'dstPort' $false), (Kv 'cs35' '3389' $false),
    (Kv 'cs52Label' 'userIdAttempted' $false), (Kv 'cs52' $user),
    (Kv 'cs67Label' 'callbackURL' $false), (Kv 'cs67' "$($cfg.callback_base)?incidentID=$incidentId")
  )
  Send-Syslog "$header|$fusedExt"

  $eventData = [ordered]@{
    user_name = $user
    service_details = [ordered]@{
      host_mac            = $null
      remote_port         = $null
      service_name        = 'MS-WBT-SERVER'
      service_port        = 3389
      auth_attempted      = $true
      client_host_ip      = $srcIp
      remote_address      = $srcIp
      client_host_name    = $clientHost
      service_host_name   = $cfg.decoy_name
      service_host_address= $cfg.decoy_ip
    }
  }
  $json = ($eventData | ConvertTo-Json -Compress -Depth 5)
  $svcHeader = "CEF:0|Acalvio|ShadowPlex|$($cfg.cef_version)|DETECT_AND_RESPOND|SERVICE_INTERACTION|9"
  $svcExt = Join-Ext @(
    (Kv 'cs2Label' 'incidentID' $false), (Kv 'cs2' $incidentId $false),
    (Kv 'cs78Label' 'event_data' $false), (Kv 'cs78' $json $false)
  )
  Send-Syslog "$svcHeader|$svcExt"
  Write-Log "incident $incidentId emitted for $user from $srcIp → $($cfg.syslog_host):$($cfg.syslog_port)"
}

# ── Security-log watch loop ───────────────────────────────────────────────────
function Get-HighWater {
  if (Test-Path $StateFile) {
    try { return [int64](Get-Content -Raw $StateFile).Trim() } catch { }
  }
  # First run: start from the current newest Security record so we only react to
  # NEW logons after the sensor comes up (not historical ones on reboot).
  try {
    $latest = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 1 -ErrorAction Stop
    return [int64]$latest.RecordId
  } catch { return [int64]0 }
}
function Set-HighWater([int64]$rid) { Set-Content -Path $StateFile -Value $rid }

$hw = Get-HighWater
Write-Log "watching Security 4624/4625 for honey accounts [$([string]::Join(',', $honey.Keys))]; relay=$($cfg.syslog_host):$($cfg.syslog_port); highwater=$hw"

while ($true) {
  try {
    $events = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 200 -ErrorAction SilentlyContinue |
               Where-Object { $_.RecordId -gt $hw } | Sort-Object RecordId)
    foreach ($evt in $events) {
      $hw = [int64]$evt.RecordId
      try {
        $xml = [xml]$evt.ToXml()
        $d = @{}
        foreach ($node in $xml.Event.EventData.Data) { $d[$node.Name] = $node.'#text' }
        $user = $d['TargetUserName']; $ip = $d['IpAddress']
        $lt = $d['LogonType'];        $wks = $d['WorkstationName']
        if (-not $user) { continue }
        if (-not $honey.ContainsKey($user.ToLower())) { continue }
        if ($lt -notin @('3','10')) { continue }
        if (-not $ip -or $ip -in @('-','::1','127.0.0.1','0.0.0.0')) { continue }
        $when = $evt.TimeCreated
        Emit-Incident $ip $user $wks $when $when
      } catch { Write-Log "event parse error (RecordId $($evt.RecordId)): $_" }
    }
    if ($events.Count -gt 0) { Set-HighWater $hw }
  } catch { Write-Log "poll error: $_" }
  Start-Sleep -Seconds ([int]$cfg.poll_seconds)
}
