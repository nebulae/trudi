<# Defender provisioning for the isolated Windows decoy; run as Administrator.
   The honey account gets a real desktop and synthetic read-only documents.
   It has no administrative membership or permission to modify the sensor.
   Apply before baselining. Re-running does not reset attacker activity. #>
[CmdletBinding()]
param(
  [string]$HoneyAccount = 'linda',
  [string]$TelemetryAddress = '10.73.0.2',
  [string]$RelayAddress = '10.73.0.55'
)
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Decoy provisioning requires an administrator.'
}
$user = Get-LocalUser -Name $HoneyAccount
$sid = $user.SID.Value
$allowedGroups = @('S-1-5-32-545', 'S-1-5-32-555') # Users, Remote Desktop Users
foreach ($group in Get-LocalGroup) {
  $member = @(Get-LocalGroupMember -Group $group | Where-Object { $_.SID.Value -eq $sid })
  if ($member.Count -and $group.SID.Value -notin $allowedGroups) {
    Remove-LocalGroupMember -Group $group -Member $user
  }
}
foreach ($groupSid in $allowedGroups) {
  $group = Get-LocalGroup -SID $groupSid
  if (-not @(Get-LocalGroupMember -Group $group | Where-Object { $_.SID.Value -eq $sid }).Count) {
    Add-LocalGroupMember -Group $group -Member $user
  }
}

$bait = 'C:\DecoyData\Finance'
$protected = 'C:\ProgramData\TRUDI-Decoy'
New-Item -ItemType Directory -Path $bait,$protected -Force | Out-Null
& icacls.exe $bait /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*${sid}:(OI)(CI)RX" | Out-Null
if ($LASTEXITCODE) { throw 'Bait ACL setup failed' }
& icacls.exe $protected /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE) { throw 'Protected directory ACL setup failed' }
@'
Project,Quarter,Budget
Northstar Lab,Q4,125000
Orchid Lab,Q4,84000
'@ | Set-Content "$bait\Forecast.csv" -Encoding UTF8
'Finance planning draft. Proposed allocations require internal review on Friday. Do not distribute the board draft outside Finance.' |
  Set-Content "$bait\Board-Notes.txt" -Encoding UTF8
'SYNTHETIC protected canary. Standard users must not be able to read this file.' |
  Set-Content "$protected\Administrator-Only.txt" -Encoding UTF8

# Native records, independent of any attacker-writable transcript.
& auditpol.exe /set '/subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable | Out-Null
if ($LASTEXITCODE) { throw 'Logon auditing failed' }
& auditpol.exe /set '/subcategory:{0CCE921C-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable | Out-Null
if ($LASTEXITCODE) { throw 'Session reconnect auditing failed' }
& auditpol.exe /set '/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null
if ($LASTEXITCODE) { throw 'Process creation auditing failed' }
& auditpol.exe /set '/subcategory:{0CCE921D-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable | Out-Null
if ($LASTEXITCODE) { throw 'File-system auditing failed' }
$audit = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-Item $audit -Force | Out-Null
New-ItemProperty $audit -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -PropertyType DWord -Force | Out-Null
$logging = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item $logging -Force | Out-Null
New-ItemProperty $logging -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force | Out-Null
foreach ($path in $bait,$protected) {
  $acl = Get-Acl $path -Audit
  $rule = New-Object Security.AccessControl.FileSystemAuditRule(
    [Security.Principal.SecurityIdentifier]$sid,
    [Security.AccessControl.FileSystemRights]'Read,Write',
    [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
    [Security.AccessControl.PropagationFlags]::None,
    [Security.AccessControl.AuditFlags]'Success,Failure')
  $acl.SetAuditRule($rule)
  Set-Acl $path $acl
}

# No general outbound connectivity from this high-interaction decoy. Keep only
# client telemetry, signed sensor delivery, and the guest's DHCP renewal.
if (-not (Test-Path "$protected\firewall-before.wfw")) {
  & netsh.exe advfirewall export "$protected\firewall-before.wfw" | Out-Null
  if ($LASTEXITCODE) { throw 'Firewall backup failed' }
}
$groupName = 'TRUDI Decoy Egress'
function Set-DecoyEgressRule([string]$name, [string]$displayName, [hashtable]$settings) {
  if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) {
    Set-NetFirewallRule -Name $name -Enabled True -Direction Outbound -Action Allow @settings | Out-Null
  } else {
    New-NetFirewallRule -Name $name -DisplayName $displayName -Group $groupName -Enabled True -Direction Outbound -Action Allow @settings | Out-Null
  }
}
$gateway = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop
Set-DecoyEgressRule 'TRUDI-Decoy-Telemetry' 'TRUDI Velociraptor telemetry' @{
  Program='C:\Program Files\Velociraptor\velociraptor.exe'; Protocol='TCP'; RemoteAddress=$TelemetryAddress; RemotePort=8000 }
Set-DecoyEgressRule 'TRUDI-Decoy-Relay' 'TRUDI signed sensor relay' @{
  Protocol='UDP'; RemoteAddress=$RelayAddress; RemotePort=5514 }
Set-DecoyEgressRule 'TRUDI-Decoy-DHCP' 'TRUDI guest DHCP' @{
  Protocol='UDP'; LocalPort=68; RemotePort=67; RemoteAddress=@($gateway,'255.255.255.255') }
# Create replacements before removing old generated names, preserving telemetry
# while reapplying a policy whose default outbound action is already Block.
Get-NetFirewallRule -Group $groupName -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -notin @('TRUDI-Decoy-Telemetry','TRUDI-Decoy-Relay','TRUDI-Decoy-DHCP') } |
  Remove-NetFirewallRule
Get-NetFirewallRule -Direction Outbound -Enabled True -Action Allow |
  Where-Object { $_.Group -ne $groupName } | Disable-NetFirewallRule
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultOutboundAction Block

$policyDocument = @{ honey_account=$HoneyAccount; honey_sid=$sid; computer=$env:COMPUTERNAME; bait_path=$bait;
   data_classification='Synthetic exercise fixtures; no real customer, employee or credential data';
   protected_canary="$protected\Administrator-Only.txt";
   allowed_groups=$allowedGroups; outbound='telemetry, relay, DHCP only';
   provisioned_utc=[DateTime]::UtcNow.ToString('o') } |
  ConvertTo-Json
[IO.File]::WriteAllText("$protected\policy.json", $policyDocument, [Text.UTF8Encoding]::new($false))
Write-Output "Provisioned local standard-user honeytoken $HoneyAccount ($sid)."
