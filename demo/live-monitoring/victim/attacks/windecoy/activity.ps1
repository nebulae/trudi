<# Execute through the attacker's RDP session, under the honey account token.
   Synthetic documents only; all writes stay in this user's profile and HKCU.
   The transcript/result are attacker-controlled leads, not proof of actions. #>
[CmdletBinding()]
param([switch]$Cleanup, [string]$ExpectedAccount = 'linda', [string]$ReceiptPath = '')
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]$identity
if ($identity.Name.Split('\')[-1] -ine $ExpectedAccount -or
    $identity.Name.Split('\')[0] -ine $env:COMPUTERNAME -or
    $identity.User.Value -eq 'S-1-5-18' -or
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    @($identity.Groups | Where-Object { $_.Value -eq 'S-1-5-32-544' }).Count) {
  throw 'Run only as the local, non-administrator honey account in its RDP session.'
}
$root = Join-Path $env:LOCALAPPDATA 'NorthstarCache'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$runName = 'NorthstarWorkspace'
if ($Cleanup) {
  Remove-ItemProperty $runKey -Name $runName -ErrorAction SilentlyContinue
  Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
    Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -like "*$root\workspace.ps1*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
  if (Test-Path $root) { Remove-Item $root -Recurse -Force }
  if ($ReceiptPath) { @{cleaned=$true; account=$identity.Name} | ConvertTo-Json | Set-Content $ReceiptPath -Encoding UTF8 }
  Write-Output 'Removed this honey account''s demo Run value, process, and staging files.'
  exit 0
}
New-Item -ItemType Directory -Path $root -Force | Out-Null
Start-Transcript -Path (Join-Path $root 'activity.log') -Force | Out-Null
try {
  Write-Output "identity=$($identity.Name) sid=$($identity.User.Value) pid=$PID utc=$([DateTime]::UtcNow.ToString('o'))"
  whoami.exe /all
  hostname.exe
  ipconfig.exe /all
  Get-ChildItem 'C:\DecoyData\Finance'
  $stage = Join-Path $root 'staging'
  New-Item -ItemType Directory -Path $stage -Force | Out-Null
  foreach ($name in 'Forecast.csv','Board-Notes.txt') {
    $source = Join-Path 'C:\DecoyData\Finance' $name
    Get-Content $source
    Copy-Item $source $stage -Force
  }
  Compress-Archive -Path "$stage\*" -DestinationPath "$root\finance-review.zip" -Force
  # Probe an administrator-only synthetic canary, never real credentials.
  $denied = $false
  try { $null = Get-Content 'C:\ProgramData\TRUDI-Decoy\Administrator-Only.txt' -ErrorAction Stop }
  catch [System.UnauthorizedAccessException] { $denied = $true; Write-Output 'Protected canary: access denied.' }
  if (-not $denied) { throw 'The protected canary was readable; stop and fix the decoy ACLs.' }
  # Ordinary users can persist in their own logon context. This harmless worker
  # sleeps for 15 minutes; it has no network or privilege-escalation behavior.
  'Start-Sleep -Seconds 900' | Set-Content "$root\workspace.ps1" -Encoding UTF8
  $command = 'powershell.exe -NoProfile -WindowStyle Hidden -File "' + $root + '\workspace.ps1"'
  New-Item $runKey -Force | Out-Null
  New-ItemProperty $runKey -Name $runName -Value $command -PropertyType String -Force | Out-Null
  Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -File `"$root\workspace.ps1`"" -WindowStyle Hidden
  @{ account=$identity.Name; sid=$identity.User.Value; pid=$PID;
     completed_utc=[DateTime]::UtcNow.ToString('o'); archive="$root\finance-review.zip";
     run_value=$runName; protected_read='denied'; exfiltration='not attempted' } |
    ConvertTo-Json | Set-Content "$root\result.json" -Encoding UTF8
  if ($ReceiptPath) { Copy-Item "$root\result.json" $ReceiptPath -Force }
  Write-Output 'Discovery, synthetic-file staging, and current-user persistence completed.'
} finally { Stop-Transcript | Out-Null }
