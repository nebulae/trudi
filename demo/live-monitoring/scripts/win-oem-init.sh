#!/bin/bash
# win-oem-init — build the OEM payload the Windows victim installs on first boot.
#
# Runs once (restart: "no") after velo-server is healthy. It:
#   1. copies the shared Velociraptor client config and rewrites its server_urls
#      to the LAN address the NAT'd Windows guest can actually reach
#      (the docker DNS name "velo-server" does not resolve inside the VM);
#   2. downloads the Windows velociraptor.exe matching the Linux client;
#   3. writes install.bat (CRLF) which, on first logon, installs the client as
#      a service, enables RDP, and creates the RDP target account.
# All three land in the win-oem volume that victim-win mounts at /oem → C:\OEM.
#
# Idempotent: re-running overwrites the payload. Safe to re-run after a config
# regeneration (down -v) — it always reflects the current client config + CA.
set -euo pipefail

SRC_CONFIG=/config/client.config.yaml
OEM=/oem
WIN_CONFIG="${OEM}/client.config.yaml"
WIN_EXE="${OEM}/velociraptor.exe"
INSTALL_BAT="${OEM}/install.bat"

SERVER_URL="${VELO_SERVER_LAN_URL:?set VELO_SERVER_LAN_URL}"
EXE_URL="${VELOCIRAPTOR_WINDOWS_URL:?set VELOCIRAPTOR_WINDOWS_URL}"
RDP_USER="${WIN_RDP_USER:-rdpadmin}"
RDP_PASS="${WIN_RDP_PASS:-Sup3rS3cret!}"
# Honey account (WINDECOY-DEMO) — a planted breadcrumb credential, NOT an admin.
# Its USE over RDP is what the on-decoy ShadowPlex sensor reports as a touch.
HONEY_USER="${WIN_HONEY_USER:-linda}"
HONEY_PASS="${WIN_HONEY_PASS:-H0neyT0ken!}"
# On-decoy deception sensor config (WINDECOY-DEMO). The sensor emits ShadowPlex
# CEF to the lan-net relay, which forwards to the SIFT-host ingest.
SENSOR_SRC="${SENSOR_SRC:-/windecoy/sensor.ps1}"
SHADOWPLEX_RELAY_HOST="${SHADOWPLEX_RELAY_HOST:-10.73.0.55}"
SHADOWPLEX_RELAY_PORT="${SHADOWPLEX_RELAY_PORT:-5514}"
DECOY_IP="${DECOY_IP:-10.73.0.60}"
SENSOR_CEF_VERSION="${SENSOR_CEF_VERSION:-2026.8.2.0}"
SENSOR_CALLBACK_BASE="${SENSOR_CALLBACK_BASE:-https://233.252.0.91/#/incidents}"

echo "[win-oem-init] waiting for ${SRC_CONFIG} …"
for _ in $(seq 1 120); do [[ -f "${SRC_CONFIG}" ]] && break; sleep 1; done
[[ -f "${SRC_CONFIG}" ]] || { echo "[win-oem-init] client config never appeared" >&2; exit 1; }

mkdir -p "${OEM}"

# curl + ca-certs are not in debian-slim by default.
if ! command -v curl >/dev/null 2>&1; then
    echo "[win-oem-init] installing curl …"
    apt-get update -qq && apt-get install -y -qq --no-install-recommends curl ca-certificates
fi

# 1. Windows client config = the shared config with the server URL repointed at
#    the LAN IP. The cert is CA-pinned (use_self_signed_ssl), so dialing by IP
#    rather than the "velo-server" name still validates.
echo "[win-oem-init] writing ${WIN_CONFIG} (server_urls → ${SERVER_URL})"
sed -E "s#https://velo-server:8000/#${SERVER_URL}#g" "${SRC_CONFIG}" > "${WIN_CONFIG}"
if ! grep -qF "${SERVER_URL}" "${WIN_CONFIG}"; then
    echo "[win-oem-init] WARN: server_urls not rewritten — check the client config format" >&2
fi

# 2. Windows client binary.
echo "[win-oem-init] fetching velociraptor.exe …"
curl -fsSL -o "${WIN_EXE}" "${EXE_URL}"
echo "[win-oem-init] velociraptor.exe $(wc -c < "${WIN_EXE}") bytes"

# 2b. On-decoy ShadowPlex sensor payload (WINDECOY-DEMO). Copy the sensor script
#     and write its config (relay target + honey accounts) into the OEM volume.
#     Dormant unless a honey-account logon occurs AND the relay is running, so it
#     is harmless on a plain winrdp (WINRDP-DEMO) boot.
if [[ -f "${SENSOR_SRC}" ]]; then
    echo "[win-oem-init] staging ShadowPlex sensor (${SENSOR_SRC} → OEM)"
    cp "${SENSOR_SRC}" "${OEM}/sensor.ps1"
    if [[ -f /run/secrets/windecoy-cef-key ]]; then
        cp /run/secrets/windecoy-cef-key "${OEM}/cef.key"
    fi
    cat > "${OEM}/sensor.config.json" <<JSON
{
  "honey_accounts": ["${HONEY_USER}"],
  "decoy_ip": "${DECOY_IP}",
  "syslog_host": "${SHADOWPLEX_RELAY_HOST}",
  "syslog_port": ${SHADOWPLEX_RELAY_PORT},
  "site": "lab",
  "cef_version": "${SENSOR_CEF_VERSION}",
  "callback_base": "${SENSOR_CALLBACK_BASE}",
  "poll_seconds": 3
}
JSON
else
    echo "[win-oem-init] WARN: sensor script ${SENSOR_SRC} not found — decoy sensor will not be installed" >&2
fi

cp /windecoy/provision.ps1 "${OEM}/windecoy-provision.ps1"

# 3. install.bat — runs at the end of the unattended install. CRLF endings.
#    Installs the client service, enables RDP, creates the RDP target account
#    (local admin so the modelled attacker can stage follow-on activity), the
#    honey account (non-admin breadcrumb), and the on-decoy ShadowPlex sensor.
emit() { printf '%s\r\n' "$1" >> "${INSTALL_BAT}.tmp"; }
rm -f "${INSTALL_BAT}.tmp"
emit '@echo off'
emit 'setlocal'
emit 'set VELODIR=C:\Program Files\Velociraptor'
emit 'mkdir "%VELODIR%" 2>nul'
emit 'copy /y "%~dp0velociraptor.exe" "%VELODIR%\velociraptor.exe"'
emit 'copy /y "%~dp0client.config.yaml" "%VELODIR%\client.config.yaml"'
emit 'rem --- Velociraptor client as a service (connects when the network is up) ---'
emit '"%VELODIR%\velociraptor.exe" --config "%VELODIR%\client.config.yaml" service install'
emit 'rem --- Enable RDP + firewall ---'
emit 'reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'
emit 'netsh advfirewall firewall set rule group="remote desktop" new enable=Yes'
emit 'rem --- RDP target account (demo creds; keep in step with attacks/win-rdp.sh) ---'
emit "net user ${RDP_USER} \"${RDP_PASS}\" /add"
emit "wmic useraccount where \"name='${RDP_USER}'\" set PasswordExpires=false"
emit "net localgroup \"Remote Desktop Users\" ${RDP_USER} /add"
emit "net localgroup Administrators ${RDP_USER} /add"
emit 'rem --- Honey account (WINDECOY-DEMO): a planted breadcrumb, NOT an admin ---'
emit "net user ${HONEY_USER} \"${HONEY_PASS}\" /add"
emit "wmic useraccount where \"name='${HONEY_USER}'\" set PasswordExpires=false"
emit "net localgroup \"Remote Desktop Users\" ${HONEY_USER} /add"
emit 'rem --- Defender preparation: least-privilege bait account, synthetic data, auditing, egress allowlist ---'
emit "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"%~dp0windecoy-provision.ps1\" -HoneyAccount \"${HONEY_USER}\""
emit 'if errorlevel 1 exit /b 1'
emit 'rem --- On-decoy ShadowPlex sensor (WINDECOY-DEMO): boot task, run as SYSTEM ---'
emit 'if exist "%~dp0sensor.ps1" ('
emit '  mkdir "C:\ShadowPlexSensor" 2>nul'
emit '  copy /y "%~dp0sensor.ps1" "C:\ShadowPlexSensor\sensor.ps1"'
emit '  if exist "%~dp0sensor.config.json" copy /y "%~dp0sensor.config.json" "C:\ShadowPlexSensor\sensor.config.json"'
emit '  if exist "%~dp0cef.key" copy /y "%~dp0cef.key" "C:\ShadowPlexSensor\cef.key"'
emit '  icacls "C:\ShadowPlexSensor" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"'
emit '  icacls "%~dp0" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"'
emit '  schtasks /create /tn "ShadowPlexSensor" /ru SYSTEM /sc onstart /rl HIGHEST /f /tr "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\ShadowPlexSensor\sensor.ps1"'
emit '  schtasks /run /tn "ShadowPlexSensor"'
emit ')'
emit 'exit /b 0'
mv "${INSTALL_BAT}.tmp" "${INSTALL_BAT}"

echo "[win-oem-init] OEM payload ready:"
ls -la "${OEM}"
echo "[win-oem-init] done."
