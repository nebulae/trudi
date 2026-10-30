#!/bin/bash
# Real RDP interaction as the non-admin honey account. The local X11 automation
# types into its desktop; no SYSTEM task or investigator agent stages the attack.
set -euo pipefail
SELF="$(readlink -f "$0")"
TARGET="${WIN_TARGET:-10.73.0.60}"
HONEY="${WIN_HONEY_USER:-linda}"
PASSWORD="${WIN_HONEY_PASS:-H0neyT0ken!}"
STATE="${WINDECOY_STATE_DIR:-/tmp/trudi-win-decoy-${UID}}"
ACTION="${1:-run}"
[[ "$HONEY" =~ ^[A-Za-z][A-Za-z0-9_-]{0,19}$ ]] || { echo 'Invalid local honey account' >&2; exit 2; }
umask 077
mkdir -p "$STATE"

owned_session() {
    [[ -f "$STATE/pid" ]] || return 1
    local pid args
    read -r pid < "$STATE/pid"
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    args="$(ps -p "$pid" -o args= 2>/dev/null || true)"
    [[ "$args" == *"$SELF --session"* ]] && kill -0 "$pid" 2>/dev/null
}

if [[ "$ACTION" == '--cleanup' ]]; then
    if owned_session; then
        read -r pid < "$STATE/pid"
        kill -TERM -- "-$pid" 2>/dev/null || true
    fi
    rm -f "$STATE/pid"
    echo '[win-decoy] RDP channel closed. Windows staging and HKCU persistence remain evidence.'
    exit 0
fi

if [[ "$ACTION" == '--session' ]]; then
    drive="$2"
    mode="$3"
    xfreerdp /v:"$TARGET" /u:"$HONEY" /p:"$PASSWORD" \
        /cert:ignore /sec:nla /w:1024 /h:768 /t:TRUDI-WINDECOY \
        /drive:stage,"$drive" -clipboard >"$drive/rdp.log" 2>&1 &
    rdp=$!
    window=''
    for _ in {1..45}; do
        kill -0 "$rdp" 2>/dev/null || exit 1
        window="$(xdotool search --onlyvisible --pid "$rdp" --name TRUDI-WINDECOY 2>/dev/null | head -n 1 || true)"
        [[ -n "$window" ]] && break
        sleep 1
    done
    [[ -n "$window" ]] || exit 1
    # Window creation precedes desktop readiness / profile loading.
    sleep "${WINDECOY_DESKTOP_WAIT:-10}"
    command="powershell.exe -NoProfile -ExecutionPolicy Bypass -File \\\\tsclient\\stage\\activity.ps1 -ExpectedAccount $HONEY -ReceiptPath \\\\tsclient\\stage\\receipt.json"
    [[ "$mode" == reset ]] && command+=' -Cleanup'
    xdotool windowfocus --sync "$window"
    xdotool key --clearmodifiers super+r
    sleep 1
    xdotool type --clearmodifiers --delay 1 "$command"
    xdotool key Return
    wait "$rdp"
    exit $?
fi

case "$ACTION" in
    run|--reset-activity) ;;
    *) echo "usage: $0 [--cleanup|--reset-activity]" >&2; exit 2 ;;
esac
for tool in xfreerdp xvfb-run xdotool setsid; do
    command -v "$tool" >/dev/null || { echo "Missing $tool; rebuild the victim image." >&2; exit 1; }
done
owned_session && { echo 'A demo RDP session is active; close it with --cleanup first.' >&2; exit 1; }
drive="$(mktemp -d "$STATE/drive.XXXXXX")"
cp "$(dirname "$SELF")/windecoy/activity.ps1" "$drive/activity.ps1"
mode=run
[[ "$ACTION" == '--reset-activity' ]] && mode=reset
setsid xvfb-run -a bash "$SELF" --session "$drive" "$mode" >"$drive/session.log" 2>&1 &
echo "$!" > "$STATE/pid"
echo "[win-decoy] real RDP as local honey account $HONEY; waiting for Windows activity receipt"
for _ in {1..120}; do
    if [[ -s "$drive/receipt.json" ]]; then
        cat "$drive/receipt.json"
        echo
        echo "[win-decoy] attacker-side receipt saved at $drive/receipt.json; corroborate with Windows telemetry"
        exit 0
    fi
    owned_session || break
    sleep 1
done
echo "[win-decoy] No completed Windows activity confirmed. Containment may have interrupted RDP; inspect $drive/rdp.log and Windows events." >&2
if owned_session; then
    read -r pid < "$STATE/pid"
    kill -TERM -- "-$pid" 2>/dev/null || true
fi
rm -f "$STATE/pid"
exit 1
