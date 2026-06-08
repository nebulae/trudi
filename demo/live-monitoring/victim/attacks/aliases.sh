# Friendly aliases → Atomic Red Team test references.
# Sourced by /attacks/run.
#
# Each entry maps a short name the operator types to <T-number>#<test-number>.
# The test-number suffix is optional (defaults to #1). Pick tests that:
#   - have a `bash` or `sh` executor block
#   - have a `cleanup_command` so demo state is reversible
#   - fire the matching Custom.TRUDI.* detector cleanly

declare -A alias_map=(
    # New process from /tmp/ — fires Custom.TRUDI.NewProcess.
    [new-process]="T1059.004#1"

    # Cron persistence in /etc/cron.d/ — fires Custom.TRUDI.NewPersistence.
    [persistence]="T1053.003#1"

    # Outbound C2 to a non-RFC1918 destination — fires Custom.TRUDI.NewNetwork.
    # NOTE: `run` special-cases `network` (and `beacon`) to exec beacon.sh, which
    # holds a long-lived ESTABLISHED connection to the 203.0.113.10 C2 sink. The
    # T1071.001#3 mapping is retained for reference/--list only; the shipped curl
    # is too short-lived for the detector's 10s poll. See beacon.sh.
    [network]="T1071.001#3"
    [beacon]="T1071.001#3"

    # Process injection / known-bad token in memory — fires Custom.TRUDI.YaraProcess.
    [yara]="T1055.001#1"

    # LOLBin / unusual-path execution — used for the self-correction demo beat.
    # /bin/sleep run from /tmp/ — image name is allowlisted but path is not.
    [lolbas]="T1036.005#1"
)

list_aliases() {
    for k in "${!alias_map[@]}"; do
        printf "  %-14s → %s\n" "${k}" "${alias_map[$k]}"
    done | sort
}
