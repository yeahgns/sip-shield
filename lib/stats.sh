#!/bin/bash
# ============================================================================
#  stats.sh — Human-readable summary of SIP Shield's current state.
#
#  Usage:
#    bash lib/stats.sh                 # print summary (also refreshes metrics)
#    bash lib/stats.sh --refresh-only  # refresh Prometheus textfile only (cron)
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$SCRIPT_DIR/lib/config.sh"
load_config
source "$SCRIPT_DIR/lib/detect.sh"
source "$SCRIPT_DIR/lib/metrics.sh"

if [[ "${1:-}" == "--refresh-only" ]]; then
    write_prometheus_metrics
    exit $?
fi

write_prometheus_metrics 2>/dev/null || true

rule_stats=$(iptables -L INPUT -v -n -x 2>/dev/null | grep "match-set ${BR_IPSET} src" | grep DROP | head -1)
dropped_packets=$(echo "$rule_stats" | awk '{print $1}'); dropped_packets="${dropped_packets:-0}"
dropped_bytes=$(echo "$rule_stats" | awk '{print $2}');   dropped_bytes="${dropped_bytes:-0}"
allowed_ranges=$(ipset list "$BR_IPSET" 2>/dev/null | grep -c "^[0-9]" || echo 0)
banned_ips=$(fail2ban-client status asterisk 2>/dev/null | grep "Currently banned:" | grep -oE '[0-9]+' | head -1)
banned_ips="${banned_ips:-0}"

total_bans_logged=0
[[ -f "$JSON_LOG_FILE" ]] && total_bans_logged=$(grep -c '"event":"ban"' "$JSON_LOG_FILE" 2>/dev/null || echo 0)

mgmt_state="off"
if [[ "${HARDEN_MGMT_PORTS:-1}" == "1" ]]; then
    mgmt_state="on ($MGMT_PORTS)"
    for port in $MGMT_PORTS; do
        iptables -S INPUT 2>/dev/null | grep -qE -- "--dport ${port} ! -s 127\.0\.0\.1/32 .*-j DROP" \
            || mgmt_state="DEGRADED — $port not restricted"
    done
fi

human_bytes() {
    local bytes="$1"
    if   (( bytes >= 1073741824 )); then printf "%.2f GB" "$(echo "$bytes / 1073741824" | bc -l)"
    elif (( bytes >= 1048576 ));    then printf "%.2f MB" "$(echo "$bytes / 1048576" | bc -l)"
    elif (( bytes >= 1024 ));       then printf "%.2f KB" "$(echo "$bytes / 1024" | bc -l)"
    else printf "%s B" "$bytes"
    fi
}

echo ""
echo "SIP Shield"
echo "────────────────────────────────────────"
printf "Target country:         %s\n" "${SIP_SHIELD_COUNTRY:-<unset>}"
printf "Asterisk ports:         %s\n" "$(detect_asterisk_ports)"
printf "Allowed ranges loaded:  %s\n" "$allowed_ranges"
printf "Packets dropped:        %s\n" "$dropped_packets"
printf "Data dropped:           %s\n" "$(human_bytes "$dropped_bytes" 2>/dev/null || echo "${dropped_bytes} B")"
printf "Currently banned (f2b): %s\n" "$banned_ips"
printf "Total bans logged:      %s\n" "$total_bans_logged"
printf "Mgmt-port hardening:    %s\n" "$mgmt_state"
echo "────────────────────────────────────────"
echo ""
echo "Note: packet/byte counters are cumulative since the GeoIP rule was last"
echo "(re)created — they reset on every install.sh or lib/update.sh run."
echo ""
