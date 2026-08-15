#!/bin/bash
# ============================================================
#  stats.sh — Human-readable summary of SIP Shield's current state.
#
#  Usage: bash lib/stats.sh
#
#  This reads live data the same way write_prometheus_metrics()
#  does, formatted for a terminal instead of for Prometheus.
#  Country-level attacker breakdown isn't included here — see
#  the "Known limitations" note in the README about why that
#  would need a different IP-to-country data source than the
#  one this project uses.
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/detect.sh"
source "$SCRIPT_DIR/lib/metrics.sh"

# --refresh-only: used by cron to update the Prometheus textfile every
# few minutes without printing the human-readable summary below.
if [[ "${1:-}" == "--refresh-only" ]]; then
    write_prometheus_metrics
    exit $?
fi

write_prometheus_metrics 2>/dev/null || true

sip_port=$(detect_sip_port)

rule_stats=$(iptables -L INPUT -v -n -x 2>/dev/null | grep "match-set ${BR_IPSET} src" | grep DROP | head -1)
dropped_packets=$(echo "$rule_stats" | awk '{print $1}')
dropped_bytes=$(echo "$rule_stats" | awk '{print $2}')
dropped_packets="${dropped_packets:-0}"
dropped_bytes="${dropped_bytes:-0}"

allowed_ranges=$(ipset list "$BR_IPSET" 2>/dev/null | grep -c "^[0-9]" || echo 0)

banned_ips=$(fail2ban-client status asterisk 2>/dev/null \
    | grep "Currently banned:" | grep -oE '[0-9]+' | head -1)
banned_ips="${banned_ips:-0}"

total_bans_logged=0
if [[ -f "$JSON_LOG_FILE" ]]; then
    total_bans_logged=$(grep -c '"event":"ban"' "$JSON_LOG_FILE" 2>/dev/null || echo 0)
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
printf "Target country:        %s\n" "$SIP_SHIELD_COUNTRY"
printf "SIP port:               %s\n" "$sip_port"
printf "Allowed ranges loaded:  %s\n" "$allowed_ranges"
printf "Packets dropped:        %s\n" "$dropped_packets"
printf "Data dropped:           %s\n" "$(human_bytes "$dropped_bytes" 2>/dev/null || echo "${dropped_bytes} B")"
printf "Currently banned (f2b): %s\n" "$banned_ips"
printf "Total bans logged:      %s\n" "$total_bans_logged"
echo "────────────────────────────────────────"
echo ""
echo "Note: packet/byte counters are cumulative since the GeoIP rule"
echo "was last (re)created — they reset on every 'bash install.sh' or"
echo "'bash lib/update.sh' run, not on a fixed schedule."
echo ""
