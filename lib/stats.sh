#!/bin/bash
# ============================================================================
#  stats.sh — Human-readable summary of SIP Shield's current state.
#
#  Usage:
#    bash lib/stats.sh                 # print summary
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$SCRIPT_DIR/lib/config.sh"
load_config
source "$SCRIPT_DIR/lib/detect.sh"

rule_stats=$(iptables -L INPUT -v -n -x 2>/dev/null | grep "match-set ${BR_IPSET} src" | grep DROP | head -1)
dropped_packets=$(echo "$rule_stats" | awk '{print $1}'); dropped_packets="${dropped_packets:-0}"
dropped_bytes=$(echo "$rule_stats" | awk '{print $2}');   dropped_bytes="${dropped_bytes:-0}"
allowed_ranges=$(ipset list "$BR_IPSET" 2>/dev/null | grep -c "^[0-9]" || echo 0)
banned_ips=$(fail2ban-client status asterisk 2>/dev/null | grep "Currently banned:" | grep -oE '[0-9]+' | head -1)
banned_ips="${banned_ips:-0}"

total_bans_logged=0
[[ -f /var/log/sip-shield.log ]] && total_bans_logged=$(grep -c ' BAN ip=' /var/log/sip-shield.log 2>/dev/null || echo 0)

mgmt_state="off"
if [[ "${HARDEN_MGMT_PORTS:-1}" == "1" ]]; then
    mgmt_state="on ($MGMT_PORTS)"
    for port in $MGMT_PORTS; do
        iptables -S INPUT 2>/dev/null \
            | grep -E -- "--dport ${port}( |\\b)" \
            | grep -qE -- '! -s 127\.0\.0\.1/32' \
            || mgmt_state="DEGRADED — $port not restricted"
    done
fi

human_bytes() {
    # awk (not bc + printf): works without bc and with any locale (pt_BR uses a comma).
    LC_ALL=C awk -v b="$1" 'BEGIN {
        if (b >= 1073741824) printf "%.2f GB", b / 1073741824
        else if (b >= 1048576) printf "%.2f MB", b / 1048576
        else if (b >= 1024) printf "%.2f KB", b / 1024
        else printf "%d B", b }'
}

echo ""
echo "SIP Shield"
echo "────────────────────────────────────────"
printf "Target country:         %s\n" "${SIP_SHIELD_COUNTRY:-<unset>}"
printf "Asterisk ports:         %s\n" "$(detect_asterisk_ports)"
printf "Allowed ranges loaded:  %s\n" "$allowed_ranges"
printf "Packets dropped:        %s\n" "$dropped_packets"
printf "Data dropped:           %s\n" "$(human_bytes "$dropped_bytes")"
printf "Currently banned (f2b): %s\n" "$banned_ips"
printf "Total bans logged:      %s\n" "$total_bans_logged"
printf "Mgmt-port hardening:    %s\n" "$mgmt_state"
echo "────────────────────────────────────────"
echo ""
echo "Note: packet/byte counters are cumulative since the GeoIP rule was last"
echo "(re)created — they reset on every install.sh or lib/update.sh run."
echo ""
