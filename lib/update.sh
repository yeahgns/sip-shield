#!/bin/bash
# ============================================================================
#  update.sh — Monthly refresh of the allowed country's IP ranges (via cron).
#  No unprotected window: the ipset is swapped atomically. If the download
#  fails, the current ranges are kept.
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/detect.sh"
source "$SCRIPT_DIR/lib/geoip.sh"
source "$SCRIPT_DIR/lib/fail2ban.sh"
load_config

exec 9> /var/lock/sip-shield.lock
flock -n 9 || { echo "[$(date)] Another run in progress, exiting"; exit 0; }

echo "[$(date)] Starting range refresh for ${SIP_SHIELD_COUNTRY}..."
if download_country_ranges; then
    load_ipset && save_ipset
fi
apply_iptables_rules
if systemctl is-active --quiet fail2ban; then
    write_protected_ips_conf && fail2ban-client reload > /dev/null 2>&1
    unban_protected_ips
fi
echo "[$(date)] Update complete ($(ipset_count) ranges)"
