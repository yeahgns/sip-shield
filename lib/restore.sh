#!/bin/bash
# ============================================================================
#  restore.sh — Boot-time restore (called by /etc/sip-shield/restore.sh via
#  rc.local). Order matters: ipset before the rules that reference it.
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/detect.sh"
source "$SCRIPT_DIR/lib/geoip.sh"
source "$SCRIPT_DIR/lib/fail2ban.sh"
load_config

# 1. ipset first (rules depend on it)
[ -s "$GEOIP_DIR/ipset.save" ] && ipset restore -! < "$GEOIP_DIR/ipset.save"
[ "$(ipset_count)" -lt "$MIN_RANGES" ] && load_ipset

# 2. iptables snapshot (Issabel's own rules, etc.)
if [ -f /etc/sysconfig/iptables ]; then
    iptables-restore < /etc/sysconfig/iptables
elif [ -f /etc/iptables/rules.v4 ]; then
    iptables-restore < /etc/iptables/rules.v4
fi

# 3. fail2ban recreates its chains and re-applies active bans
systemctl try-restart fail2ban > /dev/null 2>&1 || true

# 4. Re-ensure GeoIP rules, mgmt-port hardening, and that trunks/trusted are unbanned
apply_iptables_rules
unban_protected_ips
