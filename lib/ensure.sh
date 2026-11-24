#!/bin/bash
# ============================================================================
#  ensure.sh — Periodic check (cron, every 5 minutes).
#
#  If the GeoIP rule or the management-port hardening disappeared from INPUT
#  (e.g. Issabel's own firewall rewrote iptables), put them back and log it to
#  /var/log/sip-shield.log. If the ipset itself is gone, reload it from the
#  saved snapshot first. When everything is in place it exits silently without
#  touching anything.
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/detect.sh"
source "$SCRIPT_DIR/lib/geoip.sh"
load_config

[ -n "$SIP_SHIELD_COUNTRY" ] || exit 0          # not installed/configured yet

_mgmt_ok() {
    [ "${HARDEN_MGMT_PORTS:-1}" = "1" ] || return 0
    local port
    for port in $MGMT_PORTS; do
        iptables -S INPUT 2>/dev/null | grep -E -- "--dport ${port}( |$)" \
            | grep -qE -- '! -s 127\.0\.0\.1/32' || return 1
    done
}

_log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> /var/log/sip-shield.log; }

# 1. The ipset must exist and be complete (rules reference it).
if [ "$(ipset_count)" -lt "$MIN_RANGES" ] && [ -s "$GEOIP_DIR/ipset.save" ]; then
    ipset restore -! < "$GEOIP_DIR/ipset.save" 2>/dev/null && _log "ENSURE ipset $BR_IPSET reloaded from snapshot"
fi

# 2. Rules already right? Leave everything alone.
_rules_already_ok && _mgmt_ok && exit 0

# 3. Something is missing: re-apply (same code path as install/update).
if apply_iptables_rules >/dev/null 2>&1; then
    _log "ENSURE GeoIP/mgmt-port rules were missing and have been re-applied"
else
    _log "ENSURE GeoIP rules missing and could NOT be re-applied (run: sip-shield status)"
fi
