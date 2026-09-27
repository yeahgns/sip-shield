#!/bin/bash
# ============================================================================
#  install.sh — SIP Shield installer / updater. Idempotent: run as many times
#  as you like. Migrates hosts from the old per-port model to the all-ports
#  model without duplicating rules.
#
#  Two ways to configure:
#
#    Interactive wizard:
#      sudo bash install.sh --wizard
#
#    Non-interactive (automation / Ansible):
#      export SIP_SHIELD_COUNTRY="BR"
#      export SIP_SHIELD_TRUNK_IPS="203.0.113.10"
#      export SIP_SHIELD_TRUSTED_IPS="198.51.100.5"
#      sudo bash install.sh
#
#  Everything installs to /opt/sip-shield, so the clone directory can be
#  deleted afterward. Per-host settings live in /etc/sip-shield/sip-shield.conf
#  and are never overwritten by a reinstall.
# ============================================================================

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
WIZARD=0
[ "${1:-}" = "--wizard" ] && WIZARD=1

if [ "$EUID" -ne 0 ]; then
    echo "[!] Run as root"
    exit 1
fi

echo ""
echo "=============================================================================="
echo "  SIP Shield | GeoIP + fail2ban protection for Issabel/Asterisk               "
echo "=============================================================================="
echo ""

# Load config early (defaults + any existing per-host file + env vars).
source "$SRC_DIR/lib/config.sh"
load_config

# Wizard, if requested — fills the variables interactively before anything else.
if [ "$WIZARD" = 1 ]; then
    source "$SRC_DIR/lib/wizard.sh"
    run_wizard
fi

# Country is mandatory in both modes.
if [ -z "$SIP_SHIELD_COUNTRY" ]; then
    echo "[ERROR] SIP_SHIELD_COUNTRY is not set."
    echo "        Run 'sudo bash install.sh --wizard' for guided setup, or set it:"
    echo "        export SIP_SHIELD_COUNTRY=\"BR\"; sudo bash install.sh"
    exit 1
fi

# Install code to the fixed path (cron and boot don't depend on the clone dir).
if [ "$SRC_DIR" != "$INSTALL_DIR" ]; then
    mkdir -p "$INSTALL_DIR/lib"
    cp -f "$SRC_DIR/install.sh" "$INSTALL_DIR/" 2>/dev/null || true
    cp -f "$SRC_DIR"/README*.md "$INSTALL_DIR/" 2>/dev/null || true
    cp -f "$SRC_DIR"/lib/*.sh "$INSTALL_DIR/lib/"
    # Carry over a real known-ips.txt if the operator created one next to the clone.
    [ -f "$SRC_DIR/lib/known-ips.txt" ] && cp -f "$SRC_DIR/lib/known-ips.txt" "$INSTALL_DIR/lib/"
    cp -f "$SRC_DIR/lib/known-ips.txt.example" "$INSTALL_DIR/lib/" 2>/dev/null || true
fi
chmod 755 "$INSTALL_DIR/install.sh" "$INSTALL_DIR"/lib/*.sh 2>/dev/null || true

# Re-source from the installed location so paths are consistent from here on.
source "$INSTALL_DIR/lib/config.sh"
load_config
source "$INSTALL_DIR/lib/detect.sh"
source "$INSTALL_DIR/lib/geoip.sh"
source "$INSTALL_DIR/lib/fail2ban.sh"
source "$INSTALL_DIR/lib/metrics.sh"

# Write the per-host config file (once) and re-load so downstream sees it.
write_default_config
load_config

print_env
echo ""

# fail2ban package
if ! command -v fail2ban-client &>/dev/null; then
    echo "[!] fail2ban not found. Installing..."
    if [ "$(detect_distro)" = "centos7" ]; then
        yum install -y epel-release > /dev/null 2>&1
        yum install -y fail2ban > /dev/null 2>&1
    else
        dnf install -y epel-release > /dev/null 2>&1
        dnf install -y fail2ban > /dev/null 2>&1
    fi
fi

echo "--- GeoIP + management-port hardening ---"
setup_geoip || { echo "[!] GeoIP setup failed. See messages above."; exit 1; }
echo ""

echo "--- fail2ban ---"
configure_fail2ban || echo "[!] Check fail2ban (GeoIP is already active)"
echo ""

echo "--- Observability ---"
write_prometheus_metrics && echo "[+] Prometheus metrics written to ${SIP_SHIELD_PROM_TEXTFILE_DIR}/sip_shield.prom"
echo ""

echo "--- Central command ---"
install -m 755 "$INSTALL_DIR/lib/cli.sh" /usr/local/bin/sip-shield \
    && echo "[+] 'sip-shield' command installed (try: sip-shield status)"
echo ""

echo "========================================"
echo "  Installation complete!"
echo "========================================"
echo "  - GeoIP: new connections from outside ${SIP_SHIELD_COUNTRY} blocked on ALL ports"
echo "  - Mgmt hardening: $([ "$HARDEN_MGMT_PORTS" = 1 ] && echo "MySQL/AMI ($MGMT_PORTS) restricted to localhost" || echo "disabled")"
echo "  - fail2ban: asterisk jail active (bantime $((SIP_SHIELD_BANTIME/86400)) days)"
echo "  - Never blocked/banned: loopback, ${TRUNK_IPS:-<none>} ${TRUSTED_IPS:-<none>}"
echo "  - Config: $CONF_FILE"
echo ""
echo "  Try:  sip-shield status"
echo ""
