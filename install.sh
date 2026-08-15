#!/bin/bash
# ============================================================
#  install.sh — SIP Shield: GeoIP + fail2ban protection for
#  Issabel/Asterisk PBX servers.
#
#  Blocks SIP traffic from outside a target country at the
#  network layer (iptables + ipset), before Asterisk even
#  processes the packet, and adds fail2ban as a second layer
#  against brute-force attempts (including from allowed
#  countries).
#
#  Usage: sudo bash install.sh
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/detect.sh"
source "$SCRIPT_DIR/lib/fail2ban.sh"
source "$SCRIPT_DIR/lib/geoip.sh"
source "$SCRIPT_DIR/lib/metrics.sh"

echo ""
echo "============================================================================="
echo "  SIP Shield | GeoIP + fail2ban protection for Issabel | by Guilherme Nunes  "
echo "============================================================================="
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "[!] Run as root"
    exit 1
fi

print_env
echo ""

if ! command -v fail2ban-client &>/dev/null; then
    echo "[!] fail2ban not found. Installing..."
    distro=$(detect_distro)
    if [ "$distro" = "centos7" ]; then
        yum install -y epel-release > /dev/null 2>&1
        yum install -y fail2ban > /dev/null 2>&1
    else
        dnf install -y epel-release > /dev/null 2>&1
        dnf install -y fail2ban > /dev/null 2>&1
    fi
    systemctl enable fail2ban
    systemctl start fail2ban
    echo "[+] fail2ban installed"
fi


echo "--- fail2ban ---"
configure_fail2ban
echo ""

echo "--- GeoIP ---"
setup_geoip
echo ""

echo "[*] Setting up monthly GeoIP update..."
CRON_JOB="0 3 1 * * root $SCRIPT_DIR/lib/update.sh >> /var/log/sip-shield-update.log 2>&1"
if ! grep -q "sip-shield" /etc/crontab 2>/dev/null; then
    echo "$CRON_JOB" >> /etc/crontab
    echo "[+] Cron configured (1st of every month at 03:00)"
fi

echo "[*] Persisting configuration for cron/fail2ban use..."
persist_config

echo "[*] Writing Prometheus metrics..."
write_prometheus_metrics && echo "[+] Metrics written to ${PROM_TEXTFILE}"

echo "[*] Setting up metrics refresh (every 5 minutes)..."
METRICS_CRON_JOB="*/5 * * * * root $SCRIPT_DIR/lib/stats.sh --refresh-only >> /var/log/sip-shield-metrics.log 2>&1"
if ! grep -q "sip-shield.*stats.sh --refresh-only" /etc/crontab 2>/dev/null; then
    echo "$METRICS_CRON_JOB" >> /etc/crontab
    echo "[+] Metrics refresh cron configured (every 5 minutes)"
fi

echo ""
echo "========================================"
echo "         Installation complete!         "
echo "========================================"
echo ""
echo "Summary:"
echo "  - fail2ban: asterisk jail active (bantime 7 days)"
echo "  - GeoIP: port $(detect_sip_port) blocked for traffic outside the target country"
echo "  - Automatic update: 1st of every month at 03:00"
echo ""
echo "Useful commands:"
echo "  fail2ban-client status asterisk     # view banned IPs"
echo "  ipset list allowed_ranges | wc -l   # view loaded country ranges"
echo "  bash $SCRIPT_DIR/lib/update.sh       # manually update ranges"
echo ""
