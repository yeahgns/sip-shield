#!/bin/bash
# ============================================================================
#  cli.sh — The `sip-shield` command. Installed to /usr/local/bin/sip-shield
#  by install.sh, so operators have one entry point instead of remembering
#  paths under lib/.
#
#  Usage: sip-shield <command> [args]
# ============================================================================

INSTALL_DIR="/opt/sip-shield"
source "$INSTALL_DIR/lib/config.sh" 2>/dev/null || { echo "SIP Shield not installed."; exit 1; }
load_config
source "$INSTALL_DIR/lib/detect.sh"
source "$INSTALL_DIR/lib/geoip.sh"
source "$INSTALL_DIR/lib/metrics.sh"

cmd="${1:-status}"; shift 2>/dev/null || true

case "$cmd" in
    status|"")
        bash "$INSTALL_DIR/lib/stats.sh"
        ;;
    update)
        exec bash "$INSTALL_DIR/lib/update.sh"
        ;;
    ban)
        [ -z "$1" ] && { echo "usage: sip-shield ban <ip>"; exit 1; }
        fail2ban-client set asterisk banip "$1" && echo "[+] Banned $1"
        ;;
    unban)
        [ -z "$1" ] && { echo "usage: sip-shield unban <ip>"; exit 1; }
        fail2ban-client set asterisk unbanip "$1" && echo "[+] Unbanned $1"
        ;;
    banned)
        fail2ban-client status asterisk 2>/dev/null | grep -A100 "Banned IP list" || echo "fail2ban not available"
        ;;
    ranges)
        echo "Ranges loaded in ipset '$BR_IPSET': $(ipset_count)"
        ;;
    test)
        [ -z "$1" ] && { echo "usage: sip-shield test <ip>"; exit 1; }
        if ipset test "$BR_IPSET" "$1" 2>/dev/null; then
            echo "[+] $1 IS in the allowed set (would pass GeoIP)"
        else
            echo "[-] $1 is NOT in the allowed set (would be dropped by GeoIP)"
        fi
        ;;
    config)
        ${EDITOR:-vi} "$CONF_FILE"
        echo "[*] Run 'sip-shield update' to apply changes."
        ;;
    logs)
        tail -n "${1:-40}" /var/log/sip-shield.log 2>/dev/null || echo "No ban log yet."
        ;;
    rules)
        iptables -S INPUT | grep -E "match-set $BR_IPSET|--dport ($(echo "$MGMT_PORTS" | tr ' ' '|'))|-i lo -j ACCEPT" || true
        ;;
    help|-h|--help)
        cat << EOF
sip-shield — GeoIP + fail2ban protection for Issabel/Asterisk

Usage: sip-shield <command> [args]

  status            Show current state (default). Also refreshes metrics.
  update            Refresh country ranges now and re-apply rules.
  ban <ip>          Ban an IP in the asterisk jail.
  unban <ip>        Unban an IP.
  banned            List currently banned IPs.
  ranges            How many country ranges are loaded.
  test <ip>         Would this IP pass the GeoIP filter?
  rules             Show the active SIP Shield iptables rules.
  config            Edit the per-host config, then reminds you to update.
  logs [n]          Show the last n ban-log lines (default 40).
  help              This message.
EOF
        ;;
    *)
        echo "Unknown command: $cmd (try 'sip-shield help')"; exit 1
        ;;
esac
