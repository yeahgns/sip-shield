#!/bin/bash
# ============================================================================
#  detect.sh — Environment detection helpers.
# ============================================================================

detect_distro() {
    if [ -f /etc/rocky-release ]; then
        echo "rocky8"
    elif [ -f /etc/centos-release ]; then
        echo "centos7"
    else
        echo "unknown"
    fi
}

# Informational only: GeoIP blocks ALL ports, so changing the SIP/PJSIP port
# (5060, 5066, a custom one...) requires no change to the rules.
detect_asterisk_ports() {
    ss -tulnp 2>/dev/null | awk '/"asterisk"/ {n=split($5,a,":"); print a[n]"/"$1}' \
        | sort -t/ -k1,1n -u | tr '\n' ' '
}

detect_asterisk_logpath() {
    if [ -f /var/log/asterisk/full ]; then
        echo "/var/log/asterisk/full"
    elif [ -f /var/log/asterisk/messages ]; then
        echo "/var/log/asterisk/messages"
    else
        echo "/var/log/asterisk/full"
    fi
}

detect_fail2ban_jail_exists() {
    grep -q '^\[asterisk\]' /etc/fail2ban/jail.local 2>/dev/null && echo "yes" || echo "no"
}

print_env() {
    echo "================================"
    echo " SIP Shield — environment"
    echo "================================"
    echo "Distro         : $(detect_distro)"
    echo "Asterisk ports : $(detect_asterisk_ports)"
    echo "Asterisk log   : $(detect_asterisk_logpath)"
    echo "f2b jail       : $(detect_fail2ban_jail_exists)"
    echo "Target country : ${SIP_SHIELD_COUNTRY:-<unset>}"
    echo "Trunks         : ${TRUNK_IPS:-<none>}"
    echo "Trusted        : ${TRUSTED_IPS:-<none>}"
    echo "Harden mgmt    : $([ "$HARDEN_MGMT_PORTS" = 1 ] && echo "yes ($MGMT_PORTS)" || echo "no")"
    echo "================================"
}
