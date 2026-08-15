#!/bin/bash

detect_distro() {
    if [ -f /etc/rocky-release ]; then
        echo "rocky8"
    elif [ -f /etc/centos-release ]; then
        echo "centos7"
    else
        echo "unknown"
    fi
}

detect_sip_port() {
    local port
    # Grabs the lowest UDP port Asterisk is listening on — SIP signaling
    # always uses a low port, while RTP media uses a much higher range
    # (typically 10000+), so sorting ascending reliably picks SIP first,
    # regardless of which specific port number is configured.
    port=$(netstat -unlp 2>/dev/null | grep asterisk | awk '{print $4}' | grep -oE '[0-9]+$' | sort -n | head -1)
    if [ -z "$port" ]; then
        port=$(ss -unlp 2>/dev/null | grep asterisk | awk '{print $5}' | grep -oE '[0-9]+$' | sort -n | head -1)
    fi
    echo "${port:-5060}"
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
    echo " SIP Shield - Environment detection"
    echo "================================"
    echo "Distro        : $(detect_distro)"
    echo "SIP port      : $(detect_sip_port)"
    echo "Asterisk log  : $(detect_asterisk_logpath)"
    echo "f2b jail      : $(detect_fail2ban_jail_exists)"
    echo "Target country: $SIP_SHIELD_COUNTRY"
    echo "================================"
}
