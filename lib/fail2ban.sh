#!/bin/bash

LOG_FILE="/var/log/sip-shield.log"

log_ban() {
    local ip="$1"
    local origin="${2:-manual}"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] BAN ip=$ip origin=$origin" >> "$LOG_FILE"
    # Additive observability hooks — JSON log + webhook. No-ops if
    # SIP_SHIELD_WEBHOOK_URL isn't set; JSON log always writes.
    record_event "ban" "$ip" "$origin" 2>/dev/null || true
}

configure_fail2ban() {
    local logpath
    logpath=$(detect_asterisk_logpath)

    echo "[*] Configuring fail2ban asterisk jail..."

    if [ ! -f "$logpath" ]; then
        touch "$logpath"
        chown asterisk:asterisk "$logpath" 2>/dev/null || true
        asterisk -rx "logger reload" > /dev/null 2>&1 || true
        echo "[+] Log file created: $logpath"
    fi

    if grep -q '^\[asterisk\]' /etc/fail2ban/jail.local 2>/dev/null; then
        echo "[*] Removing existing asterisk configuration..."
        python3 -c "
import re, sys
with open('/etc/fail2ban/jail.local', 'r') as f:
    content = f.read()
content = re.sub(r'\[asterisk\][^\[]*', '', content)
with open('/etc/fail2ban/jail.local', 'w') as f:
    f.write(content)
" 2>/dev/null || sed -i '/^\[asterisk\]/,/^\[/{ /^\[asterisk\]/d; /^\[/!d }' /etc/fail2ban/jail.local
    fi

    # Whitelisted IPs (SIP trunk providers, etc.) are never banned by fail2ban
    local ignoreip_list
    ignoreip_list=$(get_whitelist_ips_array | paste -sd' ' -)

    cat >> /etc/fail2ban/jail.local << EOF

[asterisk]
enabled = true
ignoreip = ${ignoreip_list}
logpath = ${logpath}
maxretry = ${SIP_SHIELD_MAXRETRY}
findtime = ${SIP_SHIELD_FINDTIME}
bantime = ${SIP_SHIELD_BANTIME}
EOF

    echo "[+] asterisk jail configured (bantime: $((SIP_SHIELD_BANTIME / 86400)) days, maxretry: ${SIP_SHIELD_MAXRETRY})"

    # Custom action to log bans/unbans to sip-shield.log
    setup_ban_action

    systemctl restart fail2ban
    sleep 2

    if systemctl is-active --quiet fail2ban; then
        echo "[+] fail2ban restarted successfully"
    else
        echo "[!] Error restarting fail2ban. Checking logs..."
        journalctl -u fail2ban -n 10 --no-pager
        return 1
    fi

    ban_known_ips
}

setup_ban_action() {
    cat > /etc/fail2ban/action.d/sip-shield-log.conf << EOF
[Definition]
actionban = echo "[\$(date '+%%Y-%%m-%%d %%H:%%M:%%S')] BAN ip=<ip> origin=fail2ban jail=<name>" >> /var/log/sip-shield.log; bash ${SCRIPT_DIR}/lib/record-event.sh ban <ip> fail2ban >/dev/null 2>&1 || true
actionunban = echo "[\$(date '+%%Y-%%m-%%d %%H:%%M:%%S')] UNBAN ip=<ip> origin=fail2ban jail=<name>" >> /var/log/sip-shield.log; bash ${SCRIPT_DIR}/lib/record-event.sh unban <ip> fail2ban >/dev/null 2>&1 || true
EOF

    if ! grep -q 'sip-shield-log' /etc/fail2ban/jail.local 2>/dev/null; then
        sed -i '/^\[asterisk\]/,/^\[/{/bantime/a action = %(action_mwl)s\n         sip-shield-log
}' /etc/fail2ban/jail.local 2>/dev/null || true
    fi

    echo "[+] Ban logging action configured"
}

ban_known_ips() {
    # Optional: pre-ban a list of known-bad IPs at install time.
    # See lib/known-ips.txt.example — copy it to lib/known-ips.txt
    # and adjust with your own threat intel/logs if you want this step.
    if [ ! -f "$SIP_SHIELD_KNOWN_IPS_FILE" ]; then
        echo "[*] No known-ips file found at $SIP_SHIELD_KNOWN_IPS_FILE, skipping pre-ban step."
        echo "    (see lib/known-ips.txt.example to enable this)"
        return 0
    fi

    echo "[*] Pre-banning known attacker IPs from $SIP_SHIELD_KNOWN_IPS_FILE..."

    local count=0
    while IFS= read -r ip; do
        [[ -z "$ip" || "$ip" == \#* ]] && continue
        if fail2ban-client set asterisk banip "$ip" > /dev/null 2>&1; then
            log_ban "$ip" "known-ips-list"
            count=$((count + 1))
        fi
    done < "$SIP_SHIELD_KNOWN_IPS_FILE"

    echo "[+] ${count} IPs pre-banned"
}
