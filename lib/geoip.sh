#!/bin/bash
GEOIP_DIR="/etc/sip-shield"

install_dependencies() {
    local distro
    distro=$(detect_distro)
    echo "[*] Installing dependencies..."
    if [ "$distro" = "centos7" ]; then
        yum install -y ipset curl python3 jq > /dev/null 2>&1
    else
        dnf install -y ipset curl python3 jq > /dev/null 2>&1
    fi
    echo "[+] Dependencies installed"
}

download_country_ranges() {
    local ripe_url="https://stat.ripe.net/data/country-resource-list/data.json?resource=${SIP_SHIELD_COUNTRY}"
    echo "[*] Downloading ${SIP_SHIELD_COUNTRY} IP ranges from RIPE NCC..."
    mkdir -p "$GEOIP_DIR"
    local response
    response=$(curl -s --max-time 30 "$ripe_url")
    if [ -z "$response" ]; then
        echo "[!] Error querying RIPE NCC"
        return 1
    fi
    echo "$response" | python3 -c "
import sys, json
data = json.load(sys.stdin)
ranges = data['data']['resources']['ipv4']
for r in ranges:
    print(r)
" > "$GEOIP_DIR/allowed_ranges.txt"
    local count
    count=$(wc -l < "$GEOIP_DIR/allowed_ranges.txt")
    echo "[+] ${count} ${SIP_SHIELD_COUNTRY} ranges downloaded"
}

create_ipset() {
    echo "[*] Creating ipset with ${SIP_SHIELD_COUNTRY} ranges..."

    # Remove old iptables rule referencing the ipset, if it exists
    # (must happen BEFORE destroy, otherwise the kernel refuses since it's in use)
    local sip_port
    sip_port=$(detect_sip_port)
    iptables -D INPUT -p udp --dport "$sip_port" -m set ! --match-set "$BR_IPSET" src -j DROP 2>/dev/null || true

    # Retry on destroy: the kernel may take a moment (race condition) to
    # release the ipset reference after the iptables rule is removed,
    # especially on systems using the nf_tables backend.
    local tries=0
    local max_tries=10
    while [ $tries -lt $max_tries ]; do
        if ipset destroy "$BR_IPSET" 2>/dev/null; then
            break
        fi
        # If the error is "does not exist", there's nothing to destroy, move on
        if ! ipset list -n 2>/dev/null | grep -qx "$BR_IPSET"; then
            break
        fi
        sleep 0.5
        tries=$((tries + 1))
    done

    if [ $tries -ge $max_tries ] && ipset list -n 2>/dev/null | grep -qx "$BR_IPSET"; then
        echo "[!] Warning: could not destroy the old ipset after ${max_tries} attempts."
        echo "[!] Attempting to proceed with 'ipset create -exist' as a fallback..."
    fi

    # Create new ipset (uses -exist as an extra safety net: doesn't fail if it already exists)
    ipset create "$BR_IPSET" hash:net maxelem 65536 -exist
    # Make sure it's empty before populating (in case -exist reused an old set)
    ipset flush "$BR_IPSET"

    # Add ranges
    while IFS= read -r range; do
        [ -z "$range" ] && continue
        ipset add "$BR_IPSET" "$range" 2>/dev/null || true
    done < "$GEOIP_DIR/allowed_ranges.txt"
    local count
    count=$(ipset list "$BR_IPSET" | grep -c "^[0-9]")
    echo "[+] ipset created with ${count} ranges"
}

apply_iptables_rules() {
    local sip_port
    sip_port=$(detect_sip_port)
    echo "[*] Applying iptables rules for port $sip_port..."

    # Remove old rules
    iptables -D INPUT -p udp --dport "$sip_port" -m set ! --match-set "$BR_IPSET" src -j DROP 2>/dev/null || true

    local whitelist_ips
    mapfile -t whitelist_ips < <(get_whitelist_ips_array)

    for ip in "${whitelist_ips[@]}"; do
        [[ -z "$ip" ]] && continue
        iptables -D INPUT -p udp --dport "$sip_port" -s "$ip" -j ACCEPT 2>/dev/null || true
        iptables -I INPUT 1 -p udp --dport "$sip_port" -s "$ip" -j ACCEPT
        echo "[+] Whitelisted: $ip"
    done

    # Block anything outside the target country
    # (rule position accounts for however many whitelist rules were inserted above)
    iptables -I INPUT $((${#whitelist_ips[@]} + 1)) -p udp --dport "$sip_port" -m set ! --match-set "$BR_IPSET" src -j DROP
    echo "[+] GeoIP rule applied: port $sip_port blocked for traffic outside ${SIP_SHIELD_COUNTRY}"
    save_iptables_rules
}

save_iptables_rules() {
    local distro
    distro=$(detect_distro)
    if [ "$distro" = "centos7" ]; then
        service iptables save 2>/dev/null || iptables-save > /etc/sysconfig/iptables
    else
        iptables-save > /etc/sysconfig/iptables 2>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
}

save_ipset() {
    echo "[*] Saving ipset for persistence..."
    ipset save > "$GEOIP_DIR/ipset.save"

    local sip_port
    sip_port=$(detect_sip_port)
    local whitelist_ips
    mapfile -t whitelist_ips < <(get_whitelist_ips_array)

    # Build the restore script's whitelist section dynamically
    local whitelist_restore_lines=""
    for ip in "${whitelist_ips[@]}"; do
        [[ -z "$ip" ]] && continue
        whitelist_restore_lines+="iptables -D INPUT -p udp --dport ${sip_port} -s ${ip} -j ACCEPT 2>/dev/null || true"$'\n'
        whitelist_restore_lines+="iptables -I INPUT 1 -p udp --dport ${sip_port} -s ${ip} -j ACCEPT"$'\n'
    done

    # Create the boot-time restore script (ipset BEFORE iptables)
    {
        echo '#!/bin/bash'
        echo '# 1. Restore ipset first'
        echo "ipset restore -! < ${GEOIP_DIR}/ipset.save"
        echo '# 2. Restore iptables rules'
        echo 'if [ -f /etc/sysconfig/iptables ]; then'
        echo '    iptables-restore < /etc/sysconfig/iptables'
        echo 'elif [ -f /etc/iptables/rules.v4 ]; then'
        echo '    iptables-restore < /etc/iptables/rules.v4'
        echo 'fi'
        echo '# 3. Re-ensure whitelist is on top (in case iptables-restore reordered things)'
        printf '%s' "$whitelist_restore_lines"
    } > "$GEOIP_DIR/restore.sh"

    chmod +x "$GEOIP_DIR/restore.sh"
    # Add to rc.local so it restores after reboot
    if ! grep -q "sip-shield/restore.sh" /etc/rc.local 2>/dev/null; then
        echo "$GEOIP_DIR/restore.sh" >> /etc/rc.local
        chmod +x /etc/rc.local
    fi
    echo "[+] ipset saved and configured to restore on boot"
}

setup_geoip() {
    install_dependencies
    download_country_ranges || return 1
    create_ipset
    apply_iptables_rules
    save_ipset
}
