#!/bin/bash
# ============================================================================
#  geoip.sh — Network-layer country filtering + management-port hardening.
#
#  Blocks any NEW connection from outside the allowed country, on every port
#  and protocol. Rule block sits at the top of INPUT (only fail2ban's own jump
#  targets may sit above it):
#
#    1. -i lo -j ACCEPT                      (local services, e.g. web -> AMI)
#    2. -s <trunk>   -j ACCEPT               (SIP trunk / DID provider)
#    3. -s <trusted> -j ACCEPT               (monitoring / admin)
#    4. NEW ! allowed_ranges -j DROP         (GeoIP)
#    5. management-port hardening (optional)  (MySQL/AMI to localhost only)
#
#  No RELATED,ESTABLISHED ACCEPT above the fail2ban jumps: the DROP only
#  catches NEW connections, so established traffic passes anyway, and an
#  attacker with a steady UDP flow can't dodge a ban.
#
#  Everything is idempotent: running N times yields the same result, no dupes.
# ============================================================================

install_dependencies() {
    echo "[*] Installing dependencies..."
    if [ "$(detect_distro)" = "centos7" ]; then
        yum install -y ipset curl python3 > /dev/null 2>&1
    else
        dnf install -y ipset curl python3 > /dev/null 2>&1
    fi
    echo "[+] Dependencies installed"
}

# Valid IPv4 CIDR or range lines only.
_valid_ranges() {
    grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2}|-[0-9]{1,3}(\.[0-9]{1,3}){3})$' "$1"
}

# Download the allowed country's ranges from RIPE NCC, with retries and a
# minimum-count sanity check. On failure, keeps the current ranges.
download_country_ranges() {
    echo "[*] Downloading ${SIP_SHIELD_COUNTRY} IP ranges from RIPE NCC..."
    mkdir -p "$GEOIP_DIR"
    local tmp="$GEOIP_DIR/allowed_ranges.txt.new" attempt count url
    url="$(ripe_url)"
    for attempt in 1 2 3; do
        if curl -sf --max-time 60 "$url" 2>/dev/null | python3 -c '
import sys, json
for r in json.load(sys.stdin)["data"]["resources"]["ipv4"]:
    print(r)
' > "$tmp" 2>/dev/null; then
            count=$(_valid_ranges "$tmp" | wc -l)
            if [ "$count" -ge "$MIN_RANGES" ]; then
                _valid_ranges "$tmp" > "$GEOIP_DIR/allowed_ranges.txt"
                rm -f "$tmp"
                echo "[+] $count ranges downloaded"
                return 0
            fi
            echo "[!] RIPE returned only $count ranges (min $MIN_RANGES), attempt $attempt/3"
        else
            echo "[!] RIPE NCC query failed, attempt $attempt/3"
        fi
        [ "$attempt" -lt 3 ] && sleep $((attempt * 20 + RANDOM % 20))
    done
    rm -f "$tmp"
    echo "[!] Download failed — keeping current ranges"
    return 1
}

# Load allowed_ranges.txt into the ipset with NO unprotected window: build a
# temp set and 'ipset swap' (atomic, works while the set is in use by iptables).
load_ipset() {
    local src="$GEOIP_DIR/allowed_ranges.txt" tmpset="${BR_IPSET}_new" count
    [ -f "$src" ] || { echo "[!] $src does not exist"; return 1; }
    count=$(_valid_ranges "$src" | wc -l)
    if [ "$count" -lt "$MIN_RANGES" ]; then
        echo "[!] $src has only $count ranges (min $MIN_RANGES) — ipset NOT changed"
        return 1
    fi
    echo "[*] Loading $count ranges into ipset..."
    ipset destroy "$tmpset" 2>/dev/null || true
    {
        echo "create $tmpset hash:net family inet hashsize 4096 maxelem 131072"
        _valid_ranges "$src"    | sed "s/^/add $tmpset /"
        _allow_nets             | sed "s/^/add $tmpset /"
    } | ipset restore -! || { echo "[!] Failed to build temp ipset"; ipset destroy "$tmpset" 2>/dev/null; return 1; }

    if ipset list -n 2>/dev/null | grep -qx "$BR_IPSET"; then
        ipset swap "$tmpset" "$BR_IPSET" || { echo "[!] ipset swap failed"; ipset destroy "$tmpset" 2>/dev/null; return 1; }
        ipset destroy "$tmpset" 2>/dev/null || true
    else
        ipset rename "$tmpset" "$BR_IPSET" || return 1
    fi
    echo "[+] ipset $BR_IPSET loaded with $(ipset_count) ranges"
}

# Valid GEOIP_ALLOW_NETS entries, one per line.
_allow_nets() {
    local n
    for n in $GEOIP_ALLOW_NETS; do
        if echo "$n" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$'; then
            echo "$n"
        else
            echo "[!] GEOIP_ALLOW_NETS: '$n' invalid, ignored" >&2
        fi
    done
}

# Ensure the ipset holds exactly the current GEOIP_ALLOW_NETS: add new ones,
# remove ones dropped from config (without touching the country ranges).
sync_allow_nets() {
    local f="$GEOIP_DIR/allow_nets.applied" want n changed=0
    ipset list -n 2>/dev/null | grep -qx "$BR_IPSET" || return 0
    want=$(_allow_nets)
    for n in $(cat "$f" 2>/dev/null); do
        echo "$want" | grep -qxF "$n" && continue
        _valid_ranges "$GEOIP_DIR/allowed_ranges.txt" 2>/dev/null | grep -qxF "$n" && continue
        ipset del -exist "$BR_IPSET" "$n" && changed=1 && echo "[+] Removed GeoIP exception: $n"
    done
    for n in $want; do
        ipset test "$BR_IPSET" "$n" >/dev/null 2>&1 && continue
        ipset add -exist "$BR_IPSET" "$n" && changed=1
    done
    printf '%s\n' $want | grep . > "$f.tmp" 2>/dev/null; mv -f "$f.tmp" "$f" 2>/dev/null || true
    if [ "$changed" = 1 ]; then
        save_ipset
        echo "[+] GeoIP exceptions (treated as in-country): $(echo $want)"
    fi
    return 0
}

ipset_count() {
    ipset list "$BR_IPSET" 2>/dev/null | grep -c '^[0-9]'
}

save_ipset() {
    ipset save "$BR_IPSET" > "$GEOIP_DIR/ipset.save.tmp" 2>/dev/null \
        && mv -f "$GEOIP_DIR/ipset.save.tmp" "$GEOIP_DIR/ipset.save"
}

# Delete every INPUT rule whose 'iptables -S' line matches the regex.
_ipt_del_matching() {
    local rule
    iptables -S INPUT 2>/dev/null | grep -E -- "$1" | while IFS= read -r rule; do
        eval "iptables -D ${rule#-A }" 2>/dev/null || true
    done
}

# Abort if the IP you're SSH'd in from would get blocked by the GeoIP rule.
_check_ssh_client() {
    local ip="${SSH_CLIENT%% *}" t
    [ -z "$ip" ] && return 0
    case "$ip" in *:*|127.*) return 0 ;; esac
    ipset test "$BR_IPSET" "$ip" >/dev/null 2>&1 && return 0
    for t in $TRUSTED_IPS $TRUNK_IPS; do [ "$t" = "$ip" ] && return 0; done
    if [ "${SIP_SHIELD_FORCE:-0}" = "1" ]; then
        echo "[!] WARNING: your SSH IP ($ip) is outside the allowed country — applying anyway (SIP_SHIELD_FORCE=1)"
        return 0
    fi
    echo "[!] ABORTED: your SSH IP ($ip) is not in the allowed country nor in TRUSTED_IPS."
    echo "    GeoIP would block your next connections. Add the IP to TRUSTED_IPS in"
    echo "    $CONF_FILE, or re-run with SIP_SHIELD_FORCE=1 if you're sure."
    return 1
}

# Desired top-of-INPUT rules, in 'iptables -S' form.
_desired_rules() {
    local ip
    echo "-A INPUT -i lo -j ACCEPT"
    for ip in $TRUNK_IPS $TRUSTED_IPS; do echo "-A INPUT -s $ip/32 -j ACCEPT"; done
    echo "-A INPUT -m state --state NEW -m set ! --match-set $BR_IPSET src -j DROP"
}

_EST_RE='^-A INPUT -m (state --state|conntrack --ctstate) RELATED,ESTABLISHED -j ACCEPT$'

_policy_accept() {
    iptables -S INPUT 2>/dev/null | grep -q '^-P INPUT ACCEPT'
}

# True if the desired block is already at the top (ignoring fail2ban jumps above
# it), with no stray copies below and no old ESTABLISHED ACCEPT punching bans.
_rules_already_ok() {
    local want have n
    want=$(_desired_rules)
    n=$(echo "$want" | wc -l)
    have=$(iptables -S INPUT 2>/dev/null | grep '^-A INPUT' | grep -vE -- '-j (f2b-|F2B_)')
    if _policy_accept && echo "$have" | grep -qE "$_EST_RE"; then return 1; fi
    [ "$(echo "$have" | head -n "$n")" = "$want" ] || return 1
    [ -z "$(echo "$have" | tail -n +"$((n + 1))" | grep -Fxf <(echo "$want"))" ] || return 1
    [ -z "$(echo "$have" | tail -n +"$((n + 1))" | grep -E "match-set $BR_IPSET src -j DROP")" ]
}

apply_iptables_rules() {
    local n ip pos=1
    n=$(ipset_count)
    if [ "${n:-0}" -lt "$MIN_RANGES" ]; then
        echo "[!] ipset $BR_IPSET has ${n:-0} ranges (min $MIN_RANGES) — rules NOT applied"
        return 1
    fi
    _check_ssh_client || return 1
    sync_allow_nets

    if _rules_already_ok; then
        echo "[+] GeoIP rules already correct at top of INPUT — nothing changed"
    else
        echo "[*] Applying GeoIP rules (all ports/protocols)..."
        # 1) Remove the DROP first (incl. the old per-port model), so a DROP never
        #    exists without the ACCEPT exceptions above it.
        _ipt_del_matching "match-set $BR_IPSET src -j DROP"
        # 2) Remove existing exceptions (incl. duplicates / old per-port trunk rule).
        _ipt_del_matching '^-A INPUT -i lo -j ACCEPT$'
        # Old-model ESTABLISHED ACCEPT: only remove with policy ACCEPT (with policy
        # DROP it may be needed by the rest of the firewall).
        if _policy_accept; then
            _ipt_del_matching "$_EST_RE"
        else
            echo "[!] INPUT policy is DROP: keeping existing ESTABLISHED rule"
        fi
        for ip in $TRUNK_IPS $TRUSTED_IPS; do
            _ipt_del_matching "^-A INPUT -s ${ip//./\\.}/32 .*-j ACCEPT$"
        done
        # 3) Reinsert at the top, in order.
        iptables -I INPUT $pos -i lo -j ACCEPT; pos=$((pos + 1))
        for ip in $TRUNK_IPS $TRUSTED_IPS; do
            iptables -I INPUT $pos -s "$ip" -j ACCEPT; pos=$((pos + 1))
        done
        iptables -I INPUT $pos -m state --state NEW -m set ! --match-set "$BR_IPSET" src -j DROP

        echo "[+] loopback allowed | trunks: ${TRUNK_IPS:-none} | trusted: ${TRUSTED_IPS:-none}"
        echo "[+] GeoIP active on ALL ports — new connections from outside ${SIP_SHIELD_COUNTRY} dropped"
    fi

    harden_mgmt_ports
    save_iptables_rules
}

# ─── Management-port hardening (defense in depth) ─────────────────────────────
# GeoIP filters by country, so an attacker inside the allowed country still
# reaches MySQL (3306) and AMI (5038). This drops NEW connections to those ports
# from anything except loopback — independent of country. Idempotent.
harden_mgmt_ports() {
    [ "${HARDEN_MGMT_PORTS:-1}" = "1" ] || { echo "[*] Management-port hardening disabled"; return 0; }
    local port
    for port in $MGMT_PORTS; do
        # Remove any previous copy first (idempotency), then insert just below the
        # GeoIP block so trunk/trusted ACCEPTs above still win for those IPs.
        _ipt_del_matching "^-A INPUT -p tcp -m tcp --dport ${port} ! -s 127\.0\.0\.1/32 .*-j DROP$"
        iptables -A INPUT -p tcp --dport "$port" ! -s 127.0.0.1 -m state --state NEW -j DROP
    done
    echo "[+] Management ports restricted to localhost: $MGMT_PORTS"
}

# Snapshot iptables WITHOUT fail2ban's chains: fail2ban recreates its own chains
# and re-applies bans (from its DB) on start. Saving its chains here would make
# bans "eternal" and conflict with fail2ban starting at boot.
save_iptables_rules() {
    local out="/etc/sysconfig/iptables"
    if [ ! -d /etc/sysconfig ]; then
        mkdir -p /etc/iptables
        out="/etc/iptables/rules.v4"
    fi
    iptables-save | grep -vE '^:(f2b-|F2B_)|-j (f2b-|F2B_)|^-A (f2b-|F2B_)' > "$out.tmp" \
        && mv -f "$out.tmp" "$out" && chmod 600 "$out"
}

install_restore_hook() {
    cat > "$GEOIP_DIR/restore.sh" << EOR
#!/bin/bash
# Generated by SIP Shield — do not edit. Called by rc.local at boot.
exec /bin/bash $INSTALL_DIR/lib/restore.sh
EOR
    chmod 755 "$GEOIP_DIR/restore.sh"
    local rc=/etc/rc.d/rc.local
    [ -e "$rc" ] || rc=/etc/rc.local
    [ -e "$rc" ] || printf '#!/bin/bash\ntouch /var/lock/subsys/local\n' > "$rc"
    grep -q "sip-shield/restore.sh" "$rc" || echo "$GEOIP_DIR/restore.sh" >> "$rc"
    chmod +x "$rc"
    echo "[+] Boot restore configured ($rc)"
}

install_cron() {
    local f=/etc/cron.d/sip-shield
    # Remove any old crontab entries that pointed at a git-clone path.
    sed -i '/sip-shield/d' /etc/crontab 2>/dev/null || true
    # Monthly range refresh, minute/hour randomized so a fleet doesn't hit RIPE
    # all at once.
    echo "$((RANDOM % 60)) $((2 + RANDOM % 4)) 1 * * root /bin/bash $INSTALL_DIR/lib/update.sh >> /var/log/sip-shield-update.log 2>&1" > "$f"
    # Metrics refresh every 5 minutes (Prometheus textfile).
    echo "*/5 * * * * root /bin/bash $INSTALL_DIR/lib/stats.sh --refresh-only >> /var/log/sip-shield-metrics.log 2>&1" >> "$f"
    chmod 644 "$f"
    echo "[+] Cron installed ($f): monthly range refresh + 5-min metrics refresh"
}

setup_geoip() {
    command -v ipset &>/dev/null && command -v python3 &>/dev/null && command -v curl &>/dev/null || install_dependencies
    if ! download_country_ranges; then
        [ -f "$GEOIP_DIR/allowed_ranges.txt" ] && echo "[*] Using existing ranges in $GEOIP_DIR/allowed_ranges.txt" \
            || { echo "[!] No ranges to load. Aborting without touching the firewall."; return 1; }
    fi
    load_ipset       || { echo "[!] Aborting without touching the firewall."; return 1; }
    save_ipset
    apply_iptables_rules || { echo "[!] Rules NOT applied."; return 1; }
    install_restore_hook
    install_cron
}
