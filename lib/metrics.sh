#!/bin/bash
# ============================================================================
#  metrics.sh — Observability layer. Three additive outputs, none of which
#  change the blocking logic:
#    1. Structured JSON log (one event per line) — for any SIEM/log shipper.
#    2. Generic webhook POST on ban/unban — Telegram/Slack/Discord/custom.
#    3. Prometheus textfile metrics — node_exporter -> Prometheus -> Grafana.
# ============================================================================

JSON_LOG_FILE="${SIP_SHIELD_JSON_LOG:-/var/log/sip-shield.jsonl}"
WEBHOOK_URL="${SIP_SHIELD_WEBHOOK_URL:-}"
PROM_TEXTFILE_DIR="${SIP_SHIELD_PROM_TEXTFILE_DIR:-/var/lib/sip-shield/metrics}"
PROM_TEXTFILE="${PROM_TEXTFILE_DIR}/sip_shield.prom"

# ─── JSON structured logging ────────────────────────────────────────────────
log_json_event() {
    local event_type="$1" ip="$2" origin="${3:-manual}" timestamp
    timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    mkdir -p "$(dirname "$JSON_LOG_FILE")" 2>/dev/null || true
    printf '{"timestamp":"%s","event":"%s","ip":"%s","origin":"%s"}\n' \
        "$timestamp" "$event_type" "$ip" "$origin" >> "$JSON_LOG_FILE"
}

# ─── Generic webhook (fire-and-forget) ──────────────────────────────────────
send_webhook_event() {
    local event_type="$1" ip="$2" origin="${3:-manual}"
    [[ -z "$WEBHOOK_URL" ]] && return 0
    local timestamp payload
    timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    payload=$(printf '{"timestamp":"%s","event":"%s","ip":"%s","origin":"%s","host":"%s"}' \
        "$timestamp" "$event_type" "$ip" "$origin" "$(hostname)")
    (curl -s -m 5 -X POST -H "Content-Type: application/json" \
        -d "$payload" "$WEBHOOK_URL" > /dev/null 2>&1 &) || true
}

# ─── Combined hook (single call site for fail2ban.sh) ───────────────────────
record_event() {
    local event_type="$1" ip="$2" origin="${3:-manual}"
    log_json_event "$event_type" "$ip" "$origin"
    send_webhook_event "$event_type" "$ip" "$origin"
}

# ─── Prometheus textfile exporter ───────────────────────────────────────────
write_prometheus_metrics() {
    mkdir -p "$PROM_TEXTFILE_DIR" 2>/dev/null || {
        echo "[!] Could not create $PROM_TEXTFILE_DIR — check permissions" >&2
        return 1
    }

    local sip_ports dropped_packets dropped_bytes allowed_ranges banned_ips known_ips_loaded
    sip_ports=$(detect_asterisk_ports)

    local rule_stats
    rule_stats=$(iptables -L INPUT -v -n -x 2>/dev/null | grep "match-set ${BR_IPSET} src" | grep DROP | head -1)
    dropped_packets=$(echo "$rule_stats" | awk '{print $1}')
    dropped_bytes=$(echo "$rule_stats" | awk '{print $2}')
    dropped_packets="${dropped_packets:-0}"
    dropped_bytes="${dropped_bytes:-0}"

    allowed_ranges=$(ipset list "$BR_IPSET" 2>/dev/null | grep -c "^[0-9]" || echo 0)

    banned_ips=$(fail2ban-client status asterisk 2>/dev/null \
        | grep "Currently banned:" | grep -oE '[0-9]+' | head -1)
    banned_ips="${banned_ips:-0}"

    if [[ -f "$SIP_SHIELD_KNOWN_IPS_FILE" ]]; then
        known_ips_loaded=$(grep -cvE '^\s*(#|$)' "$SIP_SHIELD_KNOWN_IPS_FILE" 2>/dev/null || echo 0)
    else
        known_ips_loaded=0
    fi

    local total_bans_logged=0
    if [[ -f "$JSON_LOG_FILE" ]]; then
        total_bans_logged=$(grep -c '"event":"ban"' "$JSON_LOG_FILE" 2>/dev/null || echo 0)
    fi

    # Management-port hardening: 1 if all configured ports have the localhost-only
    # DROP present, 0 otherwise.
    local mgmt_hardened=1 port
    if [[ "${HARDEN_MGMT_PORTS:-1}" == "1" ]]; then
        for port in $MGMT_PORTS; do
            iptables -S INPUT 2>/dev/null | grep -qE -- "--dport ${port} ! -s 127\.0\.0\.1/32 .*-j DROP" || mgmt_hardened=0
        done
    else
        mgmt_hardened=0
    fi

    local tmpfile
    tmpfile=$(mktemp)
    cat > "$tmpfile" << METRICS
# HELP sip_shield_geoip_dropped_packets_total Packets dropped by the GeoIP rule (cumulative since the rule was last recreated).
# TYPE sip_shield_geoip_dropped_packets_total counter
sip_shield_geoip_dropped_packets_total ${dropped_packets}

# HELP sip_shield_geoip_dropped_bytes_total Bytes dropped by the GeoIP rule (cumulative since the rule was last recreated).
# TYPE sip_shield_geoip_dropped_bytes_total counter
sip_shield_geoip_dropped_bytes_total ${dropped_bytes}

# HELP sip_shield_allowed_country_ranges Number of IP ranges currently loaded in the allowed-country ipset.
# TYPE sip_shield_allowed_country_ranges gauge
sip_shield_allowed_country_ranges{country="${SIP_SHIELD_COUNTRY}"} ${allowed_ranges}

# HELP sip_shield_fail2ban_banned_ips Number of IPs currently banned in the asterisk fail2ban jail.
# TYPE sip_shield_fail2ban_banned_ips gauge
sip_shield_fail2ban_banned_ips ${banned_ips}

# HELP sip_shield_known_ips_loaded Number of known-bad IPs in the known-ips file.
# TYPE sip_shield_known_ips_loaded gauge
sip_shield_known_ips_loaded ${known_ips_loaded}

# HELP sip_shield_bans_logged_total Total ban events recorded in the JSON log.
# TYPE sip_shield_bans_logged_total counter
sip_shield_bans_logged_total ${total_bans_logged}

# HELP sip_shield_mgmt_ports_hardened 1 if management ports (MySQL/AMI) are restricted to localhost, else 0.
# TYPE sip_shield_mgmt_ports_hardened gauge
sip_shield_mgmt_ports_hardened ${mgmt_hardened}

# HELP sip_shield_metrics_last_updated_timestamp_seconds Unix time of the last metrics refresh.
# TYPE sip_shield_metrics_last_updated_timestamp_seconds gauge
sip_shield_metrics_last_updated_timestamp_seconds $(date +%s)
METRICS

    mv "$tmpfile" "$PROM_TEXTFILE"
}
