#!/bin/bash
# ============================================================
#  metrics.sh — Observability layer for SIP Shield.
#
#  Three independent outputs, each optional and additive —
#  none of this changes the blocking logic itself:
#
#   1. Structured JSON log (one event per line), for any SIEM
#      or log shipper that can tail a file.
#   2. Generic webhook POST on ban/unban events, for Telegram,
#      Slack, Discord, or any endpoint that accepts JSON.
#   3. Prometheus textfile metrics, consumable by node_exporter
#      and, from there, any Grafana dashboard.
# ============================================================

JSON_LOG_FILE="${SIP_SHIELD_JSON_LOG:-/var/log/sip-shield.jsonl}"
WEBHOOK_URL="${SIP_SHIELD_WEBHOOK_URL:-}"
PROM_TEXTFILE_DIR="${SIP_SHIELD_PROM_TEXTFILE_DIR:-/var/lib/sip-shield/metrics}"
PROM_TEXTFILE="${PROM_TEXTFILE_DIR}/sip_shield.prom"

# ─── JSON structured logging ────────────────────────────────────────────────
# Called alongside the existing plain-text log_ban(), never instead of it —
# the plain log stays as the human-readable source of truth.

log_json_event() {
    local event_type="$1"   # "ban" or "unban"
    local ip="$2"
    local origin="${3:-manual}"
    local timestamp
    timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

    mkdir -p "$(dirname "$JSON_LOG_FILE")" 2>/dev/null || true

    printf '{"timestamp":"%s","event":"%s","ip":"%s","origin":"%s"}\n' \
        "$timestamp" "$event_type" "$ip" "$origin" >> "$JSON_LOG_FILE"
}

# ─── Generic webhook notification ───────────────────────────────────────────
# Fires on ban/unban if SIP_SHIELD_WEBHOOK_URL is set. Works with any
# endpoint that accepts a JSON POST — Telegram bot API, Slack incoming
# webhook, Discord webhook, or a custom listener all qualify.
#
# Deliberately fire-and-forget: a webhook failure must never block or
# slow down the actual ban/unban action, so this always backgrounds the
# curl call and swallows its exit code.

send_webhook_event() {
    local event_type="$1" ip="$2" origin="${3:-manual}"

    [[ -z "$WEBHOOK_URL" ]] && return 0

    local timestamp
    timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    local payload
    payload=$(printf '{"timestamp":"%s","event":"%s","ip":"%s","origin":"%s","host":"%s"}' \
        "$timestamp" "$event_type" "$ip" "$origin" "$(hostname)")

    (curl -s -m 5 -X POST -H "Content-Type: application/json" \
        -d "$payload" "$WEBHOOK_URL" > /dev/null 2>&1 &) || true
}

# ─── Combined hook, called from fail2ban.sh's log_ban() ────────────────────
# Single entry point so fail2ban.sh doesn't need to know about JSON logging
# or webhooks individually — adding a fourth output later only means
# changing this function, not every call site.

record_event() {
    local event_type="$1" ip="$2" origin="${3:-manual}"
    log_json_event "$event_type" "$ip" "$origin"
    send_webhook_event "$event_type" "$ip" "$origin"
}

# ─── Prometheus textfile exporter ───────────────────────────────────────────
# Writes a .prom file in node_exporter's textfile collector format.
# Point node_exporter's --collector.textfile.directory at
# SIP_SHIELD_PROM_TEXTFILE_DIR (or symlink this file into it) and
# Prometheus picks the metrics up on its normal scrape interval.
# Grafana then reads from Prometheus — no separate Grafana integration
# is needed.

write_prometheus_metrics() {
    mkdir -p "$PROM_TEXTFILE_DIR" 2>/dev/null || {
        echo "[!] Could not create $PROM_TEXTFILE_DIR — check permissions" >&2
        return 1
    }

    local sip_port dropped_packets dropped_bytes allowed_ranges banned_ips known_ips_loaded
    sip_port=$(detect_sip_port)

    # Packet/byte counters come straight from the kernel's iptables
    # accounting for the GeoIP DROP rule — this is a live, cumulative
    # counter since the rule was last (re)created, not an estimate.
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

    local tmpfile
    tmpfile=$(mktemp)
    cat > "$tmpfile" << METRICS
# HELP sip_shield_geoip_dropped_packets_total Total UDP packets dropped by the GeoIP rule for the SIP port (cumulative since the rule was last recreated).
# TYPE sip_shield_geoip_dropped_packets_total counter
sip_shield_geoip_dropped_packets_total{port="${sip_port}"} ${dropped_packets}

# HELP sip_shield_geoip_dropped_bytes_total Total bytes dropped by the GeoIP rule for the SIP port (cumulative since the rule was last recreated).
# TYPE sip_shield_geoip_dropped_bytes_total counter
sip_shield_geoip_dropped_bytes_total{port="${sip_port}"} ${dropped_bytes}

# HELP sip_shield_allowed_country_ranges Number of IP ranges currently loaded in the allowed-country ipset.
# TYPE sip_shield_allowed_country_ranges gauge
sip_shield_allowed_country_ranges{country="${SIP_SHIELD_COUNTRY}"} ${allowed_ranges}

# HELP sip_shield_fail2ban_banned_ips Number of IPs currently banned in the asterisk fail2ban jail.
# TYPE sip_shield_fail2ban_banned_ips gauge
sip_shield_fail2ban_banned_ips ${banned_ips}

# HELP sip_shield_known_ips_loaded Number of known-bad IPs loaded from the known-ips file at last install/update.
# TYPE sip_shield_known_ips_loaded gauge
sip_shield_known_ips_loaded ${known_ips_loaded}

# HELP sip_shield_bans_logged_total Total ban events recorded in the JSON log since it was created.
# TYPE sip_shield_bans_logged_total counter
sip_shield_bans_logged_total ${total_bans_logged}

# HELP sip_shield_metrics_last_updated_timestamp_seconds Unix timestamp of the last time these metrics were refreshed.
# TYPE sip_shield_metrics_last_updated_timestamp_seconds gauge
sip_shield_metrics_last_updated_timestamp_seconds $(date +%s)
METRICS

    # Atomic move — node_exporter's textfile collector reads whatever file
    # is there at scrape time, so a partial write mid-scrape would show
    # incomplete metrics. Writing to a tmpfile and moving avoids that.
    mv "$tmpfile" "$PROM_TEXTFILE"
}
