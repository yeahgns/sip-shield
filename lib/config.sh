#!/bin/bash
# ============================================================================
#  config.sh — Central configuration for SIP Shield.
#
#  Defaults live here. Per-host overrides go in the config file written at
#  install time (CONF_FILE below), which is created once and NEVER overwritten
#  by a reinstall — so upgrading the code never clobbers a host's settings.
#
#  Precedence (highest first):
#    1. Environment variables exported in the current shell
#    2. The persisted config file (CONF_FILE)
#    3. The defaults in this file
#
#  Nothing here is a real production value. Set your own via the wizard
#  (bash install.sh --wizard) or by exporting SIP_SHIELD_* variables before
#  running install.sh non-interactively.
# ============================================================================

# ─── Paths ──────────────────────────────────────────────────────────────────
GEOIP_DIR="/etc/sip-shield"          # runtime state (ranges, ipset save, config)
INSTALL_DIR="/opt/sip-shield"        # where the code is installed (cron/boot use this)
CONF_FILE="$GEOIP_DIR/sip-shield.conf"
BR_IPSET="allowed_ranges"            # ipset holding the allowed country's ranges

# ─── Country ──────────────────────────────────────────────────────────────────
# ISO 3166-1 alpha-2 code of the country whose IP ranges are allowed. Everything
# else is dropped at the network layer. No default on purpose: the target country
# must always be a deliberate choice. install.sh aborts if this is unset.
SIP_SHIELD_COUNTRY="${SIP_SHIELD_COUNTRY:-}"

# RIPE NCC country resource list (built from SIP_SHIELD_COUNTRY at load time).
RIPE_URL="${SIP_SHIELD_RIPE_URL:-https://stat.ripe.net/data/country-resource-list/data.json?resource=}"

# ─── Allow-lists ──────────────────────────────────────────────────────────────
# TRUNK_IPS      : SIP trunk / DID provider(s). Allowed on EVERYTHING (any port,
#                  any protocol) and never banned by any fail2ban jail.
# TRUSTED_IPS    : management IPs (monitoring, your own admin box) outside the
#                  allowed country. Allowed on everything, never banned.
# F2B_IGNORE_IPS : fixed customer IPs. Never banned by fail2ban, but NOT exempted
#                  in the firewall — still subject to GeoIP and management-port
#                  hardening. Use this, never TRUSTED_IPS, for a customer's IP.
TRUNK_IPS="${SIP_SHIELD_TRUNK_IPS:-}"
TRUSTED_IPS="${SIP_SHIELD_TRUSTED_IPS:-}"
F2B_IGNORE_IPS="${SIP_SHIELD_F2B_IGNORE_IPS:-}"

# Foreign networks treated AS IF they were in the allowed country: added to the
# ipset, so they follow the same rules as any in-country IP (fail2ban and
# management-port hardening still apply). Empty by default. A common use is a
# messaging provider's PJSIP trunk range that lives outside your country.
GEOIP_ALLOW_NETS="${SIP_SHIELD_GEOIP_ALLOW_NETS:-}"

# ─── Management-port hardening (defense in depth) ─────────────────────────────
# GeoIP blocks by country, so an attacker INSIDE the allowed country still reaches
# MySQL/AMI. This restricts those admin ports to localhost regardless of country.
# On by default — it's the vector that caused the real incident this project grew
# out of. Set to 0 to disable.
HARDEN_MGMT_PORTS="${SIP_SHIELD_HARDEN_MGMT_PORTS:-1}"
# Space-separated TCP ports to restrict to loopback only. 3306 = MySQL/MariaDB,
# 5038 = Asterisk Manager Interface (AMI). Add others if you expose more.
MGMT_PORTS="${SIP_SHIELD_MGMT_PORTS:-3306 5038}"

# ─── fail2ban tuning ──────────────────────────────────────────────────────────
SIP_SHIELD_MAXRETRY="${SIP_SHIELD_MAXRETRY:-5}"
SIP_SHIELD_FINDTIME="${SIP_SHIELD_FINDTIME:-60}"
SIP_SHIELD_BANTIME="${SIP_SHIELD_BANTIME:-604800}"   # 7 days, seconds

# Optional file of known-bad IPs, pre-banned at install time. One IP per line,
# '#' comments ignored. See lib/known-ips.txt.example.
SIP_SHIELD_KNOWN_IPS_FILE="${SIP_SHIELD_KNOWN_IPS_FILE:-$INSTALL_DIR/lib/known-ips.txt}"

# Never apply the DROP with fewer ranges than this — guards against wiping out
# the whole country's access if RIPE returns an empty/broken response.
MIN_RANGES="${SIP_SHIELD_MIN_RANGES:-5000}"

# ─── Observability (all optional, all safe to leave at defaults) ──────────────
SIP_SHIELD_JSON_LOG="${SIP_SHIELD_JSON_LOG:-/var/log/sip-shield.jsonl}"
SIP_SHIELD_WEBHOOK_URL="${SIP_SHIELD_WEBHOOK_URL:-}"
SIP_SHIELD_PROM_TEXTFILE_DIR="${SIP_SHIELD_PROM_TEXTFILE_DIR:-/var/lib/sip-shield/metrics}"

# ─── Helpers ──────────────────────────────────────────────────────────────────

# Load the persisted per-host config, without letting it clobber values already
# set in the environment. We snapshot the env-provided values, source the file,
# then restore the snapshots so env always wins.
load_config() {
    [ -f "$CONF_FILE" ] || return 0
    local _env_country="$SIP_SHIELD_COUNTRY"
    local _env_trunk="$SIP_SHIELD_TRUNK_IPS" _env_trusted="$SIP_SHIELD_TRUSTED_IPS"
    local _env_f2b="$SIP_SHIELD_F2B_IGNORE_IPS" _env_allow="$SIP_SHIELD_GEOIP_ALLOW_NETS"
    # shellcheck disable=SC1090
    . "$CONF_FILE"
    [ -n "$_env_country" ] && SIP_SHIELD_COUNTRY="$_env_country"
    [ -n "$_env_trunk" ]   && TRUNK_IPS="$_env_trunk"
    [ -n "$_env_trusted" ] && TRUSTED_IPS="$_env_trusted"
    [ -n "$_env_f2b" ]     && F2B_IGNORE_IPS="$_env_f2b"
    [ -n "$_env_allow" ]   && GEOIP_ALLOW_NETS="$_env_allow"
    return 0
}

# Full RIPE URL for the configured country.
ripe_url() { echo "${RIPE_URL}${SIP_SHIELD_COUNTRY}"; }

# Write the per-host config file once. Never overwrites an existing file.
write_default_config() {
    [ -f "$CONF_FILE" ] && return 0
    mkdir -p "$GEOIP_DIR"
    cat > "$CONF_FILE" << EOC
# SIP Shield — per-host configuration. NOT overwritten by reinstall/upgrade.
# Separate multiple IPs with spaces. After editing: bash $INSTALL_DIR/lib/update.sh

# ISO 3166-1 alpha-2 code of the country to allow (e.g. BR, US, PT).
SIP_SHIELD_COUNTRY="$SIP_SHIELD_COUNTRY"

# SIP trunk / DID provider(s): allowed on everything, never banned.
TRUNK_IPS="$TRUNK_IPS"

# Management IPs outside the allowed country (monitoring, admin box):
# allowed on everything, never banned.
TRUSTED_IPS="$TRUSTED_IPS"

# Fixed customer IPs: never banned by fail2ban, but still subject to GeoIP
# and management-port hardening (do NOT put these in TRUSTED_IPS).
F2B_IGNORE_IPS="$F2B_IGNORE_IPS"

# Foreign networks treated as in-country by GeoIP (added to the ipset).
# To disable on this host, leave empty. Example: a messaging provider's
# PJSIP trunk range: GEOIP_ALLOW_NETS="203.0.113.0/24 198.51.100.0/24"
GEOIP_ALLOW_NETS="$GEOIP_ALLOW_NETS"

# Restrict management ports (MySQL 3306, AMI 5038) to localhost regardless of
# country. 1 = on (recommended), 0 = off.
HARDEN_MGMT_PORTS="$HARDEN_MGMT_PORTS"
MGMT_PORTS="$MGMT_PORTS"

# fail2ban tuning
SIP_SHIELD_MAXRETRY="$SIP_SHIELD_MAXRETRY"
SIP_SHIELD_FINDTIME="$SIP_SHIELD_FINDTIME"
SIP_SHIELD_BANTIME="$SIP_SHIELD_BANTIME"

# Observability (optional). Webhook empty = disabled.
SIP_SHIELD_JSON_LOG="$SIP_SHIELD_JSON_LOG"
SIP_SHIELD_WEBHOOK_URL="$SIP_SHIELD_WEBHOOK_URL"
SIP_SHIELD_PROM_TEXTFILE_DIR="$SIP_SHIELD_PROM_TEXTFILE_DIR"
EOC
    chmod 600 "$CONF_FILE"   # may hold a webhook URL; treat as sensitive
    echo "[+] Config created: $CONF_FILE"
}

# Space-separated whitelist arrays as a stream (one per line).
whitelist_ips() { printf '%s\n' $TRUNK_IPS $TRUSTED_IPS | grep . || true; }
