#!/bin/bash
# ============================================================================
#  wizard.sh — Interactive setup. Sourced by install.sh when run with --wizard.
#  Populates the SIP_SHIELD_* / *_IPS variables in the current shell, then
#  install.sh persists them via write_default_config().
#
#  Every prompt has a sensible default shown in [brackets]; pressing Enter
#  accepts it. Nothing here contacts the network — it only gathers answers.
# ============================================================================

_ask() {
    # _ask "Prompt" "default" -> echoes the answer
    local prompt="$1" default="$2" ans
    if [ -n "$default" ]; then
        read -r -p "$prompt [$default]: " ans
        echo "${ans:-$default}"
    else
        read -r -p "$prompt: " ans
        echo "$ans"
    fi
}

_ask_yn() {
    # _ask_yn "Prompt" "Y|N" -> returns 0 for yes, 1 for no
    local prompt="$1" default="$2" ans
    read -r -p "$prompt [$([ "$default" = Y ] && echo 'Y/n' || echo 'y/N')]: " ans
    ans="${ans:-$default}"
    case "$ans" in [Yy]*) return 0 ;; *) return 1 ;; esac
}

run_wizard() {
    echo ""
    echo "──────────────────────────────────────────────"
    echo "  SIP Shield — interactive setup"
    echo "──────────────────────────────────────────────"
    echo "Press Enter to accept the [default] shown for each question."
    echo ""

    # Country (required, no default)
    while :; do
        SIP_SHIELD_COUNTRY=$(_ask "Country to ALLOW (ISO 3166-1 alpha-2, e.g. BR, US, PT)" "${SIP_SHIELD_COUNTRY}")
        SIP_SHIELD_COUNTRY=$(echo "$SIP_SHIELD_COUNTRY" | tr '[:lower:]' '[:upper:]')
        [[ "$SIP_SHIELD_COUNTRY" =~ ^[A-Z]{2}$ ]] && break
        echo "  ! Please enter a two-letter country code."
    done

    echo ""
    echo "SIP trunk / DID provider IP(s) — allowed on everything, never banned."
    echo "Space-separated. Leave empty if you don't have an external trunk."
    TRUNK_IPS=$(_ask "  Trunk IPs" "$TRUNK_IPS")

    echo ""
    echo "Management IP(s) OUTSIDE the allowed country (your admin box, monitoring)."
    echo "Allowed on everything, never banned. Space-separated."
    TRUSTED_IPS=$(_ask "  Trusted IPs" "$TRUSTED_IPS")

    echo ""
    echo "Fixed CUSTOMER IP(s) — never banned by fail2ban, but still subject to"
    echo "GeoIP and management-port hardening. Space-separated."
    F2B_IGNORE_IPS=$(_ask "  Customer IPs (f2b-ignore)" "$F2B_IGNORE_IPS")

    echo ""
    echo "Foreign networks to treat AS in-country (e.g. a messaging provider's"
    echo "PJSIP trunk range). Space-separated CIDRs. Leave empty for none."
    GEOIP_ALLOW_NETS=$(_ask "  Allow-nets" "$GEOIP_ALLOW_NETS")

    echo ""
    if _ask_yn "Restrict management ports (MySQL 3306 / AMI 5038) to localhost?" "Y"; then
        HARDEN_MGMT_PORTS=1
        MGMT_PORTS=$(_ask "  Ports to restrict" "${MGMT_PORTS:-3306 5038}")
    else
        HARDEN_MGMT_PORTS=0
    fi

    echo ""
    if _ask_yn "Configure a webhook for ban/unban notifications (Telegram/Slack/etc.)?" "N"; then
        SIP_SHIELD_WEBHOOK_URL=$(_ask "  Webhook URL" "$SIP_SHIELD_WEBHOOK_URL")
    fi

    echo ""
    echo "fail2ban tuning (Enter to keep defaults):"
    SIP_SHIELD_MAXRETRY=$(_ask "  Max retries before ban" "${SIP_SHIELD_MAXRETRY:-5}")
    SIP_SHIELD_FINDTIME=$(_ask "  Find window (seconds)" "${SIP_SHIELD_FINDTIME:-60}")
    SIP_SHIELD_BANTIME=$(_ask "  Ban time (seconds)" "${SIP_SHIELD_BANTIME:-604800}")

    echo ""
    echo "──────────────────────────────────────────────"
    echo "  Summary"
    echo "──────────────────────────────────────────────"
    echo "  Country              : $SIP_SHIELD_COUNTRY"
    echo "  Trunk IPs            : ${TRUNK_IPS:-<none>}"
    echo "  Trusted IPs          : ${TRUSTED_IPS:-<none>}"
    echo "  Customer IPs         : ${F2B_IGNORE_IPS:-<none>}"
    echo "  Allow-nets           : ${GEOIP_ALLOW_NETS:-<none>}"
    echo "  Harden mgmt ports    : $([ "$HARDEN_MGMT_PORTS" = 1 ] && echo "yes ($MGMT_PORTS)" || echo no)"
    echo "  Webhook              : ${SIP_SHIELD_WEBHOOK_URL:-<none>}"
    echo "  fail2ban             : maxretry=$SIP_SHIELD_MAXRETRY findtime=$SIP_SHIELD_FINDTIME bantime=$SIP_SHIELD_BANTIME"
    echo "──────────────────────────────────────────────"
    echo ""
    if ! _ask_yn "Proceed with these settings?" "Y"; then
        echo "[!] Aborted by user."
        exit 1
    fi
    # Export so the rest of install.sh (and write_default_config) sees them.
    export SIP_SHIELD_COUNTRY TRUNK_IPS TRUSTED_IPS F2B_IGNORE_IPS GEOIP_ALLOW_NETS
    export HARDEN_MGMT_PORTS MGMT_PORTS SIP_SHIELD_WEBHOOK_URL
    export SIP_SHIELD_MAXRETRY SIP_SHIELD_FINDTIME SIP_SHIELD_BANTIME
}
