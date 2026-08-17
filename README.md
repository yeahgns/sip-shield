🇺🇸 English | 🇧🇷 [Português](README.pt-br.md)

# SIP Shield

GeoIP + fail2ban protection for Issabel/Asterisk PBX servers. Blocks SIP traffic from outside a target country at the network layer, before Asterisk even sees the packet, and adds fail2ban as a second line of defense against brute-force attempts.

## Why this exists

VoIP servers exposed to the public internet get hit constantly by automated SIP scanning and brute-force registration attempts, most of it from infrastructure with no legitimate reason to talk to the PBX. Application-layer defenses like fail2ban alone only kick in after a number of failed attempts, so every attacker still gets to probe the server directly before being blocked. Filtering by country at the network layer removes most of that traffic before it reaches Asterisk. fail2ban handles what's left, including attackers from inside the allowed country.

## How it works

```
SIP request arrives
→ iptables checks: does the source IP belong to the target country?
  (matched against an ipset populated from RIPE NCC data)
  → No  → dropped immediately, Asterisk never sees it
  → Yes → forwarded to Asterisk
           → fail2ban watches for suspicious attempts
           → bans after N failures within a time window
```

## What it does

- **GeoIP via iptables/ipset**: blocks SIP traffic from outside a configurable target country
- **fail2ban**: second layer, bans brute-force attempts from anywhere, including the allowed country
- **Known-IPs pre-ban** (optional): a seed list of previously observed attacker IPs, banned at install time
- **Automatic updates**: the target country's IP ranges refresh monthly via RIPE NCC, since allocations change over time

## Compatibility

| System | Tested with |
|---|---|
| CentOS 7 | Issabel 4 |
| Rocky Linux 8 | Issabel 5 |

SIP port detection is automatic and doesn't assume any specific port. Works whether Asterisk is on the default `5060` or a custom port.

## Installation

```bash
git clone https://github.com/yeahgns/sip-shield.git
cd sip-shield
```

Configure your environment before running (see Configuration below), then:

```bash
sudo bash install.sh
```

## Configuration

Nothing in the scripts contains a real IP, hostname, or company name. Everything is set via environment variables before running. `SIP_SHIELD_COUNTRY` has no default and must be set explicitly, the install stops with an error if it's missing, so the target country is always a deliberate choice:

```bash
export SIP_SHIELD_COUNTRY="BR"                                  # required — ISO 3166-1 alpha-2 country code to allow
export SIP_SHIELD_WHITELIST_IPS="203.0.113.10,203.0.113.11"      # your SIP trunk provider(s), always allowed
export SIP_SHIELD_MAXRETRY="5"                                  # optional, fail2ban tuning
export SIP_SHIELD_FINDTIME="60"                                 # optional, seconds
export SIP_SHIELD_BANTIME="604800"                               # optional, seconds (default: 7 days)

sudo bash install.sh
```

If `SIP_SHIELD_WHITELIST_IPS` is left empty, no IP is exempt from the GeoIP/fail2ban rules. Set it if you have a SIP trunk provider outside the allowed country, otherwise your own trunk gets blocked.

### Known-IPs pre-ban (optional)

`lib/known-ips.txt.example` ships with a seed list of IPs previously observed attacking SIP servers in real deployments. It's a starting point, not a maintained blocklist. Attacker infrastructure changes constantly.

To enable this step:

```bash
cp lib/known-ips.txt.example lib/known-ips.txt
# edit lib/known-ips.txt with IPs relevant to your own logs, if you'd like
```

If `lib/known-ips.txt` doesn't exist, the install skips this step.

## Useful commands

```bash
# fail2ban status
fail2ban-client status asterisk

# how many country ranges are currently loaded
ipset list allowed_ranges | wc -l

# manually ban an IP
fail2ban-client set asterisk banip <IP>

# manually refresh the country's IP ranges
bash lib/update.sh

# view active GeoIP rules
iptables -L INPUT -n | grep allowed_ranges
```

## Updates

The target country's IP ranges refresh automatically on the 1st of every month at 03:00, via a cron entry created by `install.sh`. Logged to `/var/log/sip-shield-update.log`.

Manual refresh:

```bash
bash lib/update.sh
```

Ban/unban history is logged separately, to `/var/log/sip-shield.log`:

```
[2026-06-12 13:45:22] BAN ip=203.0.113.50 origin=known-ips-list
[2026-06-12 13:47:10] BAN ip=203.0.113.77 origin=fail2ban jail=asterisk
[2026-06-12 14:02:55] UNBAN ip=203.0.113.77 origin=fail2ban jail=asterisk
```

## Structure

```
sip-shield/
├── README.md
├── README.pt-br.md
├── install.sh
└── lib/
    ├── config.sh
    ├── detect.sh
    ├── fail2ban.sh
    ├── geoip.sh
    ├── metrics.sh
    ├── record-event.sh
    ├── stats.sh
    ├── update.sh
    └── known-ips.txt.example
```

## Observability

Three additive outputs — none of them change the blocking logic, and all are safe to leave disabled.

**Human-readable summary**

```bash
bash lib/stats.sh
```

```
SIP Shield
────────────────────────────────────────
Target country:        BR
SIP port:               5060
Allowed ranges loaded:  12927
Packets dropped:        128291
Data dropped:           9.37 MB
Currently banned (f2b): 7
Total bans logged:      42
────────────────────────────────────────
```

**Prometheus metrics**

Written automatically to `SIP_SHIELD_PROM_TEXTFILE_DIR` (default `/var/lib/sip-shield/metrics/sip_shield.prom`) on install, and refreshed every 5 minutes via a cron entry `install.sh` sets up. Point node_exporter's textfile collector at that directory and Prometheus picks the metrics up on its normal scrape interval — Grafana then reads from Prometheus, no separate Grafana integration needed:

```bash
export SIP_SHIELD_PROM_TEXTFILE_DIR="/var/lib/node_exporter/textfile_collector"  # example
```

Metrics exposed: `sip_shield_geoip_dropped_packets_total`, `sip_shield_geoip_dropped_bytes_total`, `sip_shield_allowed_country_ranges`, `sip_shield_fail2ban_banned_ips`, `sip_shield_known_ips_loaded`, `sip_shield_bans_logged_total`.

**JSON structured log**

Every ban/unban is also logged as one JSON object per line, alongside the existing plain-text log — pick this up with any log shipper or SIEM that can tail a file (Filebeat, Wazuh, Splunk forwarder, etc.):

```bash
export SIP_SHIELD_JSON_LOG="/var/log/sip-shield.jsonl"  # default shown
```

```json
{"timestamp":"2026-06-12T13:45:22Z","event":"ban","ip":"203.0.113.50","origin":"fail2ban"}
```

**Generic webhook**

Fires a JSON POST on every ban/unban if configured — works with Telegram (via a bot's `sendMessage`-compatible relay), Slack incoming webhooks, Discord webhooks, or any custom endpoint:

```bash
export SIP_SHIELD_WEBHOOK_URL="https://your-endpoint.example/webhook"
```

The webhook call is fire-and-forget: a failed or slow endpoint never blocks or delays the actual ban/unban.

## Configuration persistence

`install.sh` writes the resolved configuration to `/etc/sip-shield/config.env` (permissions `600`, since it may contain a webhook URL) at the end of a successful run. This exists because `lib/update.sh` (via cron) and the fail2ban ban/unban action don't inherit environment variables from your interactive shell — without this, both would silently fail to find `SIP_SHIELD_COUNTRY` outside of the install session. Environment variables in the current shell always take precedence over this file; it's purely a fallback for non-interactive contexts.

## Known limitations

- Country-level filtering is a blunt instrument. Legitimate users traveling abroad, or using a VPN/proxy, get blocked unless whitelisted individually. That trades some legitimate-traffic friction for a large reduction in attack surface, evaluate if that fits your use case.
- IP-to-country data (RIPE NCC, in this implementation) isn't perfectly precise or instantaneous. Ranges get reassigned between regions over time, which is why the monthly refresh exists, but there's always some lag.
- Tested specifically on Issabel over CentOS 7 and Rocky Linux 8. Other Asterisk-based distributions likely work with minor adjustments to `lib/detect.sh` and the package manager calls in `install.sh`.
- IPv4 only, in the current version.
- No per-attacker country breakdown ("top attacking countries") — this project only knows whether a packet's source *is or isn't* in the allowed country, not which country a blocked packet actually came from. That would require a full IP-to-country database (e.g. MaxMind GeoLite2) instead of RIPE NCC's single-country range list — a deliberate scope decision, not an oversight.
