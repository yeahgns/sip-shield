🇺🇸 English | 🇧🇷 [Português](README.pt-br.md)

# SIP Shield

Plug-and-play, network-layer protection for Issabel/Asterisk PBX servers. It blocks connections from outside a target country **on every port**, before Asterisk (or MySQL, or the web panel) ever sees the packet, adds fail2ban as a second layer against brute force, and hardens management ports (MySQL/AMI) to localhost. One installer, an interactive wizard, and a single `sip-shield` command to run it all.

## Why this exists

Public-facing VoIP servers are hit constantly by automated SIP scanning and brute-force registration, almost all of it from infrastructure with no legitimate reason to reach the PBX. Application-layer defenses like fail2ban only react after several failed attempts, so every attacker still gets to probe the box first. Filtering by country at the network layer removes most of that traffic up front; fail2ban handles what's left, including attackers from inside the allowed country; and management-port hardening closes the admin services (MySQL, Asterisk Manager Interface) that don't belong on the public internet at all — the exact class of exposure that motivated this project.

## How it works

```
New connection arrives (any port)
 → loopback? / trunk? / trusted IP?      → ACCEPT
 → source IP in the allowed country?      (ipset from RIPE NCC)
     → No  → DROP (Asterisk/MySQL/web never see it)
     → Yes → continue
              → MySQL/AMI from non-localhost?  → DROP (management hardening)
              → fail2ban watches for brute force → bans after N failures
```

The GeoIP block sits at the very top of `INPUT` and only matches **new** connections, so established traffic is never interrupted and attackers with a steady UDP flow can't slip past a ban.

## What it does

- **GeoIP via iptables/ipset, all ports** — blocks new connections from outside the target country on every port and protocol. Changing the SIP/PJSIP port later requires no reconfiguration.
- **Management-port hardening** — restricts MySQL (`3306`) and the Asterisk Manager Interface (`5038`) to localhost regardless of country, so an in-country attacker can't reach them either. On by default; configurable.
- **fail2ban** — second layer, bans brute-force attempts from anywhere, including the allowed country. Loopback, trunks and trusted IPs are never banned by any jail.
- **Atomic updates** — the target country's ranges refresh monthly via RIPE NCC using `ipset swap`, so there's never an unprotected window; if RIPE fails or returns a short list, the current ranges are kept.
- **Anti-lockout** — if the IP you're connected from via SSH would be blocked, the install aborts before touching the firewall (override with `SIP_SHIELD_FORCE=1`).
- **Known-IPs pre-ban** (optional) — seed a list of known-bad IPs to ban at install time.
- **Observability** — structured JSON log, generic webhook, and Prometheus textfile metrics. All additive, all optional.

## Compatibility

| System | Tested with |
|---|---|
| CentOS 7 | Issabel 4 |
| Rocky Linux 8 | Issabel 5 |

IPv4 only in the current version.

## Installation

```bash
git clone https://github.com/yeahgns/sip-shield.git
cd sip-shield
```

**Interactive wizard** (recommended for a single host):

```bash
sudo bash install.sh --wizard
```

The wizard asks for the target country, trunk/trusted/customer IPs, management-port hardening, optional webhook, and fail2ban tuning, shows a summary, and applies everything.

**Non-interactive** (automation / Ansible):

```bash
export SIP_SHIELD_COUNTRY="BR"                       # required, ISO 3166-1 alpha-2
export SIP_SHIELD_TRUNK_IPS="203.0.113.10"            # SIP trunk provider(s)
export SIP_SHIELD_TRUSTED_IPS="198.51.100.5"          # monitoring / admin box
sudo bash install.sh
```

The installer is idempotent — re-running it (including on hosts still on the old per-port model) migrates to the current model without duplicating rules. Everything installs to `/opt/sip-shield`, so the clone can be deleted afterward.

## The `sip-shield` command

Installed to `/usr/local/bin/sip-shield` — one entry point instead of remembering paths under `lib/`:

```bash
sip-shield status         # current state (country, ranges, drops, bans, hardening)
sip-shield update         # refresh country ranges now and re-apply rules
sip-shield ban <ip>       # ban an IP
sip-shield unban <ip>     # unban an IP
sip-shield banned         # list currently banned IPs
sip-shield test <ip>      # would this IP pass the GeoIP filter?
sip-shield ranges         # how many country ranges are loaded
sip-shield rules          # show the active SIP Shield iptables rules
sip-shield config         # edit per-host config, then reminds you to update
sip-shield logs [n]       # last n ban-log lines
sip-shield help
```

`sip-shield status` example:

```
SIP Shield
────────────────────────────────────────
Target country:         BR
Asterisk ports:         5060/udp 5061/tcp
Allowed ranges loaded:  12927
Packets dropped:        128291
Data dropped:           9.37 MB
Currently banned (f2b): 7
Total bans logged:      42
Mgmt-port hardening:    on (3306 5038)
────────────────────────────────────────
```

## Configuration

Per-host settings live in `/etc/sip-shield/sip-shield.conf`, created at install and **never overwritten** by a reinstall. Edit it directly (or via `sip-shield config`), then apply with `sip-shield update`.

| Key | Meaning |
|---|---|
| `SIP_SHIELD_COUNTRY` | ISO 3166-1 alpha-2 code of the country to allow. |
| `TRUNK_IPS` | SIP trunk / DID provider(s): allowed on everything, never banned. |
| `TRUSTED_IPS` | Management IPs outside the country: allowed on everything, never banned. |
| `F2B_IGNORE_IPS` | Fixed customer IPs: never banned, **but** still subject to GeoIP and management-port hardening. Use this, not `TRUSTED_IPS`, for a customer. |
| `GEOIP_ALLOW_NETS` | Foreign CIDRs treated as in-country (e.g. a messaging provider's PJSIP trunk). |
| `HARDEN_MGMT_PORTS` | `1` (default) restricts management ports to localhost; `0` disables. |
| `MGMT_PORTS` | Ports restricted to localhost (default `3306 5038`). |

Precedence: environment variables in the current shell > the config file > built-in defaults. This is what lets the same code run interactively, from Ansible, and from cron.

### Known-IPs pre-ban (optional)

```bash
cp lib/known-ips.txt.example lib/known-ips.txt
# edit with IPs from your own logs; if the file is absent, the step is skipped
```

## Observability

Three additive outputs — none change the blocking logic, all safe to leave off.

**Prometheus** — a `.prom` textfile is written on install and refreshed every 5 minutes by cron. Point node_exporter's textfile collector at `SIP_SHIELD_PROM_TEXTFILE_DIR` (default `/var/lib/sip-shield/metrics`) and Prometheus scrapes it normally; Grafana reads from Prometheus. Metrics: `sip_shield_geoip_dropped_packets_total`, `sip_shield_geoip_dropped_bytes_total`, `sip_shield_allowed_country_ranges`, `sip_shield_fail2ban_banned_ips`, `sip_shield_known_ips_loaded`, `sip_shield_bans_logged_total`, `sip_shield_mgmt_ports_hardened`.

**JSON log** — every ban/unban as one JSON object per line, for any log shipper/SIEM:

```json
{"timestamp":"2026-06-12T13:45:22Z","event":"ban","ip":"203.0.113.50","origin":"fail2ban"}
```

**Webhook** — fire-and-forget JSON POST on ban/unban (Telegram/Slack/Discord/custom). A slow or failed endpoint never delays the actual ban:

```bash
export SIP_SHIELD_WEBHOOK_URL="https://your-endpoint.example/webhook"
```

## Files

| Path | What it is |
|---|---|
| `/opt/sip-shield/` | installed code |
| `/usr/local/bin/sip-shield` | the central command |
| `/etc/sip-shield/sip-shield.conf` | per-host config (never overwritten) |
| `/etc/sip-shield/allowed_ranges.txt` | downloaded country ranges |
| `/etc/sip-shield/ipset.save` | ipset snapshot for boot |
| `/etc/sip-shield/restore.sh` | called by `rc.local` at boot |
| `/etc/cron.d/sip-shield` | monthly range refresh + 5-min metrics refresh |
| `/var/log/sip-shield.log` | ban/unban log |
| `/var/log/sip-shield.jsonl` | structured JSON events |

## Known limitations

- Country filtering is a blunt instrument: legitimate users traveling abroad or on a VPN get blocked unless whitelisted. That trades some friction for a large cut in attack surface.
- IP-to-country data (RIPE NCC here) isn't perfectly precise or instant; the monthly refresh reduces, but doesn't eliminate, lag.
- No per-attacker country breakdown — this project only knows whether a source **is or isn't** in the allowed country, not which country a blocked packet came from. That would need a full IP-to-country database (e.g. MaxMind GeoLite2) rather than RIPE's single-country list.
- Tested on Issabel over CentOS 7 and Rocky Linux 8; other Asterisk distros likely need small tweaks to `lib/detect.sh` and the package-manager calls.

## License

MIT — see [LICENSE](LICENSE).
