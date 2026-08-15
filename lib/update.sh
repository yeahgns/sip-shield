#!/bin/bash

# Monthly update of the allowed country's IP ranges.
# Run via cron (configured automatically by install.sh).

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/detect.sh"
source "$SCRIPT_DIR/lib/geoip.sh"

echo "[$(date)] Starting update of allowed country ranges..."

download_country_ranges && create_ipset && save_ipset

echo "[$(date)] Update complete"
