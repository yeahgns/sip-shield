#!/bin/bash
# ============================================================
#  record-event.sh — Standalone event recorder, callable by
#  fail2ban's action.d config directly (fail2ban actions run
#  as plain shell commands, they don't source our functions).
#
#  Usage: bash record-event.sh <ban|unban> <ip> <origin>
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$SCRIPT_DIR/lib/config.sh" 2>/dev/null || true
source "$SCRIPT_DIR/lib/metrics.sh"

record_event "$1" "$2" "${3:-fail2ban}"
