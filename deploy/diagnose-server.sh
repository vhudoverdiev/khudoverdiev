#!/usr/bin/env bash
set -uo pipefail

APP_DIR="${APP_DIR:-/opt/khudoverdiev}"
SERVICE="${SERVICE:-khudoverdiev.service}"
DOMAINS=(
  khudoverdiev.ru
  www.khudoverdiev.ru
  it.khudoverdiev.ru
  ph.khudoverdiev.ru
)

section() {
  printf '\n===== %s =====\n' "$*"
}

run() {
  printf '+ %s\n' "$*"
  "$@" || true
}

section "Host"
run hostname
run whoami
run date

section "Project"
run test -d "$APP_DIR"
if [[ -d "$APP_DIR" ]]; then
  run git -C "$APP_DIR" status --short --branch
  run git -C "$APP_DIR" log --oneline -3
  run ls -la "$APP_DIR"
fi

section "Python"
run test -x "$APP_DIR/venv/bin/python"
if [[ -x "$APP_DIR/venv/bin/python" ]]; then
  run "$APP_DIR/venv/bin/python" --version
  run "$APP_DIR/venv/bin/python" -m pip show flask gunicorn
  run "$APP_DIR/venv/bin/python" -m compileall -q "$APP_DIR/app.py"
fi

section "Systemd"
run systemctl status "$SERVICE" --no-pager
run journalctl -u "$SERVICE" -n 120 --no-pager

section "Ports"
run ss -ltnp

section "Nginx"
run nginx -t
run systemctl status nginx --no-pager
run ls -la /etc/nginx/sites-enabled

section "Local Health"
run curl -i --max-time 10 http://127.0.0.1:8000/health

section "Domains"
for domain in "${DOMAINS[@]}"; do
  run getent hosts "$domain"
  run curl -I --max-time 10 "http://$domain/"
done
