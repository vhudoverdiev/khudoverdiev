#!/usr/bin/env bash
set -Eeuo pipefail

EMAIL="${EMAIL:-vhudoverdiev@gmail.com}"
DOMAINS=(
  khudoverdiev.ru
  www.khudoverdiev.ru
  it.khudoverdiev.ru
  ph.khudoverdiev.ru
  phh.khudoverdiev.ru
)

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

fail() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

[[ "$(id -u)" -eq 0 ]] || fail "run this script as root"

log "installing certbot"
apt-get update
apt-get install -y certbot python3-certbot-nginx

log "checking nginx config"
nginx -t
systemctl reload nginx

certbot_args=(--nginx --non-interactive --agree-tos --redirect --email "$EMAIL")
for domain in "${DOMAINS[@]}"; do
  certbot_args+=(-d "$domain")
done

log "requesting certificates"
certbot "${certbot_args[@]}"

log "checking renewal"
systemctl list-timers | grep -E 'certbot|snap.certbot' || true
certbot renew --dry-run

log "SSL setup completed"
