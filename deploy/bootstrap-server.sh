#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${APP_DIR:-/opt/khudoverdiev}"
REPO_URL="${REPO_URL:-https://github.com/vhudoverdiev/khudoverdiev.git}"
BRANCH="${BRANCH:-main}"
SERVICE="${SERVICE:-khudoverdiev.service}"
BACKUP_DIR="${BACKUP_DIR:-/root/backups/khudoverdiev}"

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

fail() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

[[ "$(id -u)" -eq 0 ]] || fail "run this script as root"

export DEBIAN_FRONTEND=noninteractive

log "installing system packages"
apt-get update
apt-get install -y git nginx python3 python3-venv python3-pip ca-certificates

mkdir -p "$(dirname "$APP_DIR")" "$BACKUP_DIR"

if [[ -d "$APP_DIR/.git" ]]; then
  log "repository already exists: $APP_DIR"
  git -C "$APP_DIR" fetch --prune origin "$BRANCH"
  git -C "$APP_DIR" checkout "$BRANCH"
  git -C "$APP_DIR" merge --ff-only "origin/$BRANCH"
else
  if [[ -e "$APP_DIR" ]]; then
    fail "$APP_DIR exists but is not a Git repository"
  fi
  log "cloning $REPO_URL"
  git clone --branch "$BRANCH" "$REPO_URL" "$APP_DIR"
fi

cd "$APP_DIR"
git config --global --add safe.directory "$APP_DIR" || true

if [[ ! -f "$APP_DIR/.env" ]]; then
  log "creating .env"
  flask_secret="$(
    python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
  )"
  admin_password="$(
    python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(18))
PY
  )"
  umask 077
  cat > "$APP_DIR/.env" <<EOF
FLASK_SECRET_KEY=$flask_secret
ADMIN_PASSWORD=$admin_password
ADMIN_PASSWORD_HASH=
FLASK_COOKIE_SECURE=1
FORCE_HTTPS=1
EOF
  log "generated ADMIN_PASSWORD in $APP_DIR/.env"
fi

if [[ ! -x "$APP_DIR/venv/bin/python" ]]; then
  log "creating virtual environment"
  python3 -m venv "$APP_DIR/venv"
fi

log "installing Python dependencies"
"$APP_DIR/venv/bin/python" -m pip install --upgrade pip
"$APP_DIR/venv/bin/python" -m pip install -r requirements.txt "gunicorn==23.0.0"

log "initializing database"
"$APP_DIR/venv/bin/python" - <<'PY'
from app import init_db
init_db()
PY

log "installing systemd service"
install -m 0644 "$APP_DIR/deploy/khudoverdiev.service" "/etc/systemd/system/$SERVICE"
systemctl daemon-reload
systemctl enable "$SERVICE"

log "installing nginx config"
install -m 0644 "$APP_DIR/deploy/nginx-khudoverdiev.conf" /etc/nginx/sites-available/khudoverdiev
ln -sfn /etc/nginx/sites-available/khudoverdiev /etc/nginx/sites-enabled/khudoverdiev
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable nginx
systemctl reload nginx || systemctl restart nginx

log "installing deploy command"
chmod +x "$APP_DIR/deploy.sh"
ln -sfn "$APP_DIR/deploy.sh" /usr/local/bin/deploy

log "starting application"
systemctl restart "$SERVICE"
systemctl is-active --quiet "$SERVICE"

log "checking health"
"$APP_DIR/venv/bin/python" - <<'PY'
import json
import urllib.request

with urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=10) as response:
    payload = json.load(response)
if response.status != 200 or payload.get("status") != "ok":
    raise SystemExit(1)
PY

log "server bootstrap completed"
