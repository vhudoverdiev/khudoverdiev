#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

APP_DIR="${APP_DIR:-/opt/khudoverdiev}"
DATA_DIR="${DATA_DIR:-/var/lib/khudoverdiev}"
DB_PATH="${SITE_DB_PATH:-$DATA_DIR/site.db}"
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

ensure_runtime_permissions() {
  log "ensuring runtime permissions"

  chmod 0755 "$(dirname "$APP_DIR")"
  chown root:www-data "$APP_DIR" || true
  chmod 0755 "$APP_DIR"
  mkdir -p "$(dirname "$DB_PATH")"
  chown www-data:www-data "$(dirname "$DB_PATH")" || true
  chmod 0750 "$(dirname "$DB_PATH")" || true

  if [[ -d "$APP_DIR/venv" ]]; then
    find "$APP_DIR/venv" -type d -exec chmod a+rx {} +
    find "$APP_DIR/venv" -type f -exec chmod a+r {} +
    if [[ -d "$APP_DIR/venv/bin" ]]; then
      find "$APP_DIR/venv/bin" -maxdepth 1 -type f -exec chmod a+rx {} +
    fi
  fi

  if [[ -f "$APP_DIR/deploy.sh" ]]; then
    chmod +x "$APP_DIR/deploy.sh"
  fi

  if [[ -f "$APP_DIR/site.db" && ! -f "$DB_PATH" ]]; then
    mv "$APP_DIR/site.db" "$DB_PATH"
  fi

  if [[ -f "$DB_PATH" ]]; then
    chown www-data:www-data "$DB_PATH" || true
    chmod 0660 "$DB_PATH" || true
  fi
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

if [[ ! -x "$APP_DIR/venv/bin/python" ]]; then
  log "creating virtual environment"
  python3 -m venv "$APP_DIR/venv"
fi

log "installing Python dependencies"
"$APP_DIR/venv/bin/python" -m pip install --upgrade pip
"$APP_DIR/venv/bin/python" -m pip install -r requirements.txt "gunicorn==23.0.0"

if [[ ! -f "$APP_DIR/.env" ]]; then
  log "creating .env"
  flask_secret="$(
    python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
  )"
  admin_password_hash="$(
    "$APP_DIR/venv/bin/python" - <<'PY'
import secrets
from werkzeug.security import generate_password_hash

print(generate_password_hash(secrets.token_urlsafe(24)))
PY
  )"
  (
    umask 077
    cat > "$APP_DIR/.env" <<EOF
FLASK_SECRET_KEY=$flask_secret
ADMIN_USERNAME=admin
ADMIN_PASSWORD=
ADMIN_PASSWORD_HASH=$admin_password_hash
REQUIRE_ADMIN_PASSWORD_HASH=1
FLASK_COOKIE_SECURE=1
FORCE_HTTPS=1
SITE_DB_PATH=$DB_PATH
EOF
  )
  log "generated ADMIN_PASSWORD_HASH in $APP_DIR/.env"
fi

ensure_runtime_permissions

log "initializing database"
"$APP_DIR/venv/bin/python" - <<'PY'
from app import init_db
init_db()
PY
ensure_runtime_permissions

log "installing systemd service"
install -m 0644 "$APP_DIR/deploy/khudoverdiev.service" "/etc/systemd/system/$SERVICE"
systemctl daemon-reload
systemctl enable "$SERVICE"

log "installing nginx config"
if [[ -f /etc/nginx/sites-available/khudoverdiev ]] \
  && grep -Eq "ssl_certificate|managed by Certbot" /etc/nginx/sites-available/khudoverdiev; then
  log "existing SSL nginx config detected; keeping /etc/nginx/sites-available/khudoverdiev"
else
  install -m 0644 "$APP_DIR/deploy/nginx-khudoverdiev.conf" /etc/nginx/sites-available/khudoverdiev
  ln -sfn /etc/nginx/sites-available/khudoverdiev /etc/nginx/sites-enabled/khudoverdiev
  rm -f /etc/nginx/sites-enabled/default
fi
nginx -t
systemctl enable nginx
systemctl reload nginx || systemctl restart nginx

log "installing deploy command"
chmod +x "$APP_DIR/deploy.sh"
ln -sfn "$APP_DIR/deploy.sh" /usr/local/bin/deploy
ensure_runtime_permissions

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
