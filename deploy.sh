#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

SCRIPT_PATH="$(readlink -f -- "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd -- "$(dirname -- "$SCRIPT_PATH")" && pwd)"
APP_DIR="${APP_DIR:-$SCRIPT_DIR}"
BRANCH="${BRANCH:-main}"
REMOTE="${REMOTE:-origin}"
SERVICE="${SERVICE:-khudoverdiev.service}"
VENV_DIR="${VENV_DIR:-$APP_DIR/venv}"
BACKUP_DIR="${BACKUP_DIR:-/root/backups/khudoverdiev}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8000/health}"
HEALTH_TIMEOUT_SECONDS="${HEALTH_TIMEOUT_SECONDS:-45}"
RUN_TESTS="${RUN_TESTS:-1}"
GUNICORN_VERSION="${GUNICORN_VERSION:-23.0.0}"
DEPLOY_COMMAND_PATH="${DEPLOY_COMMAND_PATH:-/usr/local/bin/deploy}"
SYSTEMD_SOURCE="${SYSTEMD_SOURCE:-$APP_DIR/deploy/khudoverdiev.service}"
SYSTEMD_TARGET="${SYSTEMD_TARGET:-/etc/systemd/system/$SERVICE}"
INSTALL_NGINX_CONFIG="${INSTALL_NGINX_CONFIG:-1}"
NGINX_SITE_NAME="${NGINX_SITE_NAME:-khudoverdiev}"
NGINX_CONFIG_SOURCE="${NGINX_CONFIG_SOURCE:-$APP_DIR/deploy/nginx-khudoverdiev.conf}"
NGINX_CONFIG_TARGET="${NGINX_CONFIG_TARGET:-/etc/nginx/sites-available/$NGINX_SITE_NAME}"

BEFORE_HEAD=""
UPDATED=0
SERVICE_TOUCHED=0

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

fail() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "command '$1' was not found"
}

systemctl_cmd() {
  if [[ "$EUID" -eq 0 ]]; then
    systemctl "$@"
  else
    sudo systemctl "$@"
  fi
}

root_cmd() {
  if [[ "$EUID" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

install_deploy_command() {
  local current_target=""

  if [[ -e "$DEPLOY_COMMAND_PATH" && ! -L "$DEPLOY_COMMAND_PATH" ]]; then
    fail "$DEPLOY_COMMAND_PATH already exists and is not a symlink"
  fi

  if [[ -L "$DEPLOY_COMMAND_PATH" ]]; then
    current_target="$(readlink -f -- "$DEPLOY_COMMAND_PATH" || true)"
    if [[ -n "$current_target" && "$current_target" != "$SCRIPT_PATH" ]]; then
      fail "$DEPLOY_COMMAND_PATH points to another file: $current_target"
    fi
  fi

  if [[ "$EUID" -eq 0 ]]; then
    ln -sfn -- "$SCRIPT_PATH" "$DEPLOY_COMMAND_PATH"
  else
    sudo ln -sfn -- "$SCRIPT_PATH" "$DEPLOY_COMMAND_PATH"
  fi

  log "deploy command installed: $DEPLOY_COMMAND_PATH"
}

install_systemd_service() {
  [[ -f "$SYSTEMD_SOURCE" ]] || fail "systemd service file was not found: $SYSTEMD_SOURCE"

  if [[ "$EUID" -eq 0 ]]; then
    install -m 0644 "$SYSTEMD_SOURCE" "$SYSTEMD_TARGET"
  else
    sudo install -m 0644 "$SYSTEMD_SOURCE" "$SYSTEMD_TARGET"
  fi
  systemctl_cmd daemon-reload
  systemctl_cmd enable "$SERVICE" >/dev/null
  log "systemd service installed: $SYSTEMD_TARGET"
}

install_nginx_config() {
  [[ "$INSTALL_NGINX_CONFIG" == "1" ]] || return 0
  [[ -f "$NGINX_CONFIG_SOURCE" ]] || return 0
  command -v nginx >/dev/null 2>&1 || return 0

  if [[ -f "$NGINX_CONFIG_TARGET" ]] && grep -Eq "ssl_certificate|managed by Certbot" "$NGINX_CONFIG_TARGET"; then
    log "existing SSL nginx config detected; keeping $NGINX_CONFIG_TARGET"
    if [[ "$EUID" -eq 0 ]]; then
      nginx -t
      systemctl reload nginx
    else
      sudo nginx -t
      sudo systemctl reload nginx
    fi
    return 0
  fi

  if [[ "$EUID" -eq 0 ]]; then
    install -m 0644 "$NGINX_CONFIG_SOURCE" "$NGINX_CONFIG_TARGET"
    ln -sfn "$NGINX_CONFIG_TARGET" "/etc/nginx/sites-enabled/$NGINX_SITE_NAME"
    nginx -t
    systemctl reload nginx
  else
    sudo install -m 0644 "$NGINX_CONFIG_SOURCE" "$NGINX_CONFIG_TARGET"
    sudo ln -sfn "$NGINX_CONFIG_TARGET" "/etc/nginx/sites-enabled/$NGINX_SITE_NAME"
    sudo nginx -t
    sudo systemctl reload nginx
  fi
  log "nginx config installed: $NGINX_CONFIG_TARGET"
}

backup_file() {
  local source_path="$1"
  local label="$2"
  local backup_path

  if [[ ! -f "$source_path" ]]; then
    log "$label does not exist yet; skipping backup"
    return
  fi

  mkdir -p "$BACKUP_DIR"
  backup_path="$BACKUP_DIR/$(basename "$source_path").$(date '+%Y%m%d-%H%M%S').bak"
  cp -p -- "$source_path" "$backup_path"
  log "$label backup: $backup_path"
}

install_dependencies() {
  "$VENV_DIR/bin/python" -m pip install --upgrade pip
  "$VENV_DIR/bin/python" -m pip install \
    --disable-pip-version-check \
    -r requirements.txt \
    "gunicorn==$GUNICORN_VERSION"
}

ensure_runtime_permissions() {
  log "ensuring runtime permissions"

  root_cmd chmod 0755 "$(dirname "$APP_DIR")"
  root_cmd chown www-data:www-data "$APP_DIR" || true
  root_cmd chmod 0755 "$APP_DIR"

  if [[ -d "$VENV_DIR" ]]; then
    root_cmd find "$VENV_DIR" -type d -exec chmod a+rx {} +
    root_cmd find "$VENV_DIR" -type f -exec chmod a+r {} +
    if [[ -d "$VENV_DIR/bin" ]]; then
      root_cmd find "$VENV_DIR/bin" -maxdepth 1 -type f -exec chmod a+rx {} +
    fi
  fi

  root_cmd chmod +x "$SCRIPT_PATH"

  if [[ -f "$APP_DIR/site.db" ]]; then
    root_cmd chown www-data:www-data "$APP_DIR/site.db" || true
    root_cmd chmod 0660 "$APP_DIR/site.db" || true
  fi
}

check_health() {
  "$VENV_DIR/bin/python" - "$HEALTH_URL" <<'PY'
import json
import sys
import urllib.request

url = sys.argv[1]
with urllib.request.urlopen(url, timeout=5) as response:
    payload = json.load(response)
if response.status != 200 or payload.get("status") != "ok":
    raise SystemExit(1)
PY
}

wait_for_health() {
  local deadline=$((SECONDS + HEALTH_TIMEOUT_SECONDS))

  while (( SECONDS < deadline )); do
    if check_health >/dev/null 2>&1; then
      log "health check passed: $HEALTH_URL"
      return 0
    fi
    sleep 2
  done

  return 1
}

rollback_on_error() {
  local exit_code="$1"
  local line_number="$2"

  trap - ERR
  set +e
  printf 'Deploy failed at line %s; rolling back.\n' "$line_number" >&2

  if [[ "$UPDATED" -eq 1 && -n "$BEFORE_HEAD" ]]; then
    git reset --hard "$BEFORE_HEAD"
    if [[ -x "$VENV_DIR/bin/python" ]]; then
      install_dependencies
      ensure_runtime_permissions
    fi
  fi

  if [[ "$SERVICE_TOUCHED" -eq 1 ]]; then
    systemctl_cmd restart "$SERVICE"
  fi

  printf 'Deploy was canceled; previous version restored.\n' >&2
  exit "$exit_code"
}

main() {
  require_cmd git
  require_cmd ln
  require_cmd python3
  require_cmd systemctl
  if [[ "$EUID" -ne 0 ]]; then
    require_cmd sudo
  fi

  [[ -d "$APP_DIR/.git" ]] || fail "$APP_DIR is not a Git repository"
  cd "$APP_DIR"

  git config --global --add safe.directory "$APP_DIR" || true

  if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
    git status --short >&2
    fail "server has local changes; deploy stopped to avoid overwriting them"
  fi

  systemctl_cmd cat "$SERVICE" >/dev/null
  install_deploy_command
  BEFORE_HEAD="$(git rev-parse HEAD)"
  log "current version: ${BEFORE_HEAD:0:12}"

  backup_file "$APP_DIR/site.db" "database"
  backup_file "$APP_DIR/.env" "environment"

  log "fetching $REMOTE/$BRANCH from GitHub"
  git fetch --prune "$REMOTE" "$BRANCH"
  git checkout "$BRANCH"
  git show-ref --verify --quiet "refs/remotes/$REMOTE/$BRANCH" \
    || fail "branch $REMOTE/$BRANCH was not found"
  git merge --ff-only "$REMOTE/$BRANCH"

  if [[ "$(git rev-parse HEAD)" != "$BEFORE_HEAD" ]]; then
    UPDATED=1
  fi

  if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    log "creating virtual environment"
    python3 -m venv "$VENV_DIR"
  fi

  log "installing dependencies"
  install_dependencies
  ensure_runtime_permissions

  log "checking Python files"
  "$VENV_DIR/bin/python" -m compileall -q app.py

  if [[ "$RUN_TESTS" == "1" ]]; then
    log "running tests"
    "$VENV_DIR/bin/python" -m pytest -q
  fi

  install_systemd_service
  install_nginx_config

  log "restarting $SERVICE"
  SERVICE_TOUCHED=1
  systemctl_cmd restart "$SERVICE"
  systemctl_cmd is-active --quiet "$SERVICE"

  log "checking application health"
  wait_for_health

  local after_head
  after_head="$(git rev-parse HEAD)"
  log "deploy completed: ${BEFORE_HEAD:0:12} -> ${after_head:0:12}"
}

trap 'rollback_on_error "$?" "$LINENO"' ERR
main "$@"
