from pathlib import Path
import subprocess
import sys

from werkzeug.security import check_password_hash


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_windows_launcher_only_runs_server_side_github_deploy():
    script = (PROJECT_ROOT / "deploy.ps1").read_text(encoding="utf-8")

    assert "root@135.106.181.55" in script
    assert "git push" not in script
    assert "& ssh @SshArguments" in script
    assert "./deploy.sh" in script


def test_cmd_wrapper_allows_deploy_command_from_project_folder():
    wrapper = (PROJECT_ROOT / "deploy.cmd").read_text(encoding="utf-8")

    assert "deploy.ps1" in wrapper
    assert "exit /b %ERRORLEVEL%" in wrapper


def test_server_deploy_is_safe_and_verified():
    script = (PROJECT_ROOT / "deploy.sh").read_text(encoding="utf-8")

    assert "umask 022" in script
    assert 'readlink -f -- "${BASH_SOURCE[0]}"' in script
    assert "/usr/local/bin/deploy" in script
    assert "install_deploy_command" in script
    assert "install_systemd_service" in script
    assert "install_nginx_config" in script
    assert "existing SSL nginx config detected" in script
    assert "ssl_certificate|managed by Certbot" in script
    assert "ensure_runtime_permissions" in script
    assert "chown www-data:www-data \"$APP_DIR\"" in script
    assert 'find "$VENV_DIR" -type d -exec chmod a+rx {} +' in script
    assert 'find "$VENV_DIR/bin" -maxdepth 1 -type f -exec chmod a+rx {} +' in script
    assert "chown www-data:www-data \"$APP_DIR/site.db\"" in script
    assert "git merge --ff-only" in script
    assert "git clean -fd" not in script
    assert "backup_file \"$APP_DIR/site.db\"" in script
    assert "backup_file \"$APP_DIR/.env\"" in script
    assert "pytest -q" in script
    assert "wait_for_health" in script
    assert "rollback_on_error" in script


def test_systemd_service_runs_this_flask_app():
    service = (PROJECT_ROOT / "deploy" / "khudoverdiev.service").read_text(encoding="utf-8")

    assert "WorkingDirectory=/opt/khudoverdiev" in service
    assert "EnvironmentFile=-/opt/khudoverdiev/.env" in service
    assert "gunicorn" in service
    assert "app:app" in service


def test_nginx_config_routes_all_site_hosts_to_gunicorn():
    config = (PROJECT_ROOT / "deploy" / "nginx-khudoverdiev.conf").read_text(encoding="utf-8")

    assert "server_name khudoverdiev.ru" in config
    assert "it.khudoverdiev.ru" in config
    assert "ph.khudoverdiev.ru" in config
    assert "phh.khudoverdiev.ru" not in config
    assert "proxy_pass http://127.0.0.1:8000" in config
    assert "alias /opt/khudoverdiev/static/" in config


def test_server_bootstrap_installs_project_and_deploy_command():
    script = (PROJECT_ROOT / "deploy" / "bootstrap-server.sh").read_text(encoding="utf-8")

    assert "umask 022" in script
    assert "https://github.com/vhudoverdiev/khudoverdiev.git" in script
    assert "git clone --branch" in script
    assert "python3 -m venv" in script
    assert "ADMIN_USERNAME=admin" in script
    assert "ensure_runtime_permissions" in script
    assert "chown www-data:www-data \"$APP_DIR\"" in script
    assert 'find "$APP_DIR/venv" -type d -exec chmod a+rx {} +' in script
    assert 'find "$APP_DIR/venv/bin" -maxdepth 1 -type f -exec chmod a+rx {} +' in script
    assert "chown www-data:www-data \"$APP_DIR/site.db\"" in script
    assert "systemctl enable \"$SERVICE\"" in script
    assert "existing SSL nginx config detected" in script
    assert "ssl_certificate|managed by Certbot" in script
    assert "ln -sfn \"$APP_DIR/deploy.sh\" /usr/local/bin/deploy" in script
    assert "http://127.0.0.1:8000/health" in script


def test_server_diagnostics_cover_backend_and_nginx():
    script = (PROJECT_ROOT / "deploy" / "diagnose-server.sh").read_text(encoding="utf-8")

    assert "systemctl status \"$SERVICE\"" in script
    assert "journalctl -u \"$SERVICE\"" in script
    assert "nginx -t" in script
    assert "http://127.0.0.1:8000/health" in script


def test_admin_credentials_script_updates_env_with_password_hash(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "\n".join(
            [
                "FLASK_SECRET_KEY=keep-me",
                "ADMIN_PASSWORD=old-secret",
                "FORCE_HTTPS=1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "deploy" / "admin_credentials.py"),
            "--env",
            str(env_path),
            "--username",
            "owner",
            "--password",
            "new-secret",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    values = dict(line.split("=", 1) for line in env_path.read_text(encoding="utf-8").splitlines() if "=" in line)
    assert values["FLASK_SECRET_KEY"] == "keep-me"
    assert values["FORCE_HTTPS"] == "1"
    assert values["ADMIN_USERNAME"] == "owner"
    assert values["ADMIN_PASSWORD"] == ""
    assert values["ADMIN_PASSWORD_HASH"] != "new-secret"
    assert check_password_hash(values["ADMIN_PASSWORD_HASH"], "new-secret")


def test_ssl_setup_requests_certificates_for_all_domains():
    script = (PROJECT_ROOT / "deploy" / "setup-ssl.sh").read_text(encoding="utf-8")

    assert "certbot" in script
    assert "khudoverdiev.ru" in script
    assert "www.khudoverdiev.ru" in script
    assert "it.khudoverdiev.ru" in script
    assert "ph.khudoverdiev.ru" in script
    assert "phh.khudoverdiev.ru" not in script
