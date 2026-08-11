from pathlib import Path


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

    assert 'readlink -f -- "${BASH_SOURCE[0]}"' in script
    assert "/usr/local/bin/deploy" in script
    assert "install_deploy_command" in script
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
