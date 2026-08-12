#!/usr/bin/env python3
import argparse
import getpass
import os
import stat
from pathlib import Path

from werkzeug.security import generate_password_hash


DEFAULT_ENV_PATH = Path("/opt/khudoverdiev/.env")


def parse_args():
    parser = argparse.ArgumentParser(description="Create or update admin credentials in the app .env file.")
    parser.add_argument("--env", default=str(DEFAULT_ENV_PATH), help="Path to the environment file.")
    parser.add_argument("--username", required=True, help="Admin username.")
    parser.add_argument("--password", help="Admin password. Prefer --prompt-password on shared machines.")
    parser.add_argument("--prompt-password", action="store_true", help="Prompt for the admin password.")
    return parser.parse_args()


def clean_username(value):
    value = (value or "").strip()
    if not value:
        raise SystemExit("Error: username cannot be empty.")
    if any(char.isspace() for char in value):
        raise SystemExit("Error: username cannot contain spaces.")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise SystemExit("Error: username cannot contain control characters.")
    return value


def read_password(args):
    if args.prompt_password:
        password = getpass.getpass("Admin password: ")
        confirmation = getpass.getpass("Repeat admin password: ")
        if password != confirmation:
            raise SystemExit("Error: passwords do not match.")
    else:
        password = args.password or ""
    if len(password) < 8:
        raise SystemExit("Error: password must be at least 8 characters.")
    return password


def read_env(path):
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").splitlines()


def set_env_value(lines, key, value):
    prefix = f"{key}="
    next_lines = []
    replaced = False
    for line in lines:
        if line.startswith(prefix):
            if not replaced:
                next_lines.append(f"{key}={value}")
                replaced = True
            continue
        next_lines.append(line)
    if not replaced:
        next_lines.append(f"{key}={value}")
    return next_lines


def write_env(path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def main():
    args = parse_args()
    env_path = Path(args.env)
    username = clean_username(args.username)
    password = read_password(args)
    password_hash = generate_password_hash(password)

    lines = read_env(env_path)
    lines = set_env_value(lines, "ADMIN_USERNAME", username)
    lines = set_env_value(lines, "ADMIN_PASSWORD", "")
    lines = set_env_value(lines, "ADMIN_PASSWORD_HASH", password_hash)
    write_env(env_path, lines)

    print(f"Admin credentials updated in {env_path}")
    print("Restart the service to apply changes: systemctl restart khudoverdiev.service")


if __name__ == "__main__":
    main()
