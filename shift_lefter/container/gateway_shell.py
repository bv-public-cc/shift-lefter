#!/usr/bin/env python3
"""Restricted SSH forced command for one repository per gateway container."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import sys
from pathlib import Path, PurePosixPath

CONFIG_PATH = Path("/run/shift-lefter-gateway-config.json")
ALLOWED_CONFIG_KEYS = {
    "PYTHONPATH",
    "SHIFT_LEFTER_PROJECT_NAME",
    "SHIFT_LEFTER_UPSTREAM_URL",
    "SHIFT_LEFTER_UPSTREAM_HOST",
    "SHIFT_LEFTER_ROOT",
    "SHIFT_LEFTER_TRANSIENT_ROOT",
    "SHIFT_LEFTER_GITLEAKS",
    "SHIFT_LEFTER_TRUFFLEHOG",
    "SHIFT_LEFTER_DETECT_SECRETS",
    "SHIFT_LEFTER_FALSE_POSITIVE_ALLOWLIST",
    "GIT_SSH_COMMAND",
}


def _runtime_config() -> dict[str, str]:
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict) or not set(data).issubset(ALLOWED_CONFIG_KEYS):
        return {}
    if not all(
        isinstance(key, str) and isinstance(value, str) for key, value in data.items()
    ):
        return {}
    return data


def _authenticated_pusher_id() -> str:
    """Return a content-free identifier bound to OpenSSH's accepted public key."""
    auth_info = os.environ.get("SSH_USER_AUTH", "")
    if not auth_info:
        raise RuntimeError("OpenSSH authentication evidence is unavailable")
    path = Path(auth_info)
    data = path.read_text(encoding="utf-8", errors="strict")
    if len(data) > 16384:
        raise RuntimeError("OpenSSH authentication evidence is unexpectedly large")
    public_keys = [
        line.strip()
        for line in data.splitlines()
        if line.strip().startswith("publickey ")
    ]
    if len(public_keys) != 1:
        raise RuntimeError("exactly one public-key identity is required")
    return "sha256:" + hashlib.sha256(public_keys[0].encode()).hexdigest()


def main() -> int:
    config = _runtime_config()
    if not config:
        print("gateway runtime configuration unavailable", file=sys.stderr)
        return 2
    os.environ.update(config)
    try:
        os.environ["SHIFT_LEFTER_PUSHER_ID"] = _authenticated_pusher_id()
    except (OSError, UnicodeError, RuntimeError):
        print("authenticated pusher identity unavailable", file=sys.stderr)
        return 2
    project = config.get("SHIFT_LEFTER_PROJECT_NAME", "")
    original = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    try:
        fields = shlex.split(original)
    except ValueError:
        print("malformed Git SSH command rejected", file=sys.stderr)
        return 2
    if len(fields) != 2 or fields[0] not in {"git-receive-pack", "git-upload-pack"}:
        print("only Git upload and receive commands are allowed", file=sys.stderr)
        return 2
    requested = PurePosixPath(fields[1].lstrip("/"))
    expected = PurePosixPath(project + ".git")
    if requested != expected or ".." in requested.parts:
        print("requested repository is not mapped by this gateway", file=sys.stderr)
        return 2
    executable = fields[0]
    os.execvp(executable, [executable, f"/srv/git/{expected}"])
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
