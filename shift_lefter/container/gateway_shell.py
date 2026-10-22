#!/usr/bin/env python3
"""Restricted SSH forced command for one repository per gateway container."""

from __future__ import annotations

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
    "SHIFT_LEFTER_STANDALONE",
    "SHIFT_LEFTER_MODEL_ENDPOINT",
    "SHIFT_LEFTER_MODEL_NAME",
    "SHIFT_LEFTER_ALLOWED_MODEL_HOSTS",
    "SHIFT_LEFTER_ALLOW_PLAINTEXT_MODEL_HOSTS",
    "SHIFT_LEFTER_CA_BUNDLE",
    "SHIFT_LEFTER_LOCAL_API_KEY_FILE",
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


def main() -> int:
    config = _runtime_config()
    if not config:
        print("gateway runtime configuration unavailable", file=sys.stderr)
        return 2
    os.environ.update(config)
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
