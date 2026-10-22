import os
import secrets
import string
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("SHIFT_LEFTER_RUN_GATEWAY_E2E") != "1" or os.name == "nt",
    reason="requires the pinned scanners, local model, and POSIX Git hooks",
)


def _run(command, **kwargs):
    return subprocess.run(command, capture_output=True, text=True, **kwargs)


def _git(repo: Path, *args: str, check: bool = True):
    return _run(["git", "-C", str(repo), *args], check=check)


def test_gateway_forwards_safe_push_and_quarantines_rejected_push(tmp_path):
    project_root = Path(__file__).resolve().parents[2]
    source = tmp_path / "developer"
    gateway = tmp_path / "gateway.git"
    upstream = tmp_path / "gitlab.git"
    evidence = tmp_path / "evidence"
    _run(["git", "init", str(source)], check=True)
    _run(["git", "init", "--bare", str(gateway)], check=True)
    _run(["git", "init", "--bare", str(upstream)], check=True)
    _git(source, "config", "user.email", "test@example.invalid")
    _git(source, "config", "user.name", "Gateway Test")

    hook = gateway / "hooks" / "pre-receive"
    hook_program = (
        "#!/bin/sh\n"
        f"export PYTHONPATH={project_root}\n"
        f"export SHIFT_LEFTER_ROOT={evidence}\n"
        "export SHIFT_LEFTER_ALLOW_FILE_UPSTREAM=1\n"
        f"exec {sys.executable} -m shift_lefter.gateway "
        f"--repo {gateway} --upstream {upstream} --allow-host local-file-test\n"
    )
    hook.write_text(hook_program)
    hook.chmod(0o700)

    source_file = source / "app.py"
    source_file.write_text("mode = 'safe'\n")
    _git(source, "add", "app.py")
    _git(source, "commit", "-m", "safe")
    safe_sha = _git(source, "rev-parse", "HEAD").stdout.strip()
    allowed = _git(source, "push", str(gateway), "HEAD:refs/heads/main", check=False)
    assert allowed.returncode == 0, allowed.stderr
    assert _git(gateway, "rev-parse", "refs/heads/main").stdout.strip() == safe_sha
    assert _git(upstream, "rev-parse", "refs/heads/main").stdout.strip() == safe_sha

    # Scanner startup is checked for every transaction. An empty commit has no
    # new blob or nonempty message to scan, but must still fail closed when a
    # required scanner is unavailable.
    _git(source, "commit", "--allow-empty", "--allow-empty-message", "-m", "")
    hook.write_text(
        hook_program.replace(
            "export SHIFT_LEFTER_ALLOW_FILE_UPSTREAM=1\n",
            "export SHIFT_LEFTER_ALLOW_FILE_UPSTREAM=1\n"
            "export SHIFT_LEFTER_GITLEAKS=/nonexistent/gitleaks\n",
        )
    )
    outage = _git(
        source,
        "push",
        str(gateway),
        "HEAD:refs/heads/scanner-outage",
        check=False,
    )
    hook.write_text(hook_program)

    assert outage.returncode != 0
    assert "scanner_preflight_error_fail_closed" in outage.stderr
    assert (
        _git(
            upstream, "show-ref", "--verify", "refs/heads/scanner-outage", check=False
        ).returncode
        != 0
    )

    alphabet = string.ascii_letters + string.digits
    candidate = "ghp_" + "".join(secrets.choice(alphabet) for _ in range(36))
    source_file.write_text(
        "# active runtime credential\ngithub_token = " + repr(candidate) + "\n"
    )
    _git(source, "add", "app.py")
    _git(source, "commit", "-m", "must be rejected")
    rejected = _git(source, "push", str(gateway), "HEAD:refs/heads/main", check=False)

    assert rejected.returncode != 0
    assert "push rejected" in rejected.stderr
    assert _git(gateway, "rev-parse", "refs/heads/main").stdout.strip() == safe_sha
    assert _git(upstream, "rev-parse", "refs/heads/main").stdout.strip() == safe_sha
    assert candidate not in (evidence / "gateway-audit/events.jsonl").read_text()

    # Removing the candidate in a later commit must not hide it in history.
    source_file.write_text("mode = 'safe again'\n")
    _git(source, "add", "app.py")
    _git(source, "commit", "-m", "remove candidate from tip")
    history_rejected = _git(
        source, "push", str(gateway), "HEAD:refs/heads/main", check=False
    )

    assert history_rejected.returncode != 0
    assert "push rejected" in history_rejected.stderr
    assert _git(gateway, "rev-parse", "refs/heads/main").stdout.strip() == safe_sha
    assert _git(upstream, "rev-parse", "refs/heads/main").stdout.strip() == safe_sha
