import subprocess
from pathlib import Path

import pytest

from shift_lefter import gateway, guard


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def test_blocked_receive_is_never_forwarded(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIFT_LEFTER_ROOT", str(tmp_path / "evidence"))
    forwarded = []
    old_sha = "1" * 40
    new_sha = "2" * 40
    lines = [f"{old_sha} {new_sha} refs/heads/main\n"]

    def scanner(_repo, _lines):
        return [
            {
                "path": "app.py",
                "verdict": "block",
                "reason_code": "classifier_block",
                "finding_count": 1,
                "scanner_errors": [],
            }
        ]

    def forwarder(*args):
        forwarded.append(args)

    result = gateway.process_receive(
        tmp_path,
        lines,
        "ssh://git@gitlab.example/repo.git",
        ["gitlab.example"],
        scanner,
        forwarder,
        lambda: {},
    )

    assert result["verdict"] == "block"
    assert forwarded == []
    audit = (tmp_path / "evidence/gateway-audit/events.jsonl").read_text()
    assert "app.py" not in audit
    assert "classifier_block" not in audit


def test_audit_binds_transaction_to_hashed_pusher_identity(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIFT_LEFTER_ROOT", str(tmp_path / "evidence"))
    pusher_id = "sha256:" + "a" * 64

    result = gateway.process_receive(
        tmp_path,
        [f"{'1' * 40} {'2' * 40} refs/heads/main\n"],
        "ssh://git@gitlab.example/repo.git",
        ["gitlab.example"],
        lambda _repo, _lines: [
            {
                "verdict": "block",
                "reason_code": "strict_scanner_hold",
                "finding_count": 1,
                "scanner_errors": [],
            }
        ],
        lambda *_args: None,
        lambda: {},
        pusher_id=pusher_id,
    )

    assert result["pusher_id"] == pusher_id
    assert pusher_id in (tmp_path / "evidence/gateway-audit/events.jsonl").read_text()


def test_forward_failure_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIFT_LEFTER_ROOT", str(tmp_path / "evidence"))
    old_sha = "1" * 40
    new_sha = "2" * 40

    def fail(*_args):
        raise RuntimeError("upstream detail must not be logged")

    result = gateway.process_receive(
        tmp_path,
        [f"{old_sha} {new_sha} refs/heads/main\n"],
        "ssh://git@gitlab.example/repo.git",
        ["gitlab.example"],
        lambda _repo, _lines: [],
        fail,
        lambda: {},
    )

    assert result["verdict"] == "review"
    assert result["reason_code"] == "upstream_forward_error_fail_closed"
    assert (
        "upstream detail"
        not in (tmp_path / "evidence/gateway-audit/events.jsonl").read_text()
    )


def test_audit_failure_before_forward_fails_closed(tmp_path, monkeypatch):
    forwarded = []
    monkeypatch.setattr(
        gateway,
        "_write_audit",
        lambda _record: (_ for _ in ()).throw(OSError("unavailable")),
    )

    result = gateway.process_receive(
        tmp_path,
        [f"{'1' * 40} {'2' * 40} refs/heads/main\n"],
        "ssh://git@gitlab.example/repo.git",
        ["gitlab.example"],
        lambda _repo, _lines: [],
        lambda *_args: forwarded.append(True),
        lambda: {},
    )

    assert result["verdict"] == "review"
    assert result["reason_code"] == "audit_unavailable_fail_closed"
    assert forwarded == []


def test_audit_completion_failure_does_not_misreport_forwarded_push(
    tmp_path, monkeypatch
):
    writes = []

    def audit(record):
        writes.append(record)
        if len(writes) == 2:
            raise OSError("completion unavailable")

    monkeypatch.setattr(gateway, "_write_audit", audit)
    result = gateway.process_receive(
        tmp_path,
        [f"{'1' * 40} {'2' * 40} refs/heads/main\n"],
        "ssh://git@gitlab.example/repo.git",
        ["gitlab.example"],
        lambda _repo, _lines: [],
        lambda *_args: None,
        lambda: {},
    )

    assert result["verdict"] == "allow"
    assert result["reason_code"] == "validated_and_forwarded_audit_completion_error"
    assert writes[0]["reason_code"] == "validated_pending_atomic_forward"


def test_atomic_forward_moves_authoritative_ref(tmp_path, monkeypatch):
    source = tmp_path / "gateway"
    upstream = tmp_path / "upstream.git"
    source.mkdir()
    subprocess.run(["git", "init", str(source)], check=True, capture_output=True)
    subprocess.run(
        ["git", "init", "--bare", str(upstream)], check=True, capture_output=True
    )
    _git(source, "config", "user.email", "test@example.invalid")
    _git(source, "config", "user.name", "Test User")
    (source / "README.md").write_text("safe\n")
    _git(source, "add", "README.md")
    _git(source, "commit", "-m", "safe")
    new_sha = _git(source, "rev-parse", "HEAD")
    monkeypatch.setenv("SHIFT_LEFTER_ALLOW_FILE_UPSTREAM", "1")

    gateway.forward_atomic(
        source,
        [gateway.RefUpdate(guard.ZERO_SHA, new_sha, "refs/heads/main")],
        str(upstream),
        ["local-file-test"],
    )

    assert _git(upstream, "rev-parse", "refs/heads/main") == new_sha


def test_upstream_requires_exact_allowlist():
    with pytest.raises(ValueError, match="allowlisted"):
        gateway.validate_upstream(
            "ssh://git@gitlab.example/repo.git", ["other.example"]
        )


def test_https_upstream_rejects_embedded_credentials():
    with pytest.raises(ValueError, match="must not be embedded"):
        gateway.validate_upstream(
            "https://oauth2:secret@gitlab.example/repo.git", ["gitlab.example"]
        )


def test_invalid_receive_record_fails_closed():
    with pytest.raises(ValueError, match="invalid"):
        gateway.parse_updates(["not a valid record\n"])


def test_scanner_preflight_failure_blocks_even_without_scannable_content(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SHIFT_LEFTER_ROOT", str(tmp_path / "evidence"))
    scanned = []
    forwarded = []

    result = gateway.process_receive(
        tmp_path,
        [f"{'0' * 40} {'2' * 40} refs/heads/empty-commit\n"],
        "ssh://git@gitlab.example/repo.git",
        ["gitlab.example"],
        lambda *_args: scanned.append(True),
        lambda *_args: forwarded.append(True),
        lambda: (_ for _ in ()).throw(RuntimeError("scanner unavailable")),
    )

    assert result["verdict"] == "review"
    assert result["reason_code"] == "scanner_preflight_error_fail_closed"
    assert result["scanner_error_count"] == 1
    assert scanned == []
    assert forwarded == []
    audit = (tmp_path / "evidence/gateway-audit/events.jsonl").read_text()
    assert "scanner unavailable" not in audit
