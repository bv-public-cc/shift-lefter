import io
import json
import subprocess
import sys
from types import SimpleNamespace
from pathlib import Path

import pytest

from shift_lefter import guard


def test_scanner_preflight_requires_every_executable(tmp_path, monkeypatch):
    missing = tmp_path / "missing-gitleaks"
    monkeypatch.setenv("SHIFT_LEFTER_GITLEAKS", str(missing))

    try:
        guard.preflight_scanners(("gitleaks",))
    except RuntimeError as exc:
        assert "required scanner is unavailable" in str(exc)
    else:
        raise AssertionError("missing scanner did not fail preflight")


def test_gitleaks_adapter_keeps_raw_report_in_memory_and_discards_match(
    tmp_path, monkeypatch
):
    binary = tmp_path / "gitleaks"
    binary.write_text("")
    artifact = tmp_path / "app.py"
    artifact.write_text("placeholder")
    candidate = "candidate-must-not-survive-normalization"
    monkeypatch.setattr(guard, "_tool_path", lambda *_args: binary)

    def run(command, **_kwargs):
        if "version" in command:
            return SimpleNamespace(returncode=0, stdout="8.test\n", stderr="")
        report_index = command.index("--report-path")
        assert command[report_index + 1] == "-"
        payload = [
            {
                "RuleID": "synthetic",
                "StartLine": 2,
                "Match": candidate,
                "Secret": "REDACTED",
            }
        ]
        return SimpleNamespace(returncode=1, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr(guard.subprocess, "run", run)
    findings, version = guard.scan_gitleaks(artifact, tmp_path)

    assert version == "8.test"
    assert findings[0]["line"] == 2
    assert candidate not in str(findings)
    assert list(tmp_path.glob("*.json")) == []


def test_trufflehog_adapter_discards_raw_candidate(tmp_path, monkeypatch):
    binary = tmp_path / "trufflehog"
    binary.write_text("")
    artifact = tmp_path / "app.py"
    artifact.write_text("placeholder")
    candidate = "candidate-must-not-survive-normalization"
    monkeypatch.setattr(guard, "_tool_path", lambda *_args: binary)

    def run(command, **_kwargs):
        assert "--no-update" in command
        if "--version" in command:
            return SimpleNamespace(
                returncode=0, stdout="trufflehog 3.test\n", stderr=""
            )
        assert "--no-verification" in command
        payload = {
            "DetectorName": "Synthetic",
            "Raw": candidate,
            "SourceMetadata": {"Data": {"Filesystem": {"line": 4}}},
        }
        return SimpleNamespace(
            returncode=0, stdout=json.dumps(payload) + "\n", stderr=""
        )

    monkeypatch.setattr(guard.subprocess, "run", run)
    findings, version = guard.scan_trufflehog(artifact, tmp_path)

    assert version == "trufflehog 3.test"
    assert findings[0]["line"] == 4
    assert candidate not in str(findings)


def test_detect_secrets_adapter_is_offline_and_content_free(tmp_path, monkeypatch):
    binary = tmp_path / "detect-secrets"
    hook = tmp_path / "detect-secrets-hook"
    binary.write_text("")
    hook.write_text("")
    artifact = tmp_path / "app.py"
    artifact.write_text("placeholder")
    monkeypatch.setattr(guard, "_tool_path", lambda *_args: binary)

    def run(command, **_kwargs):
        if "--version" in command:
            return SimpleNamespace(returncode=0, stdout="1.test\n", stderr="")
        assert command[0] == str(hook)
        assert "--no-verify" in command
        payload = {
            "results": {
                str(artifact): [
                    {
                        "type": "Secret Keyword",
                        "line_number": 2,
                        "hashed_secret": "safe-hash",
                    }
                ]
            }
        }
        return SimpleNamespace(returncode=1, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr(guard.subprocess, "run", run)
    findings, version = guard.scan_detect_secrets(artifact, tmp_path)

    assert version == "1.test"
    assert findings[0]["rule_id"] == "Secret Keyword"
    assert "safe-hash" not in str(findings)


def test_redacted_context_never_contains_candidate(tmp_path):
    candidate = "live-secret-value-12345"
    artifact = tmp_path / "app.py"
    artifact.write_text(
        f"mode = 'runtime'\napi_key = '{candidate}'\nregion = 'local'\n"
    )

    context = guard._redacted_context(artifact, 2)

    assert candidate not in context
    assert "<REDACTED_CANDIDATE" in context
    assert "markers=runtime" in context


def test_redacted_candidate_line_does_not_project_attacker_controlled_markers(tmp_path):
    candidate = "opaquevalue123456789"
    artifact = tmp_path / "app.py"
    artifact.write_text(
        f"runtime_credential = '{candidate}'  # active secret\n", encoding="utf-8"
    )

    context = guard._redacted_context(artifact, 1)

    assert candidate not in context
    assert "markers=none" in context
    assert "structure=assignment" in context


def test_strict_policy_holds_a_scanner_finding_even_when_model_allows():
    verdict, reason = guard.decide_findings(
        [{"rule_id": "generic-token"}],
        [{"verdict": "allow", "confidence": 0.99, "reason_code": "placeholder"}],
        [],
        allow_classifier_allow=False,
    )

    assert verdict == "review"
    assert reason == "strict_scanner_hold"


def test_contextual_experiment_policy_can_measure_model_allow():
    verdict, reason = guard.decide_findings(
        [{"rule_id": "generic-token"}],
        [{"verdict": "allow", "confidence": 0.99, "reason_code": "placeholder"}],
        [],
        allow_classifier_allow=True,
    )

    assert verdict == "allow"
    assert reason == "classifier_allow"


def test_content_addressed_false_positive_exception_allows_exact_artifact(
    tmp_path, monkeypatch
):
    artifact = tmp_path / "documented-example.txt"
    artifact.write_text("credential-shaped but reviewed content\n")
    digest = guard.experiment._sha256_file(artifact)
    finding = guard._finding("gitleaks", "generic-token", 1, artifact)
    policy = tmp_path / "exceptions.json"
    policy.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "entries": [
                    {
                        "artifact_sha256": digest,
                        "finding_keys": ["gitleaks:generic-token"],
                        "expires_utc": "2099-01-01T00:00:00Z",
                        "ticket": "SEC-1234",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    policy.chmod(0o600)
    monkeypatch.setenv("SHIFT_LEFTER_FALSE_POSITIVE_ALLOWLIST", str(policy))
    monkeypatch.setattr(
        guard,
        "scan_candidates",
        lambda _path, _scanners: {
            "artifact_sha256": digest,
            "findings": [finding],
            "scanner_errors": [],
            "scanner_versions": {"gitleaks": "test"},
        },
    )

    result = guard.scan_file(artifact, scanners=("gitleaks",))

    assert result["verdict"] == "allow"
    assert result["reason_code"] == "approved_false_positive_exception"


def test_false_positive_exception_cannot_override_private_key(tmp_path, monkeypatch):
    artifact = tmp_path / "key.txt"
    artifact.write_text("reviewed private key material\n")
    digest = guard.experiment._sha256_file(artifact)
    finding = guard._finding("gitleaks", "shift-private-key", 1, artifact)
    policy = tmp_path / "exceptions.json"
    policy.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "entries": [
                    {
                        "artifact_sha256": digest,
                        "finding_keys": ["gitleaks:shift-private-key"],
                        "expires_utc": "2099-01-01T00:00:00Z",
                        "ticket": "SEC-1234",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    policy.chmod(0o600)
    monkeypatch.setenv("SHIFT_LEFTER_FALSE_POSITIVE_ALLOWLIST", str(policy))
    monkeypatch.setattr(
        guard,
        "scan_candidates",
        lambda _path, _scanners: {
            "artifact_sha256": digest,
            "findings": [finding],
            "scanner_errors": [],
            "scanner_versions": {"gitleaks": "test"},
        },
    )

    result = guard.scan_file(artifact, scanners=("gitleaks",))

    assert result["verdict"] == "block"
    assert result["reason_code"] == "non_overridable_hard_block"


def test_classifier_rejects_allow_with_credential_reason():
    payload = json.dumps(
        {"verdict": "allow", "confidence": 0.99, "reason_code": "credential_like"}
    )

    with pytest.raises(ValueError, match="allow reason is inconsistent"):
        guard.validate_classifier_content(payload)


def test_classifier_rejects_block_with_safe_reason():
    payload = json.dumps(
        {"verdict": "block", "confidence": 0.99, "reason_code": "placeholder"}
    )

    with pytest.raises(ValueError, match="block reason is inconsistent"):
        guard.validate_classifier_content(payload)


def test_classifier_context_redacts_adjacent_candidates(tmp_path):
    first = "first-candidate-must-not-reach-model"
    second = "second-candidate-must-not-reach-model"
    artifact = tmp_path / "app.py"
    artifact.write_text(f"first = '{first}'\nsecond = '{second}'\nmode = 'runtime'\n")
    findings = [
        {"scanner": "one", "rule_id": "token", "line": 1},
        {"scanner": "two", "rule_id": "password", "line": 2},
    ]

    target = guard.classification_targets(findings)[0]
    messages = guard.classifier_messages(artifact, target)
    serialized = json.dumps(messages)

    assert first not in serialized
    assert second not in serialized
    assert serialized.count("REDACTED_CANDIDATE") == 2


def test_scanner_failure_fails_closed(tmp_path, monkeypatch):
    artifact = tmp_path / "app.py"
    artifact.write_text("ordinary = 'content'\n")
    monkeypatch.setenv("SHIFT_LEFTER_ROOT", str(tmp_path / "research"))

    def unavailable(_path, _transient):
        raise RuntimeError("missing")

    monkeypatch.setitem(guard.SCANNER_FUNCTIONS, "test-scanner", unavailable)
    result = guard.scan_file(artifact, scanners=("test-scanner",))

    assert result["verdict"] == "review"
    assert result["reason_code"] == "scanner_error_fail_closed"
    assert result["scanner_errors"] == [
        {"scanner": "test-scanner", "error": "RuntimeError"}
    ]


def test_findings_are_classified_with_redacted_context(tmp_path, monkeypatch):
    candidate = "SLAPI_LIVESECRETEXAMPLE123456"
    artifact = tmp_path / "app.py"
    artifact.write_text(f"# active runtime credential\napi_key = '{candidate}'\n")
    monkeypatch.setenv("SHIFT_LEFTER_ROOT", str(tmp_path / "research"))

    monkeypatch.setitem(
        guard.SCANNER_FUNCTIONS,
        "test-scanner",
        lambda path, transient: (
            [guard._finding("test-scanner", "api-key", 2, path)],
            "1.0",
        ),
    )

    def classify(_path, _finding):
        raise AssertionError("the enforcement path must not invoke the research model")

    monkeypatch.setattr(guard, "classify_redacted", classify)
    result = guard.scan_file(artifact, scanners=("test-scanner",))

    assert result["verdict"] == "review"
    assert result["reason_code"] == "strict_scanner_hold"
    assert result["finding_count"] == 1
    assert candidate not in str(result)


def test_clean_filter_blocks_before_emitting_bytes(tmp_path, monkeypatch):
    candidate = b"api_key = 'live-secret'\n"
    monkeypatch.setenv("SHIFT_LEFTER_ROOT", str(tmp_path / "research"))
    monkeypatch.setattr(
        guard,
        "scan_file",
        lambda path: {
            "verdict": "block",
            "reason_code": "classifier_block",
            "finding_count": 1,
        },
    )
    stdin = io.TextIOWrapper(io.BytesIO(candidate), encoding="utf-8")
    stdout_bytes = io.BytesIO()
    stdout = io.TextIOWrapper(stdout_bytes, encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "stdout", stdout)

    status = guard.filter_clean("app.py")
    stdout.flush()

    assert status == 2
    assert stdout_bytes.getvalue() == b""


def test_clean_filter_scans_nul_containing_input(tmp_path, monkeypatch):
    candidate = b"\0api_key = 'live-secret'\n"
    scanned = []
    monkeypatch.setenv("SHIFT_LEFTER_ROOT", str(tmp_path / "research"))

    def scan(path):
        scanned.append(path.read_bytes())
        return {
            "verdict": "block",
            "reason_code": "strict_scanner_hold",
            "finding_count": 1,
        }

    monkeypatch.setattr(guard, "scan_file", scan)
    stdin = io.TextIOWrapper(io.BytesIO(candidate), encoding="utf-8")
    stdout_bytes = io.BytesIO()
    stdout = io.TextIOWrapper(stdout_bytes, encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "stdout", stdout)

    status = guard.filter_clean("artifact.bin")
    stdout.flush()

    assert status == 2
    assert scanned == [candidate]
    assert stdout_bytes.getvalue() == b""


def test_install_uses_repo_local_required_filter_and_hooks(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)

    result = guard.install(repo)
    git_dir = Path(
        subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--absolute-git-dir"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )

    assert result["clean_filter"] == "required"
    assert (git_dir / "shift-lefter-hooks" / "pre-commit").is_file()
    assert (git_dir / "shift-lefter-hooks" / "pre-push").is_file()
    assert "* filter=shift-lefter" in (git_dir / "info" / "attributes").read_text()
    required = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "config",
            "--local",
            "--get",
            "filter.shift-lefter.required",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert required == "true"


def test_pre_push_scans_secret_removed_by_later_commit(tmp_path, monkeypatch):
    repo = tmp_path / "work"
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    for key, value in (
        ("user.email", "test@example.invalid"),
        ("user.name", "Test User"),
    ):
        subprocess.run(["git", "-C", str(repo), "config", key, value], check=True)
    artifact = repo / "app.py"
    artifact.write_text("value = 'safe'\n")
    subprocess.run(["git", "-C", str(repo), "add", "app.py"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "base"],
        check=True,
        capture_output=True,
    )
    old_sha = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    artifact.write_text("api_key = 'secret-in-intermediate-history'\n")
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-am", "add candidate"],
        check=True,
        capture_output=True,
    )
    artifact.write_text("value = 'safe again'\n")
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-am", "remove candidate"],
        check=True,
        capture_output=True,
    )
    new_sha = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    monkeypatch.setenv("SHIFT_LEFTER_ROOT", str(tmp_path / "research"))

    def classify(path):
        blocked = "secret-in-intermediate-history" in path.read_text(errors="ignore")
        return {
            "verdict": "block" if blocked else "allow",
            "reason_code": "strict_scanner_hold" if blocked else "no_scanner_finding",
            "finding_count": int(blocked),
        }

    monkeypatch.setattr(guard, "scan_file", classify)
    results = guard.scan_push(
        repo, [f"refs/heads/main {new_sha} refs/heads/main {old_sha}\n"]
    )

    assert any(item["verdict"] == "block" for item in results)


def test_pre_receive_scans_proposed_revision_not_worktree(tmp_path, monkeypatch):
    bare = tmp_path / "central.git"
    work = tmp_path / "work"
    subprocess.run(
        ["git", "init", "--bare", str(bare)], check=True, capture_output=True
    )
    subprocess.run(["git", "init", str(work)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(work), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(work), "config", "user.name", "Test User"], check=True
    )
    (work / "app.py").write_text("value = 'safe'\n")
    subprocess.run(["git", "-C", str(work), "add", "app.py"], check=True)
    subprocess.run(
        ["git", "-C", str(work), "commit", "-m", "safe"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(work), "push", str(bare), "HEAD:refs/heads/main"],
        check=True,
        capture_output=True,
    )
    old_sha = subprocess.run(
        ["git", "-C", str(work), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    (work / "app.py").write_text("api_key = 'synthetic-secret'\n")
    subprocess.run(["git", "-C", str(work), "add", "app.py"], check=True)
    subprocess.run(
        ["git", "-C", str(work), "commit", "-m", "candidate"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(work), "push", str(bare), "HEAD:refs/heads/candidate"],
        check=True,
        capture_output=True,
    )
    new_sha = subprocess.run(
        ["git", "-C", str(work), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    # Leave the proposed objects present but unreachable, as they are while a
    # real pre-receive hook is evaluating a quarantined transaction.
    subprocess.run(
        ["git", "-C", str(bare), "update-ref", "-d", "refs/heads/candidate"],
        check=True,
    )
    monkeypatch.setenv("SHIFT_LEFTER_ROOT", str(tmp_path / "research"))

    def classify_materialized_blob(path):
        blocked = "synthetic-secret" in path.read_text()
        return {
            "verdict": "block" if blocked else "allow",
            "reason_code": "classifier_block" if blocked else "no_scanner_finding",
            "finding_count": int(blocked),
        }

    monkeypatch.setattr(guard, "scan_file", classify_materialized_blob)
    results = guard.scan_receive(bare, [f"{old_sha} {new_sha} refs/heads/main\n"])

    assert len(results) == 1
    assert results[0]["path"] == "app.py"
    assert results[0]["verdict"] == "block"


def test_pre_receive_scans_secret_removed_by_later_commit(tmp_path, monkeypatch):
    bare = tmp_path / "central.git"
    work = tmp_path / "work"
    subprocess.run(
        ["git", "init", "--bare", str(bare)], check=True, capture_output=True
    )
    subprocess.run(["git", "init", str(work)], check=True, capture_output=True)
    for key, value in (
        ("user.email", "test@example.invalid"),
        ("user.name", "Test User"),
    ):
        subprocess.run(["git", "-C", str(work), "config", key, value], check=True)
    artifact = work / "app.py"
    artifact.write_text("value = 'safe'\n")
    subprocess.run(["git", "-C", str(work), "add", "app.py"], check=True)
    subprocess.run(
        ["git", "-C", str(work), "commit", "-m", "safe"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(work), "push", str(bare), "HEAD:refs/heads/main"],
        check=True,
        capture_output=True,
    )
    old_sha = subprocess.run(
        ["git", "-C", str(work), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    artifact.write_text("api_key = 'secret-in-intermediate-history'\n")
    subprocess.run(
        ["git", "-C", str(work), "commit", "-am", "add candidate"],
        check=True,
        capture_output=True,
    )
    artifact.write_text("value = 'safe again'\n")
    subprocess.run(
        ["git", "-C", str(work), "commit", "-am", "remove candidate"],
        check=True,
        capture_output=True,
    )
    new_sha = subprocess.run(
        ["git", "-C", str(work), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "-C", str(work), "push", str(bare), "HEAD:refs/heads/candidate"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(bare), "update-ref", "-d", "refs/heads/candidate"],
        check=True,
    )
    monkeypatch.setenv("SHIFT_LEFTER_ROOT", str(tmp_path / "research"))

    def classify_materialized_object(path):
        blocked = "secret-in-intermediate-history" in path.read_text(errors="ignore")
        return {
            "verdict": "block" if blocked else "allow",
            "reason_code": "classifier_block" if blocked else "no_scanner_finding",
            "finding_count": int(blocked),
        }

    monkeypatch.setattr(guard, "scan_file", classify_materialized_object)
    results = guard.scan_receive(bare, [f"{old_sha} {new_sha} refs/heads/main\n"])

    assert any(item["verdict"] == "block" for item in results)


def test_pre_receive_scans_commit_message_without_git_headers(tmp_path, monkeypatch):
    bare = tmp_path / "central.git"
    work = tmp_path / "work"
    subprocess.run(
        ["git", "init", "--bare", str(bare)], check=True, capture_output=True
    )
    subprocess.run(["git", "init", str(work)], check=True, capture_output=True)
    for key, value in (
        ("user.email", "test@example.invalid"),
        ("user.name", "Test User"),
    ):
        subprocess.run(["git", "-C", str(work), "config", key, value], check=True)
    (work / "app.py").write_text("value = 'safe'\n")
    subprocess.run(["git", "-C", str(work), "add", "app.py"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(work),
            "commit",
            "-m",
            "secret-in-commit-message",
        ],
        check=True,
        capture_output=True,
    )
    new_sha = subprocess.run(
        ["git", "-C", str(work), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "-C", str(work), "push", str(bare), "HEAD:refs/heads/candidate"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(bare), "update-ref", "-d", "refs/heads/candidate"],
        check=True,
    )
    monkeypatch.setenv("SHIFT_LEFTER_ROOT", str(tmp_path / "research"))
    observed = []

    def classify_materialized_object(path):
        content = path.read_text(errors="ignore")
        observed.append(content)
        blocked = "secret-in-commit-message" in content
        return {
            "verdict": "block" if blocked else "allow",
            "reason_code": "classifier_block" if blocked else "no_scanner_finding",
            "finding_count": int(blocked),
        }

    monkeypatch.setattr(guard, "scan_file", classify_materialized_object)
    results = guard.scan_receive(
        bare, [f"{guard.ZERO_SHA} {new_sha} refs/heads/main\n"]
    )

    assert any(item["verdict"] == "block" for item in results)
    assert all("tree " not in content for content in observed)
