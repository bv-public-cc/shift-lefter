import json
from pathlib import Path

import pytest

from shift_lefter import experiment
from shift_lefter.experiment import decide, generate


def test_hard_block_cannot_be_downgraded():
    verdict, reason = decide(
        [{"rule_id": "shift-private-key"}],
        [
            {
                "verdict": "allow",
                "confidence": 1.0,
                "reason_code": "documentation_example",
            }
        ],
    )
    assert verdict == "block"
    assert reason == "non_overridable_hard_block"


def test_unknown_rule_fails_closed():
    verdict, _ = decide([{"rule_id": "new-unknown-rule"}], [])
    assert verdict == "review"


def test_classifier_error_fails_closed():
    verdict, _ = decide([{"rule_id": "shift-api-token"}], [{"error": "TimeoutError"}])
    assert verdict == "review"


def test_generator_keeps_balanced_channels_and_expected_labels(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIFT_LEFTER_ROOT", str(tmp_path / "outside-git"))
    result = generate("pilot", 50, 5009)
    manifest = json.loads(
        (tmp_path / "outside-git/raw/pilot/ground_truth.json").read_text()
    )
    assert result["count"] == 50
    assert manifest["positive_count"] == 15
    assert manifest["negative_count"] == 35
    counts = {}
    for row in manifest["records"]:
        counts[row["channel"]] = counts.get(row["channel"], 0) + 1
    assert set(counts.values()) == {10}

    positives = [r for r in manifest["records"] if r["label"] == 1]
    assert {r["category"] for r in positives} == {
        "api_token",
        "generic_token",
        "password",
        "basic_auth",
        "private_key",
    }


def test_expanded_generator_has_3000_diverse_labeled_artifacts(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIFT_LEFTER_ROOT", str(tmp_path / "outside-git"))
    result = generate(experiment.EXPANDED_SET, 3000, 83017)
    raw = tmp_path / "outside-git/raw" / experiment.EXPANDED_SET
    manifest = json.loads((raw / "ground_truth.json").read_text())

    assert result["count"] == 3000
    assert manifest["positive_count"] == 1000
    assert manifest["negative_count"] == 2000
    assert len({row["category"] for row in manifest["records"]}) >= 15
    assert {row["channel"] for row in manifest["records"]} == set(experiment.CHANNELS)
    assert len(list((raw / "artifacts").iterdir())) == 3000


def test_generator_refuses_git_worktree(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    monkeypatch.setenv("SHIFT_LEFTER_ROOT", str(tmp_path / "research"))
    with pytest.raises(RuntimeError, match="inside a Git worktree"):
        generate("pilot", 50, 5009)


def test_developer_gate_blocks_before_any_git_operation(tmp_path, monkeypatch):
    artifact = tmp_path / "candidate.txt"
    artifact.write_text("synthetic candidate")
    monkeypatch.setenv("SHIFT_LEFTER_ROOT", str(tmp_path / "isolated"))
    monkeypatch.setattr(
        experiment,
        "scan_artifact",
        lambda path, report: (
            [{"rule_id": "shift-private-key", "line": 1}],
            0.01,
            "test",
        ),
    )
    result = experiment.gate_path(artifact)
    assert result["verdict"] == "block"
    assert result["reason_code"] == "non_overridable_hard_block"
    assert not (tmp_path / ".git").exists()


def test_developer_gate_allows_clean_artifact(tmp_path, monkeypatch):
    artifact = tmp_path / "clean.txt"
    artifact.write_text("ordinary content")
    monkeypatch.setenv("SHIFT_LEFTER_ROOT", str(tmp_path / "isolated"))
    monkeypatch.setattr(
        experiment, "scan_artifact", lambda path, report: ([], 0.01, "test")
    )
    result = experiment.gate_path(artifact)
    assert result["verdict"] == "allow"
    assert result["finding_count"] == 0
