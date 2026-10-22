import json

import pytest

from tools import sanitize_results


def test_transform_removes_private_details_and_renames_study():
    original = {
        "exploratory_follow_on": True,
        "platform_commit": "a" * 40,
        "source_commit": "b" * 40,
        "study": "private-internal-name",
        "source_sha256": {"ensemble_experiment.py": "c" * 64},
        "model_endpoints": ["https://private.example/v1"],
        "nested": {"observed_model_endpoints": ["http://private.example/v1"]},
    }

    public = sanitize_results.transform(
        original, "Local Model A", "evaluation-v4-combined-scanners-model-a"
    )

    assert "platform_commit" not in public
    assert "source_commit" not in public
    assert "exploratory_follow_on" not in public
    assert public["study"] == "evaluation-v4-combined-scanners-model-a"
    assert "ensemble_experiment.py" not in public["source_sha256"]
    assert public["source_sha256"]["execution_runner.py"] == "c" * 64
    assert public["model_endpoints"] == ["Local Model A"]
    assert public["nested"]["observed_model_endpoints"] == ["Local Model A"]
    assert "private.example" not in str(public)


@pytest.mark.parametrize("matches_release", [False, True])
def test_main_records_source_equivalence_flag(tmp_path, monkeypatch, matches_release):
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    (source / "records.jsonl").write_text('{"study":"private"}\n')
    (source / "run-summary.json").write_text(json.dumps({"records_sha256": "a" * 64}))
    for filename in ("analysis.json", "safety-verification.json"):
        (source / filename).write_text("{}")

    argv = [
        "sanitize_results.py",
        str(source),
        str(destination),
        "--endpoint-label",
        "Local Model",
    ]
    if matches_release:
        argv.append("--execution-source-matches-release")
    monkeypatch.setattr("sys.argv", argv)

    assert sanitize_results.main() == 0
    summary = json.loads((destination / "run-summary.json").read_text())
    assert summary["execution_source_matches_release"] is matches_release
