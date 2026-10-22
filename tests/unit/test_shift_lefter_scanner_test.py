import json
from types import SimpleNamespace

from shift_lefter import scanner_test


def test_parallel_runner_writes_deterministic_manifest_order(tmp_path, monkeypatch):
    research = tmp_path / "research"
    raw = research / "raw" / "expanded"
    artifacts = raw / "artifacts"
    artifacts.mkdir(parents=True)
    records = []
    for index in range(8):
        path = artifacts / f"item-{index}.txt"
        path.write_text(f"safe item {index}\n")
        records.append(
            {
                "artifact_id": f"item-{index}",
                "filename": path.name,
                "label": 0,
                "sha256": scanner_test.experiment._sha256_file(path),
            }
        )
    (raw / "ground_truth.json").write_text(json.dumps({"records": records}))
    monkeypatch.setattr(scanner_test.experiment, "_research_root", lambda: research)
    monkeypatch.setattr(
        scanner_test,
        "_execution_manifest",
        lambda _commit, _source: {"worktree_clean": True, "source_sha256": {}},
    )
    monkeypatch.setattr(
        scanner_test.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout="a" * 40),
    )
    monkeypatch.setattr(
        scanner_test.guard,
        "scan_candidates",
        lambda _path, _scanners: {
            "findings": [],
            "scanner_errors": [],
            "scanner_versions": {"test": "1"},
        },
    )

    scanner_test.run(
        repeats=1,
        result_name="evaluation-v3-parallel-test",
        source_set="expanded",
        workers=4,
    )

    output = research / "sanitized-results/evaluation-v3-parallel-test"
    rows = [
        json.loads(line) for line in (output / "records.jsonl").read_text().splitlines()
    ]
    baseline_ids = [
        row["artifact_id"] for row in rows if row["condition"] == "baseline"
    ]
    assert baseline_ids == [record["artifact_id"] for record in records]
    assert json.loads((output / "run-summary.json").read_text())["worker_count"] == 4


def test_runner_limits_discovery_to_selected_scanner(tmp_path, monkeypatch):
    research = tmp_path / "research"
    raw = research / "raw" / "expanded"
    artifacts = raw / "artifacts"
    artifacts.mkdir(parents=True)
    artifact = artifacts / "item.txt"
    artifact.write_text("safe item\n")
    (raw / "ground_truth.json").write_text(
        json.dumps(
            {
                "records": [
                    {
                        "artifact_id": "item-1",
                        "filename": artifact.name,
                        "label": 0,
                        "sha256": scanner_test.experiment._sha256_file(artifact),
                    }
                ]
            }
        )
    )
    monkeypatch.setattr(scanner_test.experiment, "_research_root", lambda: research)
    monkeypatch.setattr(
        scanner_test,
        "_execution_manifest",
        lambda _commit, _source: {"worktree_clean": True, "source_sha256": {}},
    )
    monkeypatch.setattr(
        scanner_test.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout="a" * 40),
    )
    observed = []

    def scan(_path, scanners):
        observed.append(tuple(scanners))
        return {
            "findings": [],
            "scanner_errors": [],
            "scanner_versions": {"gitleaks": "test"},
        }

    monkeypatch.setattr(scanner_test.guard, "scan_candidates", scan)
    name = "evaluation-v5-gitleaks-test"
    summary = scanner_test.run(
        repeats=1,
        result_name=name,
        source_set="expanded",
        workers=1,
        scanners=["gitleaks"],
    )

    assert observed == [("gitleaks",)]
    assert summary["selected_scanners"] == ["gitleaks"]
    rows = [
        json.loads(line)
        for line in (research / "sanitized-results" / name / "records.jsonl")
        .read_text()
        .splitlines()
    ]
    assert all(row["selected_scanners"] == ["gitleaks"] for row in rows)


def test_scanner_selection_rejects_empty_or_unknown_values():
    with __import__("pytest").raises(ValueError, match="at least one"):
        scanner_test._scanners([])
    with __import__("pytest").raises(ValueError, match="unsupported"):
        scanner_test._scanners(["not-a-scanner"])


def test_safety_verification_scans_non_raw_research_storage(tmp_path, monkeypatch):
    research = tmp_path / "research"
    repo = tmp_path / "repo"
    state = tmp_path / "home" / ".shift-lefter"
    result_name = "evaluation-v2-test-model"
    canary = "synthetic-canary-that-must-not-persist"
    raw = research / "raw" / "evaluation"
    output = research / "sanitized-results" / result_name
    raw.mkdir(parents=True)
    output.mkdir(parents=True)
    repo.mkdir()
    state.mkdir(parents=True)
    (raw / "canary_index.json").write_text(
        json.dumps({"canaries": [canary]}), encoding="utf-8"
    )
    (output / "run-summary.json").write_text(
        json.dumps({"model_endpoints": ["https://model.internal.example:8001/v1"]}),
        encoding="utf-8",
    )
    leaked = research / "transient" / "interrupted-report.json"
    leaked.parent.mkdir()
    leaked.write_text(canary, encoding="utf-8")

    monkeypatch.setattr(scanner_test.experiment, "_research_root", lambda: research)
    monkeypatch.setattr(scanner_test.experiment, "ROOT", repo)
    monkeypatch.setattr(scanner_test.Path, "home", lambda: tmp_path / "home")
    monkeypatch.setenv("SHIFT_LEFTER_ALLOWED_MODEL_HOSTS", "model.internal.example")

    result = scanner_test.verify(result_name)

    assert result["passed"] is False
    assert result["raw_canary_hit_count_outside_approved_root"] == 1
    assert result["raw_canary_hit_paths"] == [str(leaked)]


def test_compare_uses_requested_output_name(tmp_path, monkeypatch):
    research = tmp_path / "research"
    root = research / "sanitized-results"
    source_hashes = {"guard.py": "abc"}
    analysis = {
        "baseline": {"tp": 1, "fp": 1, "tn": 0, "fn": 0},
        "hybrid": {"tp": 1, "fp": 0, "tn": 1, "fn": 0},
        "false_positive_reduction": 1.0,
        "repeat_exact_agreement": 1.0,
        "classifier_latency_median_seconds": 0.1,
        "classifier_latency_p95_seconds": 0.2,
    }
    conditions = (
        "evaluation-v3-condition-a",
        "evaluation-v3-condition-b",
    )
    for index, name in enumerate(conditions):
        output = root / name
        output.mkdir(parents=True)
        rows = [
            {
                "artifact_id": "item-1",
                "condition": "baseline",
                "finding_count": 1,
                "finding_keys": ["same"],
                "finding_scanners": ["gitleaks"],
                "scanner_error_types": [],
            },
            {
                "artifact_id": "item-1",
                "condition": "hybrid",
                "model_names": [f"model-{index}"],
            },
        ]
        (output / "records.jsonl").write_text(
            "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
        )
        (output / "run-summary.json").write_text(
            json.dumps(
                {
                    "source_sha256": source_hashes,
                    "model_endpoints": [f"https://model-{index}.example/v1"],
                    "records_sha256": str(index),
                }
            ),
            encoding="utf-8",
        )
        (output / "analysis.json").write_text(json.dumps(analysis), encoding="utf-8")
        (output / "safety-verification.json").write_text(
            json.dumps({"passed": True}), encoding="utf-8"
        )

    monkeypatch.setattr(scanner_test.experiment, "_research_root", lambda: research)
    name = "evaluation-v3-custom-comparison"
    result = scanner_test.compare(list(conditions), name)

    assert result["study"] == name
    assert (root / f"{name}.json").is_file()


def test_summary_keeps_different_scanner_conditions_separate(tmp_path, monkeypatch):
    research = tmp_path / "research"
    root = research / "sanitized-results"
    conditions = (
        ("evaluation-v5-gitleaks-model-a", "gitleaks", "model-a"),
        ("evaluation-v5-trufflehog-model-a", "trufflehog", "model-a"),
    )
    analysis = {
        "baseline": {"tp": 1, "fp": 1, "tn": 0, "fn": 0},
        "hybrid": {"tp": 1, "fp": 0, "tn": 1, "fn": 0},
        "false_positive_reduction": 1.0,
        "classifier_latency_median_seconds": 0.1,
        "classifier_latency_p95_seconds": 0.2,
    }
    for name, scanner, model in conditions:
        output = root / name
        output.mkdir(parents=True)
        (output / "records.jsonl").write_text(
            json.dumps(
                {
                    "artifact_id": "item-1",
                    "condition": "hybrid",
                    "model_names": [model],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        (output / "run-summary.json").write_text(
            json.dumps(
                {
                    "selected_scanners": [scanner],
                    "source_sha256": {"runner": "same"},
                    "model_endpoints": [f"https://{model}.example/v1"],
                    "records_sha256": scanner,
                }
            ),
            encoding="utf-8",
        )
        (output / "analysis.json").write_text(json.dumps(analysis), encoding="utf-8")
        (output / "safety-verification.json").write_text(
            json.dumps({"passed": True}), encoding="utf-8"
        )

    monkeypatch.setattr(scanner_test.experiment, "_research_root", lambda: research)
    output_name = "evaluation-v5-single-scanner-summary-test"
    result = scanner_test.summarize(
        [condition[0] for condition in conditions], output_name
    )

    assert result["condition_count"] == 2
    assert result["scanner_outputs_expected_to_differ"] is True
    assert {condition["scanner"] for condition in result["conditions"].values()} == {
        "gitleaks",
        "trufflehog",
    }
    assert (root / f"{output_name}.json").is_file()
