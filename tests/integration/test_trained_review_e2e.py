from pathlib import Path

from shift_lefter import trained_review


def test_trained_review_end_to_end_keeps_scanner_safety(tmp_path: Path) -> None:
    secret_path = tmp_path / "runtime.py"
    secret_path.write_text(
        'github_token = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"\n',
        encoding="utf-8",
    )
    example_path = tmp_path / "guide.md"
    example_path.write_text(
        "github_token=ghp_EXAMPLE_REPLACE_WITH_TOKEN________\n",
        encoding="utf-8",
    )
    secret = trained_review.safe_example(secret_path)
    example = trained_review.safe_example(example_path)
    rows = [
        {
            "artifact_id": "secret",
            "label": 1,
            "scanner_block": False,
            **secret,
        },
        {
            "artifact_id": "example",
            "label": 0,
            "scanner_block": True,
            **example,
        },
    ]
    decided = trained_review.apply_policy(
        rows,
        [0.99, 0.01],
        detection_threshold=0.9,
        suppression_threshold=0.9,
    )
    assert [row["verdict"] for row in decided] == ["block", "allow"]
    assert trained_review.incremental_outcomes(decided) == {
        "recovered_misses": 1,
        "introduced_misses": 0,
        "removed_false_alarms": 1,
        "introduced_false_alarms": 0,
    }


def test_uncertain_output_retains_each_scanner_decision() -> None:
    rows = [
        {
            "artifact_id": "found",
            "label": 1,
            "scanner_block": True,
            "hard_block": False,
            "fixed_safe": False,
        },
        {
            "artifact_id": "not-found",
            "label": 0,
            "scanner_block": False,
            "hard_block": False,
            "fixed_safe": False,
        },
    ]
    decided = trained_review.apply_policy(
        rows,
        [None, None],
        detection_threshold=0.9,
        suppression_threshold=0.9,
    )
    assert [row["verdict"] for row in decided] == ["block", "allow"]
    assert all(row["reason_code"] == "model_error_scanner_fallback" for row in decided)
