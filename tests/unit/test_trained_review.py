from pathlib import Path

from shift_lefter import trained_review


def test_safe_example_excludes_source_and_candidate_values(tmp_path: Path) -> None:
    secret = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    path = tmp_path / "settings.py"
    path.write_text(f'github_token = "{secret}"\n', encoding="utf-8")
    result = trained_review.safe_example(path)
    assert secret not in result["model_input"]
    assert str(path) not in result["model_input"]
    assert "github_pat" in result["model_input"]


def test_fixed_rule_marks_placeholder_without_exposing_it(tmp_path: Path) -> None:
    path = tmp_path / "example.env"
    path.write_text(
        "GITHUB_TOKEN=ghp_EXAMPLE_REPLACE_WITH_TOKEN________\n",
        encoding="utf-8",
    )
    result = trained_review.safe_example(path)
    assert result["fixed_safe"] is True
    assert "EXAMPLE_REPLACE" not in result["model_input"]


def test_private_key_is_always_blocked() -> None:
    verdict, reason = trained_review.policy_decision(
        scanner_block=False,
        hard_block=True,
        fixed_safe=False,
        secret_probability=0.0,
        detection_threshold=0.9,
        suppression_threshold=0.9,
    )
    assert (verdict, reason) == ("block", "non_overridable_hard_block")


def test_private_key_stays_blocked_when_model_fails() -> None:
    verdict, reason = trained_review.policy_decision(
        scanner_block=False,
        hard_block=True,
        fixed_safe=False,
        secret_probability=None,
        detection_threshold=0.9,
        suppression_threshold=0.9,
        model_error=True,
    )
    assert (verdict, reason) == ("block", "non_overridable_hard_block")


def test_model_error_uses_scanner_decision() -> None:
    blocked = trained_review.policy_decision(
        scanner_block=True,
        hard_block=False,
        fixed_safe=True,
        secret_probability=None,
        detection_threshold=0.9,
        suppression_threshold=0.9,
        model_error=True,
    )
    allowed = trained_review.policy_decision(
        scanner_block=False,
        hard_block=False,
        fixed_safe=False,
        secret_probability=None,
        detection_threshold=0.9,
        suppression_threshold=0.9,
        model_error=True,
    )
    assert blocked[0] == "block"
    assert allowed[0] == "allow"


def test_scanner_error_cannot_be_suppressed() -> None:
    verdict, reason = trained_review.policy_decision(
        scanner_block=True,
        hard_block=False,
        fixed_safe=True,
        secret_probability=0.0,
        detection_threshold=0.9,
        suppression_threshold=0.9,
        scanner_error=True,
    )
    assert (verdict, reason) == ("block", "scanner_error_non_overridable")


def test_nonnumeric_model_output_retains_scanner_decision() -> None:
    verdict, reason = trained_review.policy_decision(
        scanner_block=True,
        hard_block=False,
        fixed_safe=True,
        secret_probability="not-a-number",  # type: ignore[arg-type]
        detection_threshold=0.9,
        suppression_threshold=0.9,
    )
    assert (verdict, reason) == (
        "block",
        "invalid_model_output_scanner_fallback",
    )


def test_detection_and_suppression_have_separate_thresholds() -> None:
    detection = trained_review.policy_decision(
        scanner_block=False,
        hard_block=False,
        fixed_safe=False,
        secret_probability=0.91,
        detection_threshold=0.9,
        suppression_threshold=0.99,
    )
    suppression = trained_review.policy_decision(
        scanner_block=True,
        hard_block=False,
        fixed_safe=True,
        secret_probability=0.01,
        detection_threshold=0.99,
        suppression_threshold=0.98,
    )
    retained = trained_review.policy_decision(
        scanner_block=True,
        hard_block=False,
        fixed_safe=False,
        secret_probability=0.0,
        detection_threshold=0.9,
        suppression_threshold=0.9,
    )
    assert detection[0] == "block"
    assert suppression[0] == "allow"
    assert retained[0] == "block"


def test_threshold_selection_rejects_new_errors() -> None:
    rows = [
        {
            "label": 1,
            "scanner_block": False,
            "hard_block": False,
            "fixed_safe": False,
        },
        {
            "label": 0,
            "scanner_block": True,
            "hard_block": False,
            "fixed_safe": True,
        },
        {
            "label": 1,
            "scanner_block": True,
            "hard_block": True,
            "fixed_safe": False,
        },
    ]
    selected = trained_review.select_thresholds(rows, [0.95, 0.05, 0.0], grid=[0.9])
    assert selected["incremental_outcomes"] == {
        "recovered_misses": 1,
        "introduced_misses": 0,
        "removed_false_alarms": 1,
        "introduced_false_alarms": 0,
    }
