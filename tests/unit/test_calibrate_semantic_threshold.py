import importlib.util
import json
from pathlib import Path

TOOL = Path(__file__).parents[2] / "tools" / "calibrate_semantic_threshold.py"
SPEC = importlib.util.spec_from_file_location("calibrate_semantic_threshold", TOOL)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _write_inputs(tmp_path):
    truth = {
        "records": [
            {"artifact_id": "cal-secret", "label": 1, "partition": "calibration"},
            {"artifact_id": "cal-clean", "label": 0, "partition": "calibration"},
            {"artifact_id": "hold-secret", "label": 1, "partition": "holdout"},
            {"artifact_id": "hold-fp", "label": 0, "partition": "holdout"},
            {"artifact_id": "hold-error", "label": 1, "partition": "holdout"},
        ]
    }
    rows = []

    def pair(artifact_id, baseline, hybrid, verdicts=(), confidences=(), reason="test"):
        rows.extend(
            [
                {
                    "artifact_id": artifact_id,
                    "condition": "baseline",
                    "verdict": baseline,
                },
                {
                    "artifact_id": artifact_id,
                    "condition": "hybrid",
                    "verdict": hybrid,
                    "classifier_verdicts": list(verdicts),
                    "classifier_confidences": list(confidences),
                    "reason_code": reason,
                },
            ]
        )

    pair("cal-secret", "allow", "allow", ["secret"], [0.85])
    pair("cal-clean", "allow", "allow", ["secret"], [0.75])
    pair("hold-secret", "allow", "allow", ["secret"], [0.85])
    pair("hold-fp", "block", "allow", ["false_positive"], [0.95])
    pair(
        "hold-error",
        "allow",
        "allow",
        ["error"],
        [],
        reason="semantic_error_scanner_fallback",
    )
    truth_path = tmp_path / "truth.json"
    records_path = tmp_path / "records.jsonl"
    summary_path = tmp_path / "summary.json"
    truth_path.write_text(json.dumps(truth))
    records_path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    summary_path.write_text(
        json.dumps(
            {
                "study": "unit",
                "source_set": "unit",
                "semantic_detection_threshold": 0.9,
                "semantic_suppression_threshold": 0.9,
            }
        )
    )
    return records_path, truth_path, summary_path


def test_calibration_freezes_safe_threshold_and_scores_holdout(tmp_path):
    inputs = _write_inputs(tmp_path)
    report = MODULE.calibrate(*inputs, [0.9, 0.85, 0.75])

    assert report["selected_detection_threshold"] == 0.85
    holdout = report["selected_metrics"]["holdout"]
    assert holdout["recovered_false_negatives"] == 1
    assert holdout["introduced_false_negatives"] == 0
    assert holdout["suppressed_false_positives"] == 1
    assert holdout["model_error_fallbacks"] == 1
    unsafe = next(
        item for item in report["candidate_thresholds"] if item["threshold"] == 0.75
    )
    assert unsafe["metrics"]["introduced_false_positives"] == 1


def test_rejects_incomplete_pairs(tmp_path):
    records, truth, summary = _write_inputs(tmp_path)
    lines = records.read_text().splitlines()
    records.write_text("\n".join(lines[:-1]) + "\n")

    try:
        MODULE.calibrate(records, truth, summary, [0.9])
    except ValueError as error:
        assert "incomplete record pairs" in str(error)
    else:
        raise AssertionError("expected an incomplete-pair failure")
