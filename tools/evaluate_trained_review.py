"""Calibrate trained policies and evaluate them once on the final repositories."""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path

from shift_lefter import experiment, trained_review

MODELS = ("lightgbm", "granite", "qwen")
RESULT_NAME = "evaluation-v8-trained-review"


def _data_root() -> Path:
    return experiment._research_root() / "trained-data" / trained_review.DATASET_NAME


def _model_root(name: str) -> Path:
    return experiment._research_root() / "models" / trained_review.DATASET_NAME / name


def _result_root() -> Path:
    root = experiment._research_root() / "sanitized-results" / RESULT_NAME
    root.mkdir(parents=True, exist_ok=True)
    return root


def _read(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]


def _probabilities(name: str, split: str, rows: list[dict]) -> list[float | None]:
    predictions = {
        row["artifact_id"]: float(row["secret_probability"])
        for row in _read(_model_root(name) / f"{split}-predictions.jsonl")
    }
    if set(predictions) != {row["artifact_id"] for row in rows}:
        raise RuntimeError(f"{name} predictions do not match {split} data")
    return [predictions[row["artifact_id"]] for row in rows]


def calibrate(name: str) -> dict:
    rows = _read(_data_root() / "setup-scanned.jsonl")
    probabilities = _probabilities(name, "setup", rows)
    selected = trained_review.select_thresholds(rows, probabilities)
    result = {
        "model": name,
        "selection_data": "setup repositories only",
        "setup_sample_count": len(rows),
        "setup_repository_count": len({row["repo_group"] for row in rows}),
        **selected,
    }
    experiment._write_json(_model_root(name) / "thresholds.json", result)
    return result


def _v7_metrics() -> dict:
    path = (
        experiment._research_root()
        / "sanitized-results"
        / "evaluation-v7-operational-spark-qwen-calibrated"
        / "analysis.json"
    )
    value = json.loads(path.read_text(encoding="utf-8"))
    return value["partition_metrics"]["holdout"]


def evaluate(name: str) -> dict:
    rows = _read(_data_root() / "final.jsonl")
    probabilities = _probabilities(name, "final", rows)
    thresholds = json.loads(
        (_model_root(name) / "thresholds.json").read_text(encoding="utf-8")
    )
    decided = trained_review.apply_policy(
        rows,
        probabilities,
        detection_threshold=float(thresholds["detection_threshold"]),
        suppression_threshold=float(thresholds["suppression_threshold"]),
    )
    scanner_rows = [
        {
            **row,
            "verdict": "block" if row["scanner_block"] else "allow",
        }
        for row in rows
    ]
    fixed_rule_rows = []
    for row in rows:
        verdict, reason = trained_review.policy_decision(
            scanner_block=bool(row["scanner_block"]),
            hard_block=bool(row["hard_block"]),
            fixed_safe=bool(row["fixed_safe"]),
            secret_probability=0.0,
            detection_threshold=1.0,
            suppression_threshold=1.0,
            scanner_error=bool(row.get("scanner_error", False)),
        )
        fixed_rule_rows.append({**row, "verdict": verdict, "reason_code": reason})
    model_only_rows = [
        {
            **row,
            "verdict": "block" if probability >= 0.5 else "allow",
        }
        for row, probability in zip(rows, probabilities, strict=True)
    ]
    model_root = _model_root(name)
    latency = json.loads(
        (model_root / "final-prediction-summary.json").read_text(encoding="utf-8")
    )
    batch_one_latency = json.loads(
        (model_root / "batch-one-latency.json").read_text(encoding="utf-8")
    )
    training = json.loads(
        (model_root / "training-manifest.json").read_text(encoding="utf-8")
    )
    private_rows = [row for row in decided if row["hard_block"]]
    final_summary = json.loads(
        (_data_root() / "final-summary.json").read_text(encoding="utf-8")
    )
    hybrid_metrics = trained_review.metrics(decided)
    fixed_rule_metrics = trained_review.metrics(fixed_rule_rows)
    result = {
        "study": RESULT_NAME,
        "model": name,
        "input_version": trained_review.MODEL_INPUT_VERSION,
        "final_data": final_summary["source"],
        "final_sample_count": len(rows),
        "final_repository_count": len({row["repo_group"] for row in rows}),
        "threshold_source": "setup repositories only",
        "detection_threshold": thresholds["detection_threshold"],
        "suppression_threshold": thresholds["suppression_threshold"],
        "scanner_baseline": trained_review.metrics(scanner_rows),
        "scanner_plus_fixed_rules": fixed_rule_metrics,
        "trained_model_only": trained_review.metrics(model_only_rows),
        "scanner_plus_trained_model": hybrid_metrics,
        "incremental_outcomes": trained_review.incremental_outcomes(decided),
        "trained_model_value_beyond_fixed_rules": {
            "additional_true_positives": hybrid_metrics["tp"]
            - fixed_rule_metrics["tp"],
            "additional_false_positives": hybrid_metrics["fp"]
            - fixed_rule_metrics["fp"],
            "additional_false_negatives": hybrid_metrics["fn"]
            - fixed_rule_metrics["fn"],
            "additional_true_negatives": hybrid_metrics["tn"]
            - fixed_rule_metrics["tn"],
        },
        "v7_reference": _v7_metrics(),
        "private_key_file_count": len(private_rows),
        "private_key_files_blocked": sum(
            row["verdict"] == "block" for row in private_rows
        ),
        "reason_counts": dict(
            sorted(
                {
                    reason: sum(row["reason_code"] == reason for row in decided)
                    for reason in {row["reason_code"] for row in decided}
                }.items()
            )
        ),
        "latency": {
            "batched_final_test": {
                "total_inference_seconds": latency["total_inference_seconds"],
                "mean_seconds_per_file": latency["mean_seconds_per_file"],
            },
            "developer_scale_batch_one": batch_one_latency,
        },
        "model_artifact": training,
        "final_predictions_sha256": latency["predictions_sha256"],
    }
    destination = _result_root() / name
    destination.mkdir(parents=True, exist_ok=True)
    experiment._write_json(destination / "analysis.json", result)
    records = destination / "records.jsonl"
    if records.exists():
        raise RuntimeError(f"refusing to overwrite final records: {records}")
    with records.open("w", encoding="utf-8", newline="\n") as handle:
        for row, probability in zip(decided, probabilities, strict=True):
            handle.write(
                json.dumps(
                    {
                        "artifact_id": row["artifact_id"],
                        "label": row["label"],
                        "scanner_block": row["scanner_block"],
                        "hard_block": row["hard_block"],
                        "fixed_safe": row["fixed_safe"],
                        "secret_probability": round(float(probability), 9),
                        "verdict": row["verdict"],
                        "reason_code": row["reason_code"],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )
    result["records_sha256"] = experiment._sha256_file(records)
    experiment._write_json(destination / "analysis.json", result)
    return result


def compare() -> dict:
    analyses = {
        name: json.loads(
            (_result_root() / name / "analysis.json").read_text(encoding="utf-8")
        )
        for name in MODELS
    }
    scanner_values = {
        json.dumps(value["scanner_baseline"], sort_keys=True)
        for value in analyses.values()
    }
    if len(scanner_values) != 1:
        raise RuntimeError("scanner baseline differs between trained approaches")
    result = {
        "study": RESULT_NAME,
        "input_version": trained_review.MODEL_INPUT_VERSION,
        "same_model_inputs": True,
        "same_final_repositories": True,
        "scanner_baseline_identical": True,
        "models": analyses,
    }
    experiment._write_json(_result_root() / "model-comparison.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    calibration = sub.add_parser("calibrate")
    calibration.add_argument("--model", choices=MODELS, required=True)
    evaluation = sub.add_parser("evaluate")
    evaluation.add_argument("--model", choices=MODELS, required=True)
    sub.add_parser("compare")
    args = parser.parse_args()
    result = (
        calibrate(args.model)
        if args.command == "calibrate"
        else evaluate(args.model) if args.command == "evaluate" else compare()
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
