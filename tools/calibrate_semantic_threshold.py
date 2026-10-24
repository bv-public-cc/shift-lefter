"""Freeze a semantic detection threshold on calibration data and score holdout.

The input records are already sanitized: this tool never reads source artifacts or
candidate values.  A lower detection threshold can be evaluated exactly from the
recorded per-candidate classifications because detection is monotonic (a qualifying
``secret`` decision can only change an allow to a block).  False-positive suppression
continues to use the decision recorded by the live runner and is never broadened.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _load_records(path: Path) -> dict[str, dict]:
    paired: dict[str, dict] = {}
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            row = json.loads(line)
            artifact_id = row["artifact_id"]
            condition = row["condition"]
            if condition in paired.setdefault(artifact_id, {}):
                raise ValueError(f"duplicate {condition} record for {artifact_id}")
            paired[artifact_id][condition] = row
    incomplete = sorted(
        artifact_id
        for artifact_id, rows in paired.items()
        if set(rows) != {"baseline", "hybrid"}
    )
    if incomplete:
        raise ValueError(f"incomplete record pairs: {incomplete[:3]}")
    return paired


def _detected_at(hybrid: dict, threshold: float) -> bool:
    if hybrid.get("reason_code") == "semantic_error_scanner_fallback":
        return False
    verdicts = hybrid.get("classifier_verdicts", [])
    confidences = hybrid.get("classifier_confidences", [])
    if len(verdicts) != len(confidences):
        raise ValueError(f"unaligned classifier outputs for {hybrid['artifact_id']}")
    return any(
        verdict == "secret" and float(confidence) >= threshold
        for verdict, confidence in zip(verdicts, confidences, strict=True)
    )


def _decision(rows: dict, threshold: float) -> str:
    if _detected_at(rows["hybrid"], threshold):
        return "block"
    return rows["hybrid"]["verdict"]


def score(
    paired: dict[str, dict], truth: dict[str, dict], threshold: float, partition: str
):
    metrics = {
        "artifact_count": 0,
        "baseline_false_negatives": 0,
        "baseline_false_positives": 0,
        "hybrid_false_negatives": 0,
        "hybrid_false_positives": 0,
        "recovered_false_negatives": 0,
        "introduced_false_negatives": 0,
        "suppressed_false_positives": 0,
        "introduced_false_positives": 0,
        "model_error_fallbacks": 0,
    }
    for artifact_id, rows in paired.items():
        expected = truth[artifact_id]
        if partition != "all" and expected["partition"] != partition:
            continue
        label = int(expected["label"])
        baseline = rows["baseline"]["verdict"]
        hybrid = _decision(rows, threshold)
        metrics["artifact_count"] += 1
        metrics["baseline_false_negatives"] += int(label == 1 and baseline == "allow")
        metrics["baseline_false_positives"] += int(label == 0 and baseline == "block")
        metrics["hybrid_false_negatives"] += int(label == 1 and hybrid == "allow")
        metrics["hybrid_false_positives"] += int(label == 0 and hybrid == "block")
        metrics["recovered_false_negatives"] += int(
            label == 1 and baseline == "allow" and hybrid == "block"
        )
        metrics["introduced_false_negatives"] += int(
            label == 1 and baseline == "block" and hybrid == "allow"
        )
        metrics["suppressed_false_positives"] += int(
            label == 0 and baseline == "block" and hybrid == "allow"
        )
        metrics["introduced_false_positives"] += int(
            label == 0 and baseline == "allow" and hybrid == "block"
        )
        metrics["model_error_fallbacks"] += int(
            rows["hybrid"].get("reason_code") == "semantic_error_scanner_fallback"
        )
    return metrics


def calibrate(
    records_path: Path, truth_path: Path, summary_path: Path, candidates: list[float]
):
    paired = _load_records(records_path)
    ground_truth = _load_json(truth_path)
    truth = {row["artifact_id"]: row for row in ground_truth["records"]}
    if set(paired) != set(truth):
        raise ValueError("record artifact IDs do not exactly match ground truth")
    summary = _load_json(summary_path)
    live_threshold = float(summary["semantic_detection_threshold"])
    normalized = sorted(set(float(value) for value in candidates), reverse=True)
    if not normalized or any(
        value <= 0 or value > live_threshold for value in normalized
    ):
        raise ValueError("candidate thresholds must be > 0 and <= the live threshold")

    calibration = []
    for threshold in normalized:
        metrics = score(paired, truth, threshold, "calibration")
        calibration.append({"threshold": threshold, "metrics": metrics})
    safe = [
        item
        for item in calibration
        if item["metrics"]["introduced_false_negatives"] == 0
        and item["metrics"]["introduced_false_positives"] == 0
    ]
    if not safe:
        raise ValueError("no candidate threshold satisfies the zero-regression gate")
    selected = max(
        safe,
        key=lambda item: (
            item["metrics"]["recovered_false_negatives"],
            item["threshold"],
        ),
    )["threshold"]
    return {
        "schema_version": 1,
        "method": "calibration-only threshold freeze with untouched holdout scoring",
        "privacy": "sanitized classifier outputs only; no source or candidate values read",
        "study": summary["study"],
        "source_set": summary["source_set"],
        "live_detection_threshold": live_threshold,
        "suppression_threshold_unchanged": summary["semantic_suppression_threshold"],
        "candidate_thresholds": calibration,
        "selected_detection_threshold": selected,
        "selection_rule": "maximize recovered calibration false negatives subject to zero introduced false positives and false negatives; prefer highest threshold on ties",
        "selected_metrics": {
            partition: score(paired, truth, selected, partition)
            for partition in ("calibration", "holdout", "all")
        },
        "inputs": {
            "records_sha256": _sha256(records_path),
            "ground_truth_sha256": _sha256(truth_path),
            "run_summary_sha256": _sha256(summary_path),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--run-summary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--candidate", type=float, action="append", required=True)
    args = parser.parse_args()
    report = calibrate(
        args.records,
        args.ground_truth,
        args.run_summary,
        args.candidate,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
