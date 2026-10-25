"""Activate the verified new final test without exposing its raw files."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from shift_lefter import experiment, trained_review

TEST_NAME = "trained-review-fresh-test-v1"
EXPECTED_COUNT = 4_800


def _safe_root() -> Path:
    root = experiment._research_root() / "trained-data" / trained_review.DATASET_NAME
    experiment._assert_outside_git(root)
    return root


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]


def activate() -> dict:
    safe = _safe_root()
    source = safe / "fresh-final-scanned.jsonl"
    privacy_path = safe / "fresh-final-privacy-verification.json"
    if not source.exists() or not privacy_path.exists():
        raise RuntimeError("scan and privacy verification must finish first")
    privacy = json.loads(privacy_path.read_text(encoding="utf-8"))
    if not privacy.get("passed"):
        raise RuntimeError("new final test did not pass privacy verification")
    rows = _read_jsonl(source)
    if len(rows) != EXPECTED_COUNT:
        raise RuntimeError("new final test has an unexpected row count")
    final = safe / "final.jsonl"
    previous = safe / "v7-final.jsonl"
    if previous.exists():
        raise RuntimeError("saved v7 final input already exists")
    if not final.exists():
        raise RuntimeError("v7 final input is missing")
    final.replace(previous)
    shutil.copyfile(source, final)
    scanner_rows = [
        {**row, "verdict": "block" if row["scanner_block"] else "allow"} for row in rows
    ]
    result = {
        "sample_count": len(rows),
        "repository_count": len({row["repo_group"] for row in rows}),
        "source": TEST_NAME,
        "selection_status": "activated only after training design was fixed",
        "v7_comparison_source": "evaluation-v7-operational-spark-qwen-calibrated",
        "baseline": trained_review.metrics(scanner_rows),
        "records_sha256": experiment._sha256_file(final),
        "saved_v7_features_sha256": experiment._sha256_file(previous),
    }
    experiment._write_json(safe / "final-summary.json", result)
    return result


def main() -> int:
    print(json.dumps(activate(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
