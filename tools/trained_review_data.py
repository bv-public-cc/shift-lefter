"""Build the private training data and the untouched final evaluation inputs.

Raw generated files stay under the private research root. The derived JSONL
files contain only the feature packet defined in shift_lefter.trained_review.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import subprocess
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from shift_lefter import experiment, guard, operational_corpus, trained_review

TRAIN_COUNT = 30_000
SETUP_COUNT = 1_200
FILES_PER_REPOSITORY = 20
SEED = 410_041
FINAL_SOURCE = "operational-holdout-v1"
V7_RESULT = "evaluation-v7-operational-spark-qwen-calibrated"


def _append(path: Path, value: dict) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def _safe_root() -> Path:
    root = experiment._research_root() / "trained-data" / trained_review.DATASET_NAME
    experiment._assert_outside_git(root)
    return root


def _raw_root() -> Path:
    root = experiment._research_root() / "raw" / trained_review.DATASET_NAME
    experiment._assert_outside_git(root)
    return root


def build() -> dict:
    count = TRAIN_COUNT + SETUP_COUNT
    repo_count = count // FILES_PER_REPOSITORY
    training_repos = TRAIN_COUNT // FILES_PER_REPOSITORY
    raw = _raw_root()
    safe = _safe_root()
    if raw.exists() or safe.exists():
        raise RuntimeError("refusing to overwrite the trained-review data")
    artifacts = raw / "artifacts"
    artifacts.mkdir(parents=True, mode=0o700)
    safe.mkdir(parents=True, mode=0o700)
    rng = random.Random(SEED)
    labels = [1] * (count // 3) + [0] * (count - count // 3)
    rng.shuffle(labels)
    positive_index = 0
    negative_index = 0
    records = []
    canaries = []
    counts: Counter[str] = Counter()
    started = time.perf_counter()
    for index, label in enumerate(labels):
        repo_number = index % repo_count
        partition = "train" if repo_number < training_repos else "setup"
        repo_id = f"trained-repo-{repo_number:04d}"
        if label:
            family = operational_corpus.POSITIVE_FAMILIES[
                positive_index % len(operational_corpus.POSITIVE_FAMILIES)
            ]
            positive_index += 1
            key, value = operational_corpus._positive(rng, family)
            canaries.append(value)
        else:
            family = operational_corpus.NEGATIVE_FAMILIES[
                negative_index % len(operational_corpus.NEGATIVE_FAMILIES)
            ]
            negative_index += 1
            key, value = operational_corpus._negative(rng, family)
        channel, relative = operational_corpus.LAYOUTS[
            (index * 11 + rng.randrange(len(operational_corpus.LAYOUTS)))
            % len(operational_corpus.LAYOUTS)
        ]
        stem = str(Path(relative).with_suffix(""))
        suffix = Path(relative).suffix
        filename = f"{repo_id}/{stem}-{index:05d}{suffix}"
        note = operational_corpus.NEUTRAL_NOTES[
            (index + rng.randrange(len(operational_corpus.NEUTRAL_NOTES)))
            % len(operational_corpus.NEUTRAL_NOTES)
        ]
        destination = artifacts / filename
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        destination.write_text(
            operational_corpus._render(filename, key, value, note),
            encoding="utf-8",
            newline="\n",
        )
        safe_features = trained_review.safe_example(destination)
        artifact_id = f"SL-T-{index:05d}"
        record = {
            "artifact_id": artifact_id,
            "category": family,
            "channel": channel,
            "filename": filename,
            "label": label,
            "partition": partition,
            "repo_id": repo_id,
            "sha256": experiment._sha256_file(destination),
        }
        records.append(record)
        _append(
            safe / f"{partition}.jsonl",
            {
                "artifact_id": artifact_id,
                "label": label,
                "partition": partition,
                "repo_group": repo_id,
                **safe_features,
            },
        )
        counts[f"{partition}_count"] += 1
        counts[f"{partition}_positive_count"] += label
        counts[f"{partition}_negative_count"] += 1 - label
    manifest = {
        "dataset_name": trained_review.DATASET_NAME,
        "input_version": trained_review.MODEL_INPUT_VERSION,
        "seed": SEED,
        "repository_separated": True,
        "files_per_repository": FILES_PER_REPOSITORY,
        "training_repository_count": training_repos,
        "setup_repository_count": repo_count - training_repos,
        "final_evaluation_source": FINAL_SOURCE,
        "records": records,
    }
    experiment._write_json(raw / "ground_truth.json", manifest)
    experiment._write_json(raw / "canary_index.json", {"canaries": canaries})
    lock = {
        "dataset_name": trained_review.DATASET_NAME,
        "generator_sha256": experiment._sha256_file(Path(__file__)),
        "feature_code_sha256": experiment._sha256_file(
            Path(trained_review.__file__).resolve()
        ),
        "manifest_sha256": experiment._sha256_file(raw / "ground_truth.json"),
        "train_features_sha256": experiment._sha256_file(safe / "train.jsonl"),
        "setup_features_sha256": experiment._sha256_file(safe / "setup.jsonl"),
        "seed": SEED,
    }
    experiment._write_json(raw / "lock.json", lock)
    summary = {
        **dict(sorted(counts.items())),
        "dataset_name": trained_review.DATASET_NAME,
        "input_version": trained_review.MODEL_INPUT_VERSION,
        "training_repository_count": training_repos,
        "setup_repository_count": repo_count - training_repos,
        "final_evaluation_source": FINAL_SOURCE,
        "build_seconds": round(time.perf_counter() - started, 3),
        **lock,
    }
    experiment._write_json(safe / "summary.json", summary)
    return summary


def refresh_lock() -> dict:
    raw = _raw_root()
    safe = _safe_root()
    lock = {
        "dataset_name": trained_review.DATASET_NAME,
        "generator_sha256": experiment._sha256_file(Path(__file__)),
        "feature_code_sha256": experiment._sha256_file(
            Path(trained_review.__file__).resolve()
        ),
        "manifest_sha256": experiment._sha256_file(raw / "ground_truth.json"),
        "train_features_sha256": experiment._sha256_file(safe / "train.jsonl"),
        "setup_features_sha256": experiment._sha256_file(safe / "setup.jsonl"),
        "seed": SEED,
    }
    experiment._write_json(raw / "lock.json", lock)
    summary_path = safe / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary.update(lock)
    experiment._write_json(summary_path, summary)
    return lock


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]


def scan_setup(workers: int = 16) -> dict:
    safe = _safe_root()
    raw = _raw_root()
    destination = safe / "setup-scanned.jsonl"
    if destination.exists():
        raise RuntimeError("refusing to overwrite setup scanner results")
    rows = _read_jsonl(safe / "setup.jsonl")
    truth = {
        item["artifact_id"]: item
        for item in json.loads((raw / "ground_truth.json").read_text(encoding="utf-8"))[
            "records"
        ]
    }
    versions = guard.preflight_scanners()
    started = time.perf_counter()

    def inspect(row: dict) -> dict:
        record = truth[row["artifact_id"]]
        path = raw / "artifacts" / record["filename"]
        if experiment._sha256_file(path) != record["sha256"]:
            raise RuntimeError(f"artifact hash mismatch: {row['artifact_id']}")
        scan = guard.scan_candidates(path)
        findings = scan["findings"]
        errors = scan["scanner_errors"]
        return {
            **row,
            "scanner_block": bool(findings or errors),
            "scanner_error": bool(errors),
            "finding_keys": sorted(
                {f"{item['scanner']}:{item['rule_id']}" for item in findings}
            ),
        }

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for row in pool.map(inspect, rows):
            _append(destination, row)
    result = {
        "sample_count": len(rows),
        "worker_count": workers,
        "scanner_versions": versions,
        "duration_seconds": round(time.perf_counter() - started, 3),
        "records_sha256": experiment._sha256_file(destination),
    }
    experiment._write_json(safe / "setup-scan-summary.json", result)
    return result


def prepare_final() -> dict:
    safe = _safe_root()
    destination = safe / "final.jsonl"
    if destination.exists():
        raise RuntimeError("refusing to overwrite final feature data")
    raw = experiment._research_root() / "raw" / FINAL_SOURCE
    truth_records = json.loads((raw / "ground_truth.json").read_text(encoding="utf-8"))[
        "records"
    ]
    truth = {
        row["artifact_id"]: row
        for row in truth_records
        if row.get("partition") == "holdout"
    }
    v7_path = (
        experiment._research_root() / "sanitized-results" / V7_RESULT / "records.jsonl"
    )
    baseline = {}
    for row in _read_jsonl(v7_path):
        if row["condition"] == "baseline":
            baseline[row["artifact_id"]] = row
    if set(truth) - set(baseline):
        raise RuntimeError("v7 baseline does not cover the final repository set")
    started = time.perf_counter()
    scanner_rows = []
    for artifact_id, record in truth.items():
        path = raw / "artifacts" / record["filename"]
        if experiment._sha256_file(path) != record["sha256"]:
            raise RuntimeError(f"artifact hash mismatch: {artifact_id}")
        features = trained_review.safe_example(path)
        old = baseline[artifact_id]
        finding_keys = old.get("finding_keys", [])
        row = {
            "artifact_id": artifact_id,
            "label": record["label"],
            "partition": "final",
            "repo_group": f"final-{record['repo_id']}",
            "scanner_block": old["verdict"] != "allow",
            "scanner_error": bool(old.get("scanner_error_types")),
            "finding_keys": finding_keys,
            "hard_block": features["hard_block"]
            or any(
                "private" in key.lower() and "key" in key.lower()
                for key in finding_keys
            ),
            **{key: value for key, value in features.items() if key != "hard_block"},
        }
        _append(destination, row)
        scanner_rows.append(
            {
                **row,
                "verdict": "block" if row["scanner_block"] else "allow",
            }
        )
    result = {
        "sample_count": len(scanner_rows),
        "source": FINAL_SOURCE,
        "v7_scanner_result": V7_RESULT,
        "baseline": trained_review.metrics(scanner_rows),
        "duration_seconds": round(time.perf_counter() - started, 3),
        "records_sha256": experiment._sha256_file(destination),
    }
    experiment._write_json(safe / "final-summary.json", result)
    return result


def verify_privacy() -> dict:
    root = experiment._research_root()
    raw = _raw_root()
    safe = _safe_root()
    canaries = json.loads((raw / "canary_index.json").read_text(encoding="utf-8"))[
        "canaries"
    ]
    pattern_path = raw / "canary-search-patterns.txt"
    patterns = sorted({max(value.splitlines(), key=len) for value in canaries if value})
    pattern_path.write_text("\n".join(patterns) + "\n", encoding="utf-8")
    pattern_path.chmod(0o600)
    hits = []
    try:
        for scan_root in (experiment.ROOT, safe):
            searched = subprocess.run(
                [
                    "grep",
                    "-RIlF",
                    "-f",
                    str(pattern_path),
                    "--exclude-dir=.git",
                    str(scan_root),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if searched.returncode not in (0, 1):
                raise RuntimeError("canary safety search failed")
            hits.extend(line for line in searched.stdout.splitlines() if line)
    finally:
        pattern_path.unlink(missing_ok=True)
    forbidden_fields = []
    for name in ("train.jsonl", "setup.jsonl", "setup-scanned.jsonl", "final.jsonl"):
        path = safe / name
        if not path.exists():
            continue
        for number, row in enumerate(_read_jsonl(path), 1):
            model_input = json.loads(row["model_input"])
            keys = set(model_input)
            for candidate in model_input.get("candidates", []):
                keys.update(candidate)
            for key in sorted(keys.intersection(trained_review.FORBIDDEN_TEXT_KEYS)):
                forbidden_fields.append(f"{name}:{number}:{key}")
    result = {
        "raw_canary_hit_count_outside_raw_data": len(set(hits)),
        "forbidden_model_input_field_count": len(forbidden_fields),
        "passed": not hits and not forbidden_fields,
    }
    experiment._write_json(safe / "privacy-verification.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("build")
    sub.add_parser("refresh-lock")
    scan = sub.add_parser("scan-setup")
    scan.add_argument("--workers", type=int, default=16)
    sub.add_parser("prepare-final")
    sub.add_parser("verify")
    args = parser.parse_args()
    if args.command == "build":
        result = build()
    elif args.command == "refresh-lock":
        result = refresh_lock()
    elif args.command == "scan-setup":
        result = scan_setup(args.workers)
    elif args.command == "prepare-final":
        result = prepare_final()
    else:
        result = verify_privacy()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if args.command != "verify" or result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
