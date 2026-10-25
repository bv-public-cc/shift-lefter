"""Build and scan a new final test after the trained approach is fixed.

Raw generated files stay outside Git. The saved model input contains only the
approved derived facts used by the trained review experiment.
"""

from __future__ import annotations

import argparse
import json
import random
import subprocess
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from shift_lefter import experiment, guard, operational_corpus, trained_review

TEST_NAME = "trained-review-fresh-test-v1"
COUNT = 4_800
FILES_PER_REPOSITORY = 20
SEED = 910_041


def _raw_root() -> Path:
    root = experiment._research_root() / "raw" / TEST_NAME
    experiment._assert_outside_git(root)
    return root


def _safe_root() -> Path:
    root = experiment._research_root() / "trained-data" / trained_review.DATASET_NAME
    experiment._assert_outside_git(root)
    return root


def _append(path: Path, value: dict) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def build() -> dict:
    raw = _raw_root()
    destination = _safe_root() / "fresh-final.jsonl"
    if raw.exists() or destination.exists():
        raise RuntimeError("refusing to overwrite the new final test")
    artifacts = raw / "artifacts"
    artifacts.mkdir(parents=True, mode=0o700)
    rng = random.Random(SEED)
    labels = [1] * (COUNT // 3) + [0] * (COUNT - COUNT // 3)
    rng.shuffle(labels)
    records = []
    canaries = []
    coverage: Counter[str] = Counter()
    started = time.perf_counter()
    for index, label in enumerate(labels):
        repo_number = index % (COUNT // FILES_PER_REPOSITORY)
        repo_id = f"fresh-repo-{repo_number:04d}"
        families = (
            operational_corpus.POSITIVE_FAMILIES
            if label
            else operational_corpus.NEGATIVE_FAMILIES
        )
        family = rng.choice(families)
        if label:
            key, value = operational_corpus._positive(rng, family)
            canaries.append(value)
        else:
            key, value = operational_corpus._negative(rng, family)
        channel, relative = rng.choice(operational_corpus.LAYOUTS)
        layout = Path(relative).name
        stem = str(Path(relative).with_suffix(""))
        suffix = Path(relative).suffix
        filename = f"{repo_id}/{stem}-new-{index:05d}{suffix}"
        note = rng.choice(operational_corpus.NEUTRAL_NOTES)
        path = artifacts / filename
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(
            operational_corpus._render(filename, key, value, note),
            encoding="utf-8",
            newline="\n",
        )
        artifact_id = f"SL-N-{index:05d}"
        features = trained_review.safe_example(path)
        record = {
            "artifact_id": artifact_id,
            "category": family,
            "channel": channel,
            "filename": filename,
            "label": label,
            "repo_id": repo_id,
            "sha256": experiment._sha256_file(path),
        }
        records.append(record)
        _append(
            destination,
            {
                "artifact_id": artifact_id,
                "label": label,
                "partition": "fresh_final",
                "repo_group": repo_id,
                **features,
            },
        )
        coverage[f"family:{family}"] += 1
        coverage[f"layout:{layout}"] += 1
    manifest = {
        "test_name": TEST_NAME,
        "seed": SEED,
        "sample_count": COUNT,
        "repository_count": COUNT // FILES_PER_REPOSITORY,
        "repository_separated_from_training": True,
        "sampling": "independent random family, layout, note, and value choices",
        "records": records,
    }
    experiment._write_json(raw / "ground_truth.json", manifest)
    experiment._write_json(raw / "canary_index.json", {"canaries": canaries})
    result = {
        "test_name": TEST_NAME,
        "seed": SEED,
        "sample_count": COUNT,
        "positive_count": sum(labels),
        "negative_count": COUNT - sum(labels),
        "repository_count": COUNT // FILES_PER_REPOSITORY,
        "distinct_family_count": len({r["category"] for r in records}),
        "distinct_layout_count": sum(key.startswith("layout:") for key in coverage),
        "smallest_family_count": min(
            value for key, value in coverage.items() if key.startswith("family:")
        ),
        "features_sha256": experiment._sha256_file(destination),
        "manifest_sha256": experiment._sha256_file(raw / "ground_truth.json"),
        "generator_sha256": experiment._sha256_file(Path(__file__)),
        "feature_code_sha256": experiment._sha256_file(
            Path(trained_review.__file__).resolve()
        ),
        "build_seconds": round(time.perf_counter() - started, 3),
    }
    experiment._write_json(_safe_root() / "fresh-final-build-summary.json", result)
    return result


def scan(workers: int) -> dict:
    raw = _raw_root()
    source = _safe_root() / "fresh-final.jsonl"
    destination = _safe_root() / "fresh-final-scanned.jsonl"
    if destination.exists():
        raise RuntimeError("refusing to overwrite new final scanner results")
    rows = _read_jsonl(source)
    truth = {
        row["artifact_id"]: row
        for row in json.loads((raw / "ground_truth.json").read_text())["records"]
    }
    versions = guard.preflight_scanners()
    started = time.perf_counter()

    def inspect(row: dict) -> dict:
        record = truth[row["artifact_id"]]
        path = raw / "artifacts" / record["filename"]
        if experiment._sha256_file(path) != record["sha256"]:
            raise RuntimeError(f"artifact hash mismatch: {row['artifact_id']}")
        result = guard.scan_candidates(path)
        findings = result["findings"]
        errors = result["scanner_errors"]
        finding_keys = sorted(
            {f"{item['scanner']}:{item['rule_id']}" for item in findings}
        )
        return {
            **row,
            "scanner_block": bool(findings or errors),
            "scanner_error": bool(errors),
            "finding_keys": finding_keys,
            "hard_block": bool(row["hard_block"])
            or any(
                "private" in key.lower() and "key" in key.lower()
                for key in finding_keys
            ),
        }

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for row in pool.map(inspect, rows):
            _append(destination, row)
    result = {
        "test_name": TEST_NAME,
        "sample_count": len(rows),
        "worker_count": workers,
        "scanner_versions": versions,
        "duration_seconds": round(time.perf_counter() - started, 3),
        "records_sha256": experiment._sha256_file(destination),
    }
    experiment._write_json(_safe_root() / "fresh-final-scan-summary.json", result)
    return result


def verify() -> dict:
    raw = _raw_root()
    safe = _safe_root()
    canaries = json.loads((raw / "canary_index.json").read_text())["canaries"]
    pattern = raw / "canary-search-patterns.txt"
    pattern.write_text(
        "\n".join(sorted({max(value.splitlines(), key=len) for value in canaries}))
        + "\n",
        encoding="utf-8",
    )
    pattern.chmod(0o600)
    try:
        search = subprocess.run(
            [
                "grep",
                "-RIlF",
                "-f",
                str(pattern),
                "--exclude-dir=.git",
                str(experiment.ROOT),
                str(safe),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        pattern.unlink(missing_ok=True)
    if search.returncode not in (0, 1):
        raise RuntimeError("new final test privacy search failed")
    forbidden = []
    for row in _read_jsonl(safe / "fresh-final-scanned.jsonl"):
        packet = json.loads(row["model_input"])
        keys = set(packet)
        for item in packet.get("candidates", []):
            keys.update(item)
        forbidden.extend(keys.intersection(trained_review.FORBIDDEN_TEXT_KEYS))
    result = {
        "test_name": TEST_NAME,
        "raw_canary_hit_count_outside_raw_data": len(
            {line for line in search.stdout.splitlines() if line}
        ),
        "forbidden_model_input_field_count": len(forbidden),
        "passed": search.returncode == 1 and not forbidden,
    }
    experiment._write_json(safe / "fresh-final-privacy-verification.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("build")
    scanning = sub.add_parser("scan")
    scanning.add_argument("--workers", type=int, default=16)
    sub.add_parser("verify")
    args = parser.parse_args()
    result = (
        build()
        if args.command == "build"
        else scan(args.workers) if args.command == "scan" else verify()
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if args.command != "verify" or result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
