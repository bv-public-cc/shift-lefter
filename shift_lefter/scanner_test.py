"""Versioned scanner experiments against locked test data.

This module never overwrites the primary Gitleaks evaluation. Each run names
its source test dataset and writes a distinct sanitized result set.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import statistics
import subprocess
import time
from collections import Counter
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

from shift_lefter import experiment, guard, semantic

DEFAULT_RESULT_NAME = "evaluation-v2-combined-scanners"
RESULT_NAME_PATTERN = re.compile(r"evaluation-v[0-9]+-[a-z0-9][a-z0-9-]*$")


def _result_name(value: str) -> str:
    if not RESULT_NAME_PATTERN.fullmatch(value):
        raise ValueError("result name must be a versioned evaluation slug")
    return value


def _output_dir(result_name: str = DEFAULT_RESULT_NAME) -> Path:
    return experiment._research_root() / "sanitized-results" / _result_name(result_name)


def _scanners(values: Iterable[str] | None = None) -> tuple[str, ...]:
    selected = tuple(
        dict.fromkeys(guard.DEFAULT_SCANNERS if values is None else values)
    )
    unknown = sorted(set(selected) - set(guard.DEFAULT_SCANNERS))
    if unknown:
        raise ValueError(f"unsupported scanners: {', '.join(unknown)}")
    if not selected:
        raise ValueError("at least one scanner is required")
    return selected


def _endpoint_is_allowed(endpoint: str) -> bool:
    parsed = urlparse(endpoint)
    host = (parsed.hostname or "").lower()
    allowed = {
        item.strip().lower()
        for item in os.environ.get(
            "SHIFT_LEFTER_ALLOWED_MODEL_HOSTS", "localhost,127.0.0.1,::1"
        ).split(",")
        if item.strip()
    }
    plaintext = {
        item.strip().lower()
        for item in os.environ.get(
            "SHIFT_LEFTER_ALLOW_PLAINTEXT_MODEL_HOSTS", ""
        ).split(",")
        if item.strip()
    }
    return (
        bool(host)
        and host in allowed
        and (
            parsed.scheme == "https" or (parsed.scheme == "http" and host in plaintext)
        )
    )


def _truth(source_set: str) -> tuple[dict, dict[str, dict]]:
    raw = experiment._research_root() / "raw" / source_set
    manifest = json.loads((raw / "ground_truth.json").read_text(encoding="utf-8"))
    return manifest, {item["artifact_id"]: item for item in manifest["records"]}


def _hard_block(findings: list[dict]) -> bool:
    return any(
        "private" in item["rule_id"].lower() and "key" in item["rule_id"].lower()
        for item in findings
    )


def _execution_manifest(source_commit: str, source_set: str) -> dict:
    status = subprocess.run(
        [
            "git",
            "-C",
            str(experiment.ROOT),
            "status",
            "--porcelain",
            "--untracked-files=no",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if status:
        raise RuntimeError(
            "refusing to run the scanner experiment from a dirty worktree"
        )
    raw = experiment._research_root() / "raw" / source_set
    files = {
        "scanner_test.py": Path(__file__).resolve(),
        "experiment.py": Path(experiment.__file__).resolve(),
        "guard.py": Path(guard.__file__).resolve(),
        "semantic.py": Path(semantic.__file__).resolve(),
        "context_markers.json": guard.CONTEXT_MARKERS,
        "gitleaks.toml": experiment.CONFIG,
        "ground_truth.json": raw / "ground_truth.json",
        "canary_index.json": raw / "canary_index.json",
    }
    return {
        "source_commit": source_commit,
        "worktree_clean": True,
        "source_sha256": {
            name: experiment._sha256_file(path) for name, path in files.items()
        },
    }


def run(
    repeats: int = 3,
    result_name: str = DEFAULT_RESULT_NAME,
    source_set: str = "evaluation",
    workers: int = 1,
    scanners: Iterable[str] | None = None,
    semantic_batch: bool = False,
    semantic_detection_threshold: float = 0.90,
    semantic_suppression_threshold: float = 0.90,
) -> dict:
    result_name = _result_name(result_name)
    selected_scanners = _scanners(scanners)
    if workers < 1 or workers > 16:
        raise ValueError("workers must be between 1 and 16")
    if not 0.0 <= semantic_detection_threshold <= 1.0:
        raise ValueError("semantic detection threshold must be between zero and one")
    if not 0.0 <= semantic_suppression_threshold <= 1.0:
        raise ValueError("semantic suppression threshold must be between zero and one")
    manifest, _truth_by_id = _truth(source_set)
    raw = experiment._research_root() / "raw" / source_set
    output_dir = _output_dir(result_name)
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / "records.jsonl"
    if output.exists():
        raise RuntimeError(f"refusing to overwrite scanner-test results: {output}")
    started = time.perf_counter()
    endpoints: set[str] = set()
    scanner_versions: dict[str, str] = {}
    source_commit = subprocess.run(
        ["git", "-C", str(experiment.ROOT), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    execution = _execution_manifest(source_commit, source_set)
    context_markers_sha256 = experiment._sha256_file(guard.CONTEXT_MARKERS)

    def evaluate(record: dict) -> tuple[list[dict], set[str], dict[str, str]]:
        artifact = raw / "artifacts" / record["filename"]
        if experiment._sha256_file(artifact) != record["sha256"]:
            raise RuntimeError(f"artifact hash mismatch: {record['artifact_id']}")
        scan = guard.scan_candidates(artifact, selected_scanners)
        findings = scan["findings"]
        errors = scan["scanner_errors"]
        baseline_verdict = "review" if errors else ("block" if findings else "allow")
        rows = []
        observed_endpoints: set[str] = set()
        common = {
            "schema_version": 1,
            "study": result_name,
            "source_set": source_set,
            "artifact_id": record["artifact_id"],
            "artifact_sha256": record["sha256"],
            "source_commit": source_commit,
            "selected_scanners": list(selected_scanners),
            "finding_count": len(findings),
            "finding_keys": sorted(
                {f"{item['scanner']}:{item['rule_id']}" for item in findings}
            ),
            "finding_scanners": sorted({item["scanner"] for item in findings}),
            "scanner_error_types": sorted({item["error"] for item in errors}),
            "scanner_versions": scan["scanner_versions"],
            "context_markers_sha256": context_markers_sha256,
        }
        rows.append(
            {
                **common,
                "condition": "baseline",
                "repeat": 1,
                "verdict": baseline_verdict,
                "reason_code": (
                    "scanner_error_fail_closed"
                    if errors
                    else "scanner_finding" if findings else "no_scanner_finding"
                ),
                "classifier_seconds": 0.0,
            }
        )

        candidates = (
            semantic.candidate_features(artifact, findings) if semantic_batch else []
        )
        repeat_count = (
            repeats
            if (candidates if semantic_batch else findings)
            and not errors
            and not _hard_block(findings)
            else 1
        )
        for repeat in range(1, repeat_count + 1):
            classifications = []
            elapsed = 0.0
            model_names: set[str] = set()
            classification_error = None
            if (
                semantic_batch
                and candidates
                and not errors
                and not _hard_block(findings)
            ):
                try:
                    result, seconds, model_name, endpoint = semantic.classify_local(
                        artifact, candidates
                    )
                    classifications.extend(result)
                    elapsed += seconds
                    model_names.add(model_name)
                    observed_endpoints.add(endpoint)
                except Exception as exc:
                    classification_error = type(exc).__name__
            elif not semantic_batch:
                for target in (
                    guard.classification_targets(findings) if not errors else []
                ):
                    try:
                        result, seconds, model_name, endpoint = guard.classify_redacted(
                            artifact, target
                        )
                        classifications.append(result)
                        elapsed += seconds
                        model_names.add(model_name)
                        observed_endpoints.add(endpoint)
                    except Exception as exc:
                        classifications.append({"error": type(exc).__name__})
            if semantic_batch:
                if classification_error:
                    verdict, reason = (
                        baseline_verdict,
                        "semantic_error_scanner_fallback",
                    )
                else:
                    verdict, reason = semantic.decide(
                        findings,
                        candidates,
                        classifications,
                        errors,
                        detection_threshold=semantic_detection_threshold,
                        suppression_threshold=semantic_suppression_threshold,
                    )
            else:
                verdict, reason = guard.decide_findings(
                    findings,
                    classifications,
                    errors,
                    allow_classifier_allow=True,
                )
            rows.append(
                {
                    **common,
                    "condition": "hybrid",
                    "repeat": repeat,
                    "verdict": verdict,
                    "reason_code": reason,
                    "classifier_seconds": round(elapsed, 6),
                    "model_names": sorted(model_names) or ["not_invoked"],
                    "classifier_verdicts": [
                        item.get("classification", item.get("verdict", "error"))
                        for item in classifications
                    ]
                    or (["error"] if classification_error else []),
                    "classifier_confidences": [
                        item.get("confidence") for item in classifications
                    ],
                    "classifier_reason_codes": [
                        item.get(
                            "reason_code",
                            ",".join(item.get("evidence_codes", []))
                            or item.get("error", "error"),
                        )
                        for item in classifications
                    ]
                    or ([classification_error] if classification_error else []),
                    "semantic_candidate_count": len(candidates),
                    "semantic_scanner_hit_candidate_count": sum(
                        item["scanner_hit"] for item in candidates
                    ),
                }
            )
        return rows, observed_endpoints, scan["scanner_versions"]

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for rows, observed_endpoints, observed_versions in pool.map(
            evaluate, manifest["records"]
        ):
            endpoints.update(observed_endpoints)
            scanner_versions.update(observed_versions)
            for row in rows:
                experiment._append_jsonl(output, row)
    summary = {
        "study": result_name,
        "source_set": source_set,
        "record_count": sum(1 for _ in output.open(encoding="utf-8")),
        "worker_count": workers,
        "selected_scanners": list(selected_scanners),
        "classifier_strategy": (
            "batched_semantic_detector" if semantic_batch else "per_finding_context"
        ),
        "semantic_detection_threshold": (
            semantic_detection_threshold if semantic_batch else None
        ),
        "semantic_suppression_threshold": (
            semantic_suppression_threshold if semantic_batch else None
        ),
        "duration_seconds": round(time.perf_counter() - started, 3),
        "model_endpoints": sorted(endpoints),
        "scanner_versions": scanner_versions,
        "context_markers_sha256": context_markers_sha256,
        "records_sha256": experiment._sha256_file(output),
        **execution,
    }
    experiment._write_json(output_dir / "run-summary.json", summary)
    return summary


def analyze(
    result_name: str = DEFAULT_RESULT_NAME, source_set: str = "evaluation"
) -> dict:
    result_name = _result_name(result_name)
    _manifest, truth = _truth(source_set)
    output_dir = _output_dir(result_name)
    records = [
        json.loads(line)
        for line in (output_dir / "records.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line
    ]
    baseline = [row for row in records if row["condition"] == "baseline"]
    hybrid = [
        row for row in records if row["condition"] == "hybrid" and row["repeat"] == 1
    ]
    if len(baseline) != len(truth) or len(hybrid) != len(truth):
        raise RuntimeError("scanner-test result count does not match ground truth")
    baseline_metrics = experiment._metrics(baseline, truth)
    hybrid_metrics = experiment._metrics(hybrid, truth)
    repeated_ids = {
        row["artifact_id"]
        for row in records
        if row["condition"] == "hybrid" and row["repeat"] > 1
    }
    stability = []
    for artifact_id in repeated_ids:
        verdicts = [
            row["verdict"]
            for row in records
            if row["condition"] == "hybrid" and row["artifact_id"] == artifact_id
        ]
        stability.append(len(set(verdicts)) == 1)
    run_summary = json.loads(
        (output_dir / "run-summary.json").read_text(encoding="utf-8")
    )
    selected_scanners = _scanners(run_summary.get("selected_scanners"))
    scanner_metrics = {}
    for scanner in selected_scanners:
        rows = []
        for row in baseline:
            scanner_found = scanner in row["finding_scanners"]
            rows.append({**row, "verdict": "block" if scanner_found else "allow"})
        scanner_metrics[scanner] = experiment._metrics(rows, truth)
    classifier_times = [
        row["classifier_seconds"]
        for row in records
        if row["condition"] == "hybrid" and row["classifier_seconds"] > 0
    ]
    verdict_counts = Counter(row["verdict"] for row in hybrid)
    reason_counts = Counter(row["reason_code"] for row in hybrid)
    baseline_by_id = {row["artifact_id"]: row for row in baseline}
    hybrid_by_id = {row["artifact_id"]: row for row in hybrid}
    recovered_false_negatives = introduced_false_negatives = 0
    suppressed_false_positives = introduced_false_positives = 0
    for artifact_id, actual in truth.items():
        baseline_positive = baseline_by_id[artifact_id]["verdict"] != "allow"
        hybrid_positive = hybrid_by_id[artifact_id]["verdict"] != "allow"
        if actual["label"] == 1:
            recovered_false_negatives += int(not baseline_positive and hybrid_positive)
            introduced_false_negatives += int(baseline_positive and not hybrid_positive)
        else:
            suppressed_false_positives += int(baseline_positive and not hybrid_positive)
            introduced_false_positives += int(not baseline_positive and hybrid_positive)
    summary = {
        "study": result_name,
        "research_phase": "scanner_model_experiment",
        "source_set": source_set,
        "selected_scanners": list(selected_scanners),
        "sample_count": len(truth),
        "baseline": baseline_metrics,
        "hybrid": hybrid_metrics,
        "scanner_only_metrics": scanner_metrics,
        "difference": {
            key: hybrid_metrics[key] - baseline_metrics[key]
            for key in ("precision", "recall", "f1")
        },
        "difference_bootstrap_95pct": experiment._bootstrap(baseline, hybrid, truth),
        "mcnemar": experiment._mcnemar(baseline, hybrid, truth),
        "false_positive_reduction": (
            (baseline_metrics["fp"] - hybrid_metrics["fp"]) / baseline_metrics["fp"]
            if baseline_metrics["fp"]
            else 0.0
        ),
        "review_rate": sum(row["verdict"] == "review" for row in hybrid) / len(hybrid),
        "block_rate": sum(row["verdict"] == "block" for row in hybrid) / len(hybrid),
        "verdict_counts": dict(sorted(verdict_counts.items())),
        "reason_code_counts": dict(sorted(reason_counts.items())),
        "incremental_outcomes": {
            "recovered_false_negatives": recovered_false_negatives,
            "introduced_false_negatives": introduced_false_negatives,
            "suppressed_false_positives": suppressed_false_positives,
            "introduced_false_positives": introduced_false_positives,
        },
        "classifier_strategy": run_summary.get(
            "classifier_strategy", "per_finding_context"
        ),
        "repeat_exact_agreement": sum(stability) / len(stability) if stability else 1.0,
        "repeated_artifact_count": len(stability),
        "classifier_latency_median_seconds": (
            statistics.median(classifier_times) if classifier_times else 0.0
        ),
        "classifier_latency_p95_seconds": (
            sorted(classifier_times)[
                max(0, math.ceil(0.95 * len(classifier_times)) - 1)
            ]
            if classifier_times
            else 0.0
        ),
    }
    experiment._write_json(output_dir / "analysis.json", summary)
    return summary


def verify(
    result_name: str = DEFAULT_RESULT_NAME, source_set: str = "evaluation"
) -> dict:
    result_name = _result_name(result_name)
    root = experiment._research_root()
    raw = root / "raw" / source_set
    approved_raw_root = (root / "raw").resolve()
    canaries = json.loads((raw / "canary_index.json").read_text(encoding="utf-8"))[
        "canaries"
    ]
    scan_roots = [experiment.ROOT, root]
    configured_state = os.environ.get("SHIFT_LEFTER_STATE_ROOT", "").strip()
    if configured_state:
        scan_roots.append(Path(configured_state).expanduser().resolve())
    hits = []
    for scan_root in scan_roots:
        if not scan_root.exists():
            continue
        for path in scan_root.rglob("*"):
            if not path.is_file() or ".git" in path.parts:
                continue
            try:
                if path.resolve().is_relative_to(approved_raw_root):
                    continue
            except OSError:
                hits.append(str(path))
                continue
            try:
                data = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if any(canary in data for canary in canaries):
                hits.append(str(path))
    summary = json.loads(
        (_output_dir(result_name) / "run-summary.json").read_text(encoding="utf-8")
    )
    endpoints = summary.get("model_endpoints", [])
    endpoint_ok = bool(endpoints) and all(
        _endpoint_is_allowed(endpoint) for endpoint in endpoints
    )
    result = {
        "raw_canary_hit_count_outside_approved_root": len(set(hits)),
        "raw_canary_hit_paths": sorted(set(hits)),
        "observed_model_endpoints": endpoints,
        "model_endpoints_local_allowlisted": endpoint_ok,
        "passed": not hits and endpoint_ok,
    }
    experiment._write_json(
        _output_dir(result_name) / "safety-verification.json", result
    )
    return result


def compare(
    result_names: list[str],
    output_name: str = "evaluation-v2-model-comparison",
) -> dict:
    """Compare model conditions and prove their scanner inputs are identical."""
    names = [_result_name(name) for name in result_names]
    output_name = _result_name(output_name)
    if len(names) < 2 or len(set(names)) != len(names):
        raise ValueError("compare requires at least two distinct result names")
    conditions = {}
    reference_findings = None
    reference_sources = None
    for name in names:
        output_dir = _output_dir(name)
        records = [
            json.loads(line)
            for line in (output_dir / "records.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
            if line
        ]
        baseline = {
            row["artifact_id"]: {
                "finding_count": row["finding_count"],
                "finding_keys": row["finding_keys"],
                "finding_scanners": row["finding_scanners"],
                "scanner_error_types": row["scanner_error_types"],
            }
            for row in records
            if row["condition"] == "baseline"
        }
        run_summary = json.loads(
            (output_dir / "run-summary.json").read_text(encoding="utf-8")
        )
        analysis = json.loads(
            (output_dir / "analysis.json").read_text(encoding="utf-8")
        )
        safety = json.loads(
            (output_dir / "safety-verification.json").read_text(encoding="utf-8")
        )
        if not safety.get("passed"):
            raise RuntimeError(f"safety verification did not pass for {name}")
        if reference_findings is None:
            reference_findings = baseline
            reference_sources = run_summary.get("source_sha256")
        elif baseline != reference_findings:
            raise RuntimeError("scanner outputs differ between model conditions")
        elif run_summary.get("source_sha256") != reference_sources:
            raise RuntimeError(
                "execution source hashes differ between model conditions"
            )
        hybrid = [row for row in records if row["condition"] == "hybrid"]
        conditions[name] = {
            "model_names": sorted(
                {
                    model
                    for row in hybrid
                    for model in row.get("model_names", [])
                    if model != "not_invoked"
                }
            ),
            "model_endpoints": run_summary["model_endpoints"],
            "records_sha256": run_summary["records_sha256"],
            "metrics": {
                "baseline": analysis["baseline"],
                "hybrid": analysis["hybrid"],
                "false_positive_reduction": analysis["false_positive_reduction"],
                "repeat_exact_agreement": analysis["repeat_exact_agreement"],
                "classifier_latency_median_seconds": analysis[
                    "classifier_latency_median_seconds"
                ],
                "classifier_latency_p95_seconds": analysis[
                    "classifier_latency_p95_seconds"
                ],
            },
        }
    result = {
        "study": output_name,
        "research_phase": "scanner_model_experiment",
        "condition_count": len(conditions),
        "scanner_outputs_identical": True,
        "source_hashes_identical": True,
        "source_sha256": reference_sources,
        "conditions": conditions,
    }
    destination = (
        experiment._research_root() / "sanitized-results" / f"{output_name}.json"
    )
    experiment._write_json(destination, result)
    return result


def summarize(
    result_names: list[str],
    output_name: str = "evaluation-v5-single-scanner-summary",
) -> dict:
    """Summarize verified single-scanner conditions without equating findings."""
    names = [_result_name(name) for name in result_names]
    output_name = _result_name(output_name)
    if len(names) < 2 or len(set(names)) != len(names):
        raise ValueError("summarize requires at least two distinct result names")
    conditions = {}
    reference_sources = None
    for name in names:
        output_dir = _output_dir(name)
        run_summary = json.loads(
            (output_dir / "run-summary.json").read_text(encoding="utf-8")
        )
        analysis = json.loads(
            (output_dir / "analysis.json").read_text(encoding="utf-8")
        )
        safety = json.loads(
            (output_dir / "safety-verification.json").read_text(encoding="utf-8")
        )
        if not safety.get("passed"):
            raise RuntimeError(f"safety verification did not pass for {name}")
        selected = _scanners(run_summary.get("selected_scanners"))
        if len(selected) != 1:
            raise RuntimeError(f"single-scanner condition required for {name}")
        sources = run_summary.get("source_sha256")
        if reference_sources is None:
            reference_sources = sources
        elif sources != reference_sources:
            raise RuntimeError("execution source hashes differ between conditions")
        records = [
            json.loads(line)
            for line in (output_dir / "records.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
            if line
        ]
        model_names = sorted(
            {
                model
                for row in records
                if row["condition"] == "hybrid"
                for model in row.get("model_names", [])
                if model != "not_invoked"
            }
        )
        conditions[name] = {
            "scanner": selected[0],
            "model_names": model_names,
            "model_endpoints": run_summary["model_endpoints"],
            "records_sha256": run_summary["records_sha256"],
            "baseline": analysis["baseline"],
            "hybrid": analysis["hybrid"],
            "false_positive_reduction": analysis["false_positive_reduction"],
            "classifier_latency_median_seconds": analysis[
                "classifier_latency_median_seconds"
            ],
            "classifier_latency_p95_seconds": analysis[
                "classifier_latency_p95_seconds"
            ],
        }
    result = {
        "study": output_name,
        "research_phase": "single_scanner_experiment",
        "condition_count": len(conditions),
        "scanner_outputs_expected_to_differ": True,
        "source_hashes_identical": True,
        "source_sha256": reference_sources,
        "conditions": conditions,
    }
    destination = (
        experiment._research_root() / "sanitized-results" / f"{output_name}.json"
    )
    experiment._write_json(destination, result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run_parser = sub.add_parser("run")
    run_parser.add_argument("--repeats", type=int, default=3)
    run_parser.add_argument("--workers", type=int, default=1)
    run_parser.add_argument("--semantic-batch", action="store_true")
    run_parser.add_argument("--semantic-detection-threshold", type=float, default=0.90)
    run_parser.add_argument(
        "--semantic-suppression-threshold", type=float, default=0.90
    )
    run_parser.add_argument(
        "--scanner", action="append", choices=guard.DEFAULT_SCANNERS
    )
    for command in (run_parser, sub.add_parser("analyze"), sub.add_parser("verify")):
        command.add_argument("--result-name", default=DEFAULT_RESULT_NAME)
        command.add_argument("--source-set", default="evaluation")
    compare_parser = sub.add_parser("compare")
    compare_parser.add_argument("--result-name", action="append", required=True)
    compare_parser.add_argument(
        "--output-name", default="evaluation-v2-model-comparison"
    )
    summary_parser = sub.add_parser("summarize")
    summary_parser.add_argument("--result-name", action="append", required=True)
    summary_parser.add_argument(
        "--output-name", default="evaluation-v5-single-scanner-summary"
    )
    args = parser.parse_args(argv)
    result = (
        run(
            args.repeats,
            args.result_name,
            args.source_set,
            args.workers,
            args.scanner,
            args.semantic_batch,
            args.semantic_detection_threshold,
            args.semantic_suppression_threshold,
        )
        if args.command == "run"
        else (
            analyze(args.result_name, args.source_set)
            if args.command == "analyze"
            else (
                verify(args.result_name, args.source_set)
                if args.command == "verify"
                else (
                    compare(args.result_name, args.output_name)
                    if args.command == "compare"
                    else summarize(args.result_name, args.output_name)
                )
            )
        )
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if args.command != "verify" or result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
