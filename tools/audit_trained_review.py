"""Audit training coverage and summarize what each trained model learned."""

from __future__ import annotations

import argparse
import json
import math
import re
from collections import Counter
from pathlib import Path

from shift_lefter import experiment, operational_corpus, trained_review

MODELS = ("lightgbm", "granite", "qwen")
RESULT_NAME = "evaluation-v8-trained-review"


def _read(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]


def _safe_root() -> Path:
    return experiment._research_root() / "trained-data" / trained_review.DATASET_NAME


def _raw_root() -> Path:
    return experiment._research_root() / "raw" / trained_review.DATASET_NAME


def _result_root() -> Path:
    return experiment._research_root() / "sanitized-results" / RESULT_NAME


def _layout(filename: str) -> str:
    path = Path(filename)
    clean = re.sub(r"-\d{5}$", "", path.stem) + path.suffix
    parts = path.parts[1:-1]
    return "/".join((*parts, clean))


def coverage() -> dict:
    manifest = json.loads(
        (_raw_root() / "ground_truth.json").read_text(encoding="utf-8")
    )
    records = manifest["records"]
    train = [row for row in records if row["partition"] == "train"]
    setup = [row for row in records if row["partition"] == "setup"]
    train_repos = {row["repo_id"] for row in train}
    setup_repos = {row["repo_id"] for row in setup}
    expected_families = {
        *operational_corpus.POSITIVE_FAMILIES,
        *operational_corpus.NEGATIVE_FAMILIES,
    }
    expected_layouts = {relative for _channel, relative in operational_corpus.LAYOUTS}
    pair_counts = Counter((row["category"], _layout(row["filename"])) for row in train)
    missing_pairs = sorted(
        f"{family}|{layout}"
        for family in expected_families
        for layout in expected_layouts
        if pair_counts[(family, layout)] == 0
    )
    family_counts = Counter(row["category"] for row in train)
    layout_counts = Counter(_layout(row["filename"]) for row in train)
    safe_rows = _read(_safe_root() / "train.jsonl")
    feature_signatures = {row["model_input"] for row in safe_rows}
    fresh_manifest = json.loads(
        (
            experiment._research_root()
            / "raw"
            / "trained-review-fresh-test-v1"
            / "ground_truth.json"
        ).read_text(encoding="utf-8")
    )
    fresh = fresh_manifest["records"]
    fresh_family_counts = Counter(row["category"] for row in fresh)
    fresh_channel_counts = Counter(row["channel"] for row in fresh)
    fresh_repositories = {row["repo_id"] for row in fresh}
    expected_channels = {channel for channel, _relative in operational_corpus.LAYOUTS}
    fresh_coverage_passed = (
        len(fresh) == 4_800
        and set(fresh_family_counts) == expected_families
        and set(fresh_channel_counts) == expected_channels
        and not fresh_repositories.intersection(train_repos | setup_repos)
    )
    result = {
        "dataset_name": trained_review.DATASET_NAME,
        "training_file_count": len(train),
        "setup_file_count": len(setup),
        "training_repository_count": len(train_repos),
        "setup_repository_count": len(setup_repos),
        "repository_overlap_count": len(train_repos.intersection(setup_repos)),
        "positive_family_count": len(operational_corpus.POSITIVE_FAMILIES),
        "safe_lookalike_family_count": len(operational_corpus.NEGATIVE_FAMILIES),
        "layout_count": len(expected_layouts),
        "family_layout_pair_count": len(pair_counts),
        "expected_family_layout_pair_count": len(expected_families)
        * len(expected_layouts),
        "missing_family_layout_pairs": missing_pairs,
        "smallest_family_count": min(family_counts.values()),
        "smallest_layout_count": min(layout_counts.values()),
        "smallest_family_layout_count": min(pair_counts.values()),
        "distinct_safe_feature_packets": len(feature_signatures),
        "training_label_counts": dict(
            sorted(Counter(str(row["label"]) for row in train).items())
        ),
        "new_final_test": {
            "file_count": len(fresh),
            "repository_count": len(fresh_repositories),
            "repository_overlap_with_training_or_setup": len(
                fresh_repositories.intersection(train_repos | setup_repos)
            ),
            "label_counts": dict(
                sorted(Counter(str(row["label"]) for row in fresh).items())
            ),
            "family_counts": dict(sorted(fresh_family_counts.items())),
            "file_channel_counts": dict(sorted(fresh_channel_counts.items())),
            "smallest_family_count": min(fresh_family_counts.values()),
            "largest_family_count": max(fresh_family_counts.values()),
            "passed": fresh_coverage_passed,
        },
        "passed": (
            len(train) >= 30_000
            and not train_repos.intersection(setup_repos)
            and set(family_counts) == expected_families
            and set(layout_counts) == expected_layouts
            and not missing_pairs
            and fresh_coverage_passed
        ),
        "scope": (
            "Complete coverage of the study's 32 defined secret and safe-lookalike "
            "families across all 10 file layouts. This is broad practical coverage, "
            "not a claim that every future secret format is represented."
        ),
    }
    experiment._write_json(_result_root() / "training-coverage.json", result)
    return result


def _group_metrics(name: str, field: str) -> dict:
    raw_final = json.loads(
        (
            experiment._research_root()
            / "raw"
            / "trained-review-fresh-test-v1"
            / "ground_truth.json"
        ).read_text(encoding="utf-8")
    )["records"]
    groups = {row["artifact_id"]: row[field] for row in raw_final}
    records = _read(_result_root() / name / "records.jsonl")
    grouped: dict[str, list[dict]] = {}
    for row in records:
        grouped.setdefault(groups[row["artifact_id"]], []).append(row)
    return {
        category: {
            "sample_count": len(rows),
            **trained_review.metrics(rows),
        }
        for category, rows in sorted(grouped.items())
    }


def _new_example_summary() -> dict:
    train = _read(_safe_root() / "train.jsonl")
    final = _read(_safe_root() / "final.jsonl")
    training_packets = {row["model_input"] for row in train}
    training_repositories = {row["repo_group"] for row in train}
    final_repositories = {row["repo_group"] for row in final}
    unseen = [row for row in final if row["model_input"] not in training_packets]
    return {
        "new_file_count": len(final),
        "new_repository_count": len(final_repositories),
        "repository_overlap_with_training": len(
            training_repositories.intersection(final_repositories)
        ),
        "files_with_a_derived_fact_combination_not_seen_in_training": len(unseen),
        "distinct_derived_fact_combinations": len(
            {row["model_input"] for row in final}
        ),
        "interpretation": (
            "Every final file, repository, and credential-shaped value is new. "
            "The derived facts are intentionally low-cardinality, so an already-seen "
            "combination does not mean the underlying file or value was seen in training."
        ),
    }


def _history_summary(manifest: dict) -> dict:
    history = [row for row in manifest.get("training_history", []) if "loss" in row]
    losses = [
        float(row["loss"]) for row in history if math.isfinite(float(row["loss"]))
    ]
    gradients = [
        float(row["grad_norm"])
        for row in history
        if "grad_norm" in row and math.isfinite(float(row["grad_norm"]))
    ]
    return {
        "logged_training_points": len(history),
        "first_logged_loss": losses[0] if losses else None,
        "last_logged_loss": losses[-1] if losses else None,
        "lowest_logged_loss": min(losses) if losses else None,
        "loss_decreased": bool(losses) and losses[-1] < losses[0],
        "largest_logged_gradient_norm": max(gradients) if gradients else None,
        "all_logged_values_finite": len(losses) == len(history),
    }


def training_quality() -> dict:
    models = {}
    for name in MODELS:
        analysis = json.loads(
            (_result_root() / name / "analysis.json").read_text(encoding="utf-8")
        )
        manifest = json.loads(
            (
                experiment._research_root()
                / "models"
                / trained_review.DATASET_NAME
                / name
                / "training-manifest.json"
            ).read_text(encoding="utf-8")
        )
        thresholds = json.loads(
            (
                experiment._research_root()
                / "models"
                / trained_review.DATASET_NAME
                / name
                / "thresholds.json"
            ).read_text(encoding="utf-8")
        )
        models[name] = {
            "training": _history_summary(manifest),
            "setup_metrics_used_for_selection": thresholds.get("metrics"),
            "final_metrics": analysis["scanner_plus_trained_model"],
            "fixed_rules_without_model": analysis["scanner_plus_fixed_rules"],
            "model_only_final_metrics": analysis["trained_model_only"],
            "trained_model_value_beyond_fixed_rules": analysis[
                "trained_model_value_beyond_fixed_rules"
            ],
            "incremental_outcomes": analysis["incremental_outcomes"],
            "latency": analysis["latency"],
            "secret_family_metrics": _group_metrics(name, "category"),
            "file_channel_metrics": _group_metrics(name, "channel"),
        }
    setup_ranked = sorted(
        MODELS,
        key=lambda name: (
            models[name]["setup_metrics_used_for_selection"]["f1"],
            models[name]["setup_metrics_used_for_selection"]["precision"],
        ),
        reverse=True,
    )
    final_ranked = sorted(
        MODELS,
        key=lambda name: (
            models[name]["final_metrics"]["f1"],
            models[name]["final_metrics"]["precision"],
            -models[name]["latency"]["developer_scale_batch_one"][
                "mean_warm_seconds_per_file"
            ],
        ),
        reverse=True,
    )
    result = {
        "dataset_name": trained_review.DATASET_NAME,
        "models": models,
        "recommended_default_from_setup_data": setup_ranked[0],
        "setup_ranking_used_for_model_selection": setup_ranked,
        "descriptive_final_ranking": final_ranked,
        "new_example_summary": _new_example_summary(),
        "interpretation": (
            "The recommended default is selected from setup data, not final-test labels. "
            "The final ranking describes the independent result and is not used to tune "
            "thresholds or choose a different winner after seeing the answers. A larger "
            "model adds practical value only if its setup result supports selecting it "
            "and its final safety and accuracy justify the extra latency and operating cost."
        ),
    }
    experiment._write_json(_result_root() / "training-quality.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("coverage", "training-quality"))
    args = parser.parse_args()
    result = coverage() if args.command == "coverage" else training_quality()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if args.command != "coverage" or result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
