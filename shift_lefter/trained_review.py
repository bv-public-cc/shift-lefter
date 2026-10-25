"""Shared privacy and enforcement rules for the trained model experiment.

Models receive only the fields selected by :func:`safe_example`. Source text,
suspected values, paths, hashes, repository names, and line numbers never enter
the returned feature packet.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from shift_lefter import semantic

DATASET_NAME = "trained-review-v1"
MODEL_INPUT_VERSION = "safe-features-v1"
PRIVATE_KEY_FORMAT = "private_key"
ALLOWED_FIELDS = frozenset(
    {
        "file_type",
        "candidate_count",
        "file_category",
        "assignment_category",
        "authorization_context",
        "length_bucket",
        "entropy",
        "charset",
        "known_format",
        "placeholder_match",
        "nonsecret_format",
    }
)
FORBIDDEN_TEXT_KEYS = frozenset(
    {
        "artifact_id",
        "candidate_id",
        "filename",
        "line",
        "path",
        "repo_id",
        "repository",
        "sha256",
        "source",
        "text",
        "value",
    }
)


def _model_fields(candidate: Mapping[str, object]) -> dict[str, object]:
    value = candidate["value_features"]
    context = candidate["context_features"]
    return {
        "file_category": context["file_category"],
        "assignment_category": context["assignment_category"],
        "authorization_context": bool(context["authorization_context"]),
        "length_bucket": value["length_bucket"],
        "entropy": value["entropy"],
        "charset": value["charset"],
        "known_format": value["known_format"],
        "placeholder_match": bool(value["placeholder_match"]),
        "nonsecret_format": value["nonsecret_format"],
    }


def safe_example(path: Path) -> dict[str, object]:
    """Create the only feature representation accepted by trained models."""
    candidates = semantic.candidate_features(path, [])
    selected = [_model_fields(item) for item in candidates]
    selected.sort(key=lambda item: json.dumps(item, sort_keys=True))
    packet = {
        "file_type": path.suffix.lower() or "none",
        "candidate_count": len(selected),
        "candidates": selected,
    }
    flat: dict[str, object] = {
        "file_type": packet["file_type"],
        "candidate_count": str(packet["candidate_count"]),
    }
    for index, candidate in enumerate(selected[:4]):
        for key, value in candidate.items():
            flat[f"candidate_{index}_{key}"] = str(value).lower()
    if set(packet) != {"file_type", "candidate_count", "candidates"} or any(
        not set(candidate).issubset(ALLOWED_FIELDS) for candidate in selected
    ):
        raise RuntimeError("model feature packet contains an unexpected field")
    text = json.dumps(packet, sort_keys=True, separators=(",", ":"))
    hard_block = any(
        candidate["known_format"] == PRIVATE_KEY_FORMAT for candidate in selected
    )
    fixed_safe = bool(selected) and all(
        candidate["placeholder_match"] or candidate["nonsecret_format"] != "none"
        for candidate in selected
    )
    return {
        "input_version": MODEL_INPUT_VERSION,
        "model_input": text,
        "features": flat,
        "hard_block": hard_block,
        "fixed_safe": fixed_safe,
        "candidate_count": len(selected),
    }


def policy_decision(
    *,
    scanner_block: bool,
    hard_block: bool,
    fixed_safe: bool,
    secret_probability: float | None,
    detection_threshold: float,
    suppression_threshold: float,
    model_error: bool = False,
    scanner_error: bool = False,
) -> tuple[str, str]:
    """Combine one model probability with the scanner's fail-closed decision."""
    for name, threshold in (
        ("detection", detection_threshold),
        ("suppression", suppression_threshold),
    ):
        if not 0.0 <= threshold <= 1.0:
            raise ValueError(f"{name} threshold must be between zero and one")
    if hard_block:
        return "block", "non_overridable_hard_block"
    if scanner_error:
        return "block", "scanner_error_non_overridable"
    if model_error or secret_probability is None:
        return (
            ("block", "model_error_scanner_fallback")
            if scanner_block
            else ("allow", "model_error_scanner_fallback")
        )
    try:
        probability = float(secret_probability)
    except (TypeError, ValueError):
        return (
            ("block", "invalid_model_output_scanner_fallback")
            if scanner_block
            else ("allow", "invalid_model_output_scanner_fallback")
        )
    if not 0.0 <= probability <= 1.0:
        return (
            ("block", "invalid_model_output_scanner_fallback")
            if scanner_block
            else ("allow", "invalid_model_output_scanner_fallback")
        )
    if not scanner_block and probability >= detection_threshold:
        return "block", "trained_model_secret_detected"
    false_positive_probability = 1.0 - probability
    if (
        scanner_block
        and fixed_safe
        and false_positive_probability >= suppression_threshold
    ):
        return "allow", "fixed_rule_confirmed_false_positive"
    return (
        ("block", "scanner_decision_retained")
        if scanner_block
        else ("allow", "scanner_decision_retained")
    )


def metrics(rows: Iterable[Mapping[str, object]]) -> dict[str, float | int]:
    counts = Counter()
    for row in rows:
        actual = int(row["label"])
        predicted = row["verdict"] != "allow"
        counts[
            (
                "tp"
                if actual and predicted
                else "fn" if actual else "fp" if predicted else "tn"
            )
        ] += 1
    tp, fp, tn, fn = (counts[name] for name in ("tp", "fp", "tn", "fn"))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": (
            2 * precision * recall / (precision + recall) if precision + recall else 0.0
        ),
    }


def incremental_outcomes(
    rows: Iterable[Mapping[str, object]],
) -> dict[str, int]:
    counts = Counter()
    for row in rows:
        actual = int(row["label"])
        scanner = bool(row["scanner_block"])
        trained = row["verdict"] != "allow"
        if actual:
            counts["recovered_misses"] += int(not scanner and trained)
            counts["introduced_misses"] += int(scanner and not trained)
        else:
            counts["removed_false_alarms"] += int(scanner and not trained)
            counts["introduced_false_alarms"] += int(not scanner and trained)
    return {
        name: counts[name]
        for name in (
            "recovered_misses",
            "introduced_misses",
            "removed_false_alarms",
            "introduced_false_alarms",
        )
    }


def apply_policy(
    rows: Sequence[Mapping[str, object]],
    probabilities: Sequence[float | None],
    *,
    detection_threshold: float,
    suppression_threshold: float,
) -> list[dict[str, object]]:
    if len(rows) != len(probabilities):
        raise ValueError("prediction count does not match the evaluation data")
    output = []
    for row, probability in zip(rows, probabilities, strict=True):
        verdict, reason = policy_decision(
            scanner_block=bool(row["scanner_block"]),
            hard_block=bool(row["hard_block"]),
            fixed_safe=bool(row["fixed_safe"]),
            secret_probability=probability,
            detection_threshold=detection_threshold,
            suppression_threshold=suppression_threshold,
            model_error=probability is None,
            scanner_error=bool(row.get("scanner_error", False)),
        )
        output.append({**row, "verdict": verdict, "reason_code": reason})
    return output


def select_thresholds(
    rows: Sequence[Mapping[str, object]],
    probabilities: Sequence[float | None],
    grid: Sequence[float] | None = None,
) -> dict[str, object]:
    """Choose thresholds on setup repositories without consulting final results."""
    values = tuple(
        grid
        or (
            0.50,
            0.60,
            0.70,
            0.75,
            0.80,
            0.85,
            0.90,
            0.92,
            0.95,
            0.97,
            0.99,
        )
    )
    choices = []
    for detection in values:
        for suppression in values:
            decided = apply_policy(
                rows,
                probabilities,
                detection_threshold=detection,
                suppression_threshold=suppression,
            )
            delta = incremental_outcomes(decided)
            score = metrics(decided)
            if (
                delta["introduced_misses"] == 0
                and delta["introduced_false_alarms"] == 0
            ):
                choices.append(
                    {
                        "detection_threshold": detection,
                        "suppression_threshold": suppression,
                        "metrics": score,
                        "incremental_outcomes": delta,
                    }
                )
    if not choices:
        return {
            "detection_threshold": 1.0,
            "suppression_threshold": 1.0,
            "selection": "scanner_only_fallback",
        }
    choices.sort(
        key=lambda item: (
            item["incremental_outcomes"]["recovered_misses"]
            + item["incremental_outcomes"]["removed_false_alarms"],
            item["metrics"]["f1"],
            item["detection_threshold"],
            item["suppression_threshold"],
        ),
        reverse=True,
    )
    return {**choices[0], "selection": "setup_repositories_only"}
