"""Measure developer-scale latency with one file per model call."""

from __future__ import annotations

import argparse
import json
import time

from shift_lefter import experiment
from train_trained_review import (
    MODELS,
    _data_root,
    _model_root,
    _predict_adapter,
    _read,
)

SAMPLE_COUNT = 256


def _spread(rows: list[dict]) -> list[dict]:
    if len(rows) < SAMPLE_COUNT:
        return rows
    return [rows[index * len(rows) // SAMPLE_COUNT] for index in range(SAMPLE_COUNT)]


def _lightweight(rows: list[dict]) -> tuple[float, float]:
    import joblib

    cold_started = time.perf_counter()
    bundle = joblib.load(_model_root("lightgbm") / "model.joblib")
    loaded = time.perf_counter()
    for row in rows:
        features = bundle["vectorizer"].transform([row["features"]])
        bundle["model"].predict_proba(features)
    finished = time.perf_counter()
    return loaded - cold_started, finished - loaded


def benchmark(name: str) -> dict:
    rows = _spread(_read(_data_root() / "final.jsonl"))
    if name == "lightgbm":
        load_seconds, inference_seconds = _lightweight(rows)
    else:
        started = time.perf_counter()
        _probabilities, inference_seconds = _predict_adapter(name, rows, 1)
        load_seconds = time.perf_counter() - started - inference_seconds
    result = {
        "model": name,
        "sample_count": len(rows),
        "batch_size": 1,
        "sample_selection": "evenly spaced across the untouched final test",
        "measurement": (
            "model load is reported separately; inference uses a warm model and "
            "one file per call"
        ),
        "model_load_seconds": round(load_seconds, 6),
        "total_warm_inference_seconds": round(inference_seconds, 6),
        "mean_warm_seconds_per_file": round(inference_seconds / len(rows), 9),
    }
    experiment._write_json(_model_root(name) / "batch-one-latency.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", choices=["lightgbm", *sorted(MODELS)], required=True)
    args = parser.parse_args()
    print(json.dumps(benchmark(args.model), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
