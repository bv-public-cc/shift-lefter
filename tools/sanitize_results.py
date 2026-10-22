"""Create a lab-neutral publication copy of one sanitized result condition."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ENDPOINT_KEYS = {"model_endpoints", "observed_model_endpoints"}
PRIVATE_EXECUTION_KEYS = {
    "exploratory_follow_on",
    "platform_commit",
    "source_commit",
}


def transform(value, endpoint_label: str, study_name: str | None = None):
    if isinstance(value, list):
        return [transform(item, endpoint_label, study_name) for item in value]
    if not isinstance(value, dict):
        return value
    output = {}
    for key, item in value.items():
        if key in PRIVATE_EXECUTION_KEYS:
            continue
        public_key = "execution_runner.py" if key == "ensemble_experiment.py" else key
        if key == "study" and study_name:
            output[public_key] = study_name
            continue
        if key in ENDPOINT_KEYS:
            output[public_key] = [endpoint_label]
        else:
            output[public_key] = transform(item, endpoint_label, study_name)
    return output


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--endpoint-label", required=True)
    parser.add_argument("--study-name")
    parser.add_argument("--execution-source-matches-release", action="store_true")
    args = parser.parse_args()
    if args.destination.exists() and any(args.destination.iterdir()):
        raise RuntimeError("refusing to overwrite a non-empty destination")
    args.destination.mkdir(parents=True, exist_ok=True)

    source_records = args.source / "records.jsonl"
    destination_records = args.destination / "records.jsonl"
    with (
        source_records.open(encoding="utf-8") as source,
        destination_records.open("w", encoding="utf-8", newline="\n") as destination,
    ):
        for line in source:
            if line.strip():
                destination.write(
                    canonical(
                        transform(
                            json.loads(line), args.endpoint_label, args.study_name
                        )
                    )
                    + "\n"
                )

    public_records_hash = hashlib.sha256(destination_records.read_bytes()).hexdigest()
    for filename in ("run-summary.json", "analysis.json", "safety-verification.json"):
        source_path = args.source / filename
        if not source_path.exists():
            raise RuntimeError(f"missing required result file: {filename}")
        payload = transform(
            json.loads(source_path.read_text()),
            args.endpoint_label,
            args.study_name,
        )
        if filename == "run-summary.json":
            payload["archived_records_sha256"] = payload.get("records_sha256")
            payload["records_sha256"] = public_records_hash
            payload["endpoint_address_redacted_for_publication"] = True
            payload["execution_source_matches_release"] = (
                args.execution_source_matches_release
            )
        if filename == "safety-verification.json":
            payload["endpoint_address_redacted_for_publication"] = True
        (args.destination / filename).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
