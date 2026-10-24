"""Create a publication-safe copy of a multi-model comparison JSON file."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

PRIVATE_KEYS = {"exploratory_follow_on", "platform_commit", "source_commit"}


def _clean(value):
    if isinstance(value, list):
        return [_clean(item) for item in value]
    if not isinstance(value, dict):
        return value
    return {key: _clean(item) for key, item in value.items() if key not in PRIVATE_KEYS}


def sanitize(payload: dict, labels: dict[str, str]) -> dict:
    output = _clean(payload)
    conditions = output.get("conditions", {})
    if set(conditions) != set(labels):
        missing = sorted(set(conditions) - set(labels))
        extra = sorted(set(labels) - set(conditions))
        raise ValueError(
            f"endpoint labels must exactly match conditions; missing={missing}, extra={extra}"
        )
    for condition, data in conditions.items():
        data["model_endpoints"] = [labels[condition]]
        data["endpoint_address_redacted_for_publication"] = True
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument(
        "--label",
        action="append",
        required=True,
        help="condition=public endpoint label (repeat once per condition)",
    )
    args = parser.parse_args()
    labels = {}
    for item in args.label:
        condition, separator, label = item.partition("=")
        if not separator or not condition or not label or condition in labels:
            raise ValueError(f"invalid or duplicate label mapping: {item!r}")
        labels[condition] = label
    output = sanitize(json.loads(args.source.read_text(encoding="utf-8")), labels)
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    args.destination.write_text(
        json.dumps(output, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
