"""Run Shift Lefter against an allowlisted OpenAI-compatible local model."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import time
from pathlib import Path
from urllib.parse import urlparse

from shift_lefter import scanner_test, experiment, guard


def _model_config() -> tuple[str, str, set[str]]:
    endpoint = os.environ.get("SHIFT_LEFTER_MODEL_ENDPOINT", "").rstrip("/")
    model = os.environ.get("SHIFT_LEFTER_MODEL_NAME", "")
    allowed = {
        item.strip().lower()
        for item in os.environ.get(
            "SHIFT_LEFTER_ALLOWED_MODEL_HOSTS", "localhost,127.0.0.1,::1"
        ).split(",")
        if item.strip()
    }
    if not endpoint or not model:
        raise RuntimeError(
            "SHIFT_LEFTER_MODEL_ENDPOINT and SHIFT_LEFTER_MODEL_NAME are required"
        )
    parsed = urlparse(endpoint)
    host = (parsed.hostname or "").lower()
    if host not in allowed:
        raise RuntimeError("local model host is not explicitly allowlisted")
    plaintext_allowed = {
        item.strip().lower()
        for item in os.environ.get(
            "SHIFT_LEFTER_ALLOW_PLAINTEXT_MODEL_HOSTS", ""
        ).split(",")
        if item.strip()
    }
    if parsed.scheme == "http":
        if (
            host not in {"localhost", "127.0.0.1", "::1"}
            and host not in plaintext_allowed
        ):
            raise RuntimeError("non-loopback model endpoints require HTTPS")
    elif parsed.scheme != "https":
        raise RuntimeError("model endpoint must use HTTP or HTTPS")
    return endpoint, model, allowed


def _api_key() -> str | None:
    configured = os.environ.get("SHIFT_LEFTER_LOCAL_API_KEY_FILE")
    env_name = os.environ.get("SHIFT_LEFTER_LOCAL_API_KEY_ENV")
    if configured and env_name:
        raise RuntimeError("configure either an API key file or environment name")
    if env_name:
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", env_name):
            raise RuntimeError("local API key environment name is invalid")
        value = os.environ.get(env_name, "").strip()
        if not value:
            raise RuntimeError("local API key environment value is empty")
        return value
    if not configured:
        return None
    path = Path(configured).expanduser().resolve()
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise RuntimeError("local API key file must not be group/world accessible")
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise RuntimeError("local API key file is empty")
    return value


def complete_local(messages: list[dict]) -> tuple[str, float, str, str]:
    """Send caller-built messages to the allowlisted local endpoint."""
    import requests

    endpoint, model, _allowed = _model_config()
    headers = {"Content-Type": "application/json"}
    key = _api_key()
    if key:
        headers["Authorization"] = f"Bearer {key}"
    ca_bundle = os.environ.get("SHIFT_LEFTER_CA_BUNDLE")
    verify: bool | str = (
        str(Path(ca_bundle).expanduser().resolve()) if ca_bundle else True
    )
    session = requests.Session()
    session.trust_env = False
    started = time.perf_counter()
    response = session.post(
        endpoint + "/chat/completions",
        headers=headers,
        json={
            "model": model,
            "messages": messages,
            "temperature": 0.0,
            "max_tokens": 128,
        },
        timeout=(5, 60),
        allow_redirects=False,
        verify=verify,
    )
    elapsed = time.perf_counter() - started
    if 300 <= response.status_code < 400:
        raise RuntimeError("model redirect rejected")
    response.raise_for_status()
    payload = response.json()
    content = str(payload["choices"][0]["message"]["content"])
    return content, elapsed, model, endpoint


def classify_local(path: Path, finding: dict) -> tuple[dict, float, str, str]:
    messages = guard.classifier_messages(path, finding)
    content, elapsed, model, endpoint = complete_local(messages)
    return guard.validate_classifier_content(content), elapsed, model, endpoint


def _primary_classifier(path: Path, finding: dict) -> tuple[dict, float, str, str]:
    return experiment.classify_local(path, finding)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    generate = sub.add_parser("generate")
    generate.add_argument(
        "--set",
        required=True,
        choices=(
            "pilot",
            "evaluation",
            experiment.EXPANDED_SET,
            experiment.INDEPENDENT_CONTEXT_SET,
        ),
    )
    generate.add_argument("--count", required=True, type=int)
    generate.add_argument("--seed", required=True, type=int)
    primary_run = sub.add_parser("primary-run")
    primary_run.add_argument("--set", required=True, choices=("pilot", "evaluation"))
    primary_run.add_argument("--repeats", type=int, default=3)
    for name in ("primary-analyze", "primary-verify"):
        command = sub.add_parser(name)
        command.add_argument("--set", required=True, choices=("pilot", "evaluation"))
    scanner_test_run = sub.add_parser("scanner-test-run")
    scanner_test_run.add_argument("--repeats", type=int, default=3)
    scanner_test_run.add_argument("--workers", type=int, default=1)
    scanner_test_run.add_argument(
        "--scanner", action="append", choices=guard.DEFAULT_SCANNERS
    )
    for command in (
        scanner_test_run,
        sub.add_parser("scanner-test-analyze"),
        sub.add_parser("scanner-test-verify"),
    ):
        command.add_argument("--result-name", default=scanner_test.DEFAULT_RESULT_NAME)
        command.add_argument("--source-set", default="evaluation")
    args = parser.parse_args(argv)

    if args.command == "generate":
        result = experiment.generate(args.set, args.count, args.seed)
    elif args.command == "primary-run":
        experiment.classify_local = _primary_classifier
        result = experiment.run(args.set, args.repeats)
    elif args.command == "primary-analyze":
        result = experiment.analyze(args.set)
    elif args.command == "primary-verify":
        result = experiment.verify(args.set)
    elif args.command == "scanner-test-run":
        guard.classify_redacted = classify_local
        result = scanner_test.run(
            args.repeats,
            args.result_name,
            args.source_set,
            args.workers,
            args.scanner,
        )
    elif args.command == "scanner-test-analyze":
        result = scanner_test.analyze(args.result_name, args.source_set)
    else:
        result = scanner_test.verify(args.result_name, args.source_set)
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.command.endswith("verify") and not result["passed"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
