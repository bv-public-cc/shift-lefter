"""Atomic front-door receive gateway for developer-transparent secret policy.

Run this command from a bare gateway repository's pre-receive hook. Git keeps
new objects in quarantine while the command scans the proposed trees. Allowed
transactions are forwarded atomically to the authoritative upstream before the
gateway accepts its own ref update; rejected transactions never reach upstream.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urlparse

from shift_lefter import experiment, guard


@dataclass(frozen=True)
class RefUpdate:
    old_sha: str
    new_sha: str
    ref_name: str


def parse_updates(lines: Iterable[str]) -> list[RefUpdate]:
    updates = []
    for line in lines:
        fields = line.strip().split()
        if not fields:
            continue
        if len(fields) != 3:
            raise ValueError("invalid pre-receive record")
        old_sha, new_sha, ref_name = fields
        if not (len(old_sha) == len(new_sha) == 40):
            raise ValueError("invalid object ID in pre-receive record")
        if not ref_name.startswith("refs/") or any(char.isspace() for char in ref_name):
            raise ValueError("invalid ref name in pre-receive record")
        updates.append(RefUpdate(old_sha, new_sha, ref_name))
    if not updates:
        raise ValueError("empty pre-receive transaction")
    return updates


def _upstream_host(upstream: str) -> str:
    if os.environ.get("SHIFT_LEFTER_ALLOW_FILE_UPSTREAM") == "1" and (
        Path(upstream).is_absolute() or upstream.startswith(("./", "../"))
    ):
        return "local-file-test"
    parsed = urlparse(upstream)
    if parsed.scheme:
        if parsed.scheme not in {"ssh", "https"}:
            raise ValueError("upstream must use ssh or https")
        if parsed.scheme == "https" and (parsed.username or parsed.password):
            raise ValueError("credentials must not be embedded in the upstream URL")
        return (parsed.hostname or "").lower()
    if ":" in upstream and not upstream.startswith(("/", "./", "../")):
        return upstream.split(":", 1)[0].rsplit("@", 1)[-1].lower()
    raise ValueError("filesystem upstreams are disabled")


def validate_upstream(upstream: str, allowed_hosts: Iterable[str]) -> str:
    host = _upstream_host(upstream)
    allowed = {item.strip().lower() for item in allowed_hosts if item.strip()}
    if not allowed or host not in allowed:
        raise ValueError("upstream host is not explicitly allowlisted")
    return host


def forward_atomic(
    repo: Path, updates: list[RefUpdate], upstream: str, allowed_hosts: Iterable[str]
) -> None:
    host = validate_upstream(upstream, allowed_hosts)
    command = ["git", "-C", str(repo), "push", "--atomic", "--porcelain"]
    if host == "local-file-test" and os.environ.get("GIT_QUARANTINE_PATH"):
        command.append(
            "--receive-pack=env -u GIT_QUARANTINE_PATH -u GIT_OBJECT_DIRECTORY "
            "-u GIT_ALTERNATE_OBJECT_DIRECTORIES git-receive-pack"
        )
    for update in updates:
        expected = "" if update.old_sha == guard.ZERO_SHA else update.old_sha
        command.append(f"--force-with-lease={update.ref_name}:{expected}")
    command.append(upstream)
    for update in updates:
        source = "" if update.new_sha == guard.ZERO_SHA else update.new_sha
        command.append(f"{source}:{update.ref_name}")
    proc = subprocess.run(
        command, capture_output=True, text=True, timeout=120, check=False
    )
    if proc.returncode:
        raise RuntimeError(
            f"atomic upstream forwarding failed with exit {proc.returncode}"
        )


def _audit_record(
    updates: list[RefUpdate], results: list[dict], verdict: str, reason: str
) -> dict:
    transaction = "\n".join(
        f"{item.old_sha} {item.new_sha} {item.ref_name}" for item in updates
    )
    return {
        "schema_version": 1,
        "event_id": hashlib.sha256(transaction.encode()).hexdigest(),
        "verdict": verdict,
        "reason_code": reason,
        "ref_count": len(updates),
        "finding_file_count": len(results),
        "finding_count": sum(int(item.get("finding_count", 0)) for item in results),
        "scanner_error_count": sum(
            len(item.get("scanner_errors", [])) for item in results
        ),
        "ref_name_hashes": sorted(
            hashlib.sha256(item.ref_name.encode()).hexdigest() for item in updates
        ),
    }


def _write_audit(record: dict) -> None:
    path = experiment._research_root() / "gateway-audit" / "events.jsonl"
    experiment._assert_outside_git(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(experiment._canonical(record) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    if hasattr(os, "O_DIRECTORY"):
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def process_receive(
    repo: Path,
    lines: Iterable[str],
    upstream: str,
    allowed_hosts: Iterable[str],
    scanner: Callable[[Path, Iterable[str]], list[dict]] = guard.scan_receive,
    forwarder: Callable[
        [Path, list[RefUpdate], str, Iterable[str]], None
    ] = forward_atomic,
    preflight: Callable[[], dict[str, str]] = guard.preflight_scanners,
) -> dict:
    raw_lines = list(lines)
    updates = parse_updates(raw_lines)
    try:
        preflight()
    except Exception as exc:
        record = _audit_record(
            updates, [], "review", "scanner_preflight_error_fail_closed"
        )
        record["scanner_error_count"] = 1
        record["error_type"] = type(exc).__name__
        try:
            _write_audit(record)
        except Exception as audit_exc:
            record["reason_code"] = "scanner_and_audit_unavailable_fail_closed"
            record["audit_error_type"] = type(audit_exc).__name__
        return record
    results = scanner(repo, raw_lines)
    if results:
        record = _audit_record(updates, results, "block", "secret_policy_rejection")
        _write_audit(record)
        return {**record, "results": results}
    intent = _audit_record(updates, [], "review", "validated_pending_atomic_forward")
    try:
        _write_audit(intent)
    except Exception as exc:
        return {
            **intent,
            "reason_code": "audit_unavailable_fail_closed",
            "error_type": type(exc).__name__,
        }
    try:
        forwarder(repo, updates, upstream, allowed_hosts)
    except Exception as exc:
        record = _audit_record(
            updates, [], "review", "upstream_forward_error_fail_closed"
        )
        record["error_type"] = type(exc).__name__
        _write_audit(record)
        return record
    record = _audit_record(updates, [], "allow", "validated_and_forwarded_atomically")
    try:
        _write_audit(record)
    except Exception as exc:
        # The authoritative transaction already succeeded and cannot be safely
        # rolled back in the face of concurrent writers. The durable intent
        # record preserves an auditable indeterminate-completion marker, and
        # the client must receive success to match authoritative upstream state.
        record["reason_code"] = "validated_and_forwarded_audit_completion_error"
        record["error_type"] = type(exc).__name__
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--upstream", required=True)
    parser.add_argument(
        "--allow-host",
        action="append",
        default=[],
        help="exact upstream hostname; may be repeated",
    )
    args = parser.parse_args(argv)
    if os.environ.get("SHIFT_LEFTER_STANDALONE") == "1":
        from shift_lefter import standalone

        guard.classify_redacted = standalone.classify_local
    try:
        result = process_receive(
            args.repo.resolve(), sys.stdin, args.upstream, args.allow_host
        )
    except Exception as exc:
        print(
            f"shift-lefter: gateway rejected transaction ({type(exc).__name__})",
            file=sys.stderr,
        )
        return 2
    if result["verdict"] != "allow":
        print(
            f"shift-lefter: push rejected ({result['reason_code']}); "
            f"correlation={result['event_id'][:16]}",
            file=sys.stderr,
        )
        return 2
    print(
        f"shift-lefter: push accepted; correlation={result['event_id'][:16]}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
