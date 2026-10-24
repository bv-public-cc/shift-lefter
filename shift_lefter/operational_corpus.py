"""Generate a repository-grouped operational secret-detection corpus.

All credential-shaped values are deterministic, synthetic, and nonfunctional.
Raw artifacts and canaries are written only below SHIFT_LEFTER_ROOT/raw.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import random
import string
from collections import Counter
from pathlib import Path

from shift_lefter import experiment

SET_NAME = "operational-holdout-v1"
PROTOCOL_VERSION = "repository-holdout-v1"
POSITIVE_FAMILIES = (
    "aws_access_key",
    "github_pat",
    "gitlab_pat",
    "slack_bot_token",
    "slack_webhook",
    "stripe_secret",
    "sendgrid_key",
    "google_api_key",
    "jwt_hs256",
    "database_url",
    "basic_auth",
    "npm_token",
    "azure_storage",
    "private_key",
    "generic_runtime_secret",
    "split_runtime_secret",
)
NEGATIVE_FAMILIES = (
    "documented_aws_example",
    "placeholder_github_pat",
    "placeholder_gitlab_pat",
    "placeholder_slack_token",
    "placeholder_database_url",
    "placeholder_basic_auth",
    "sha256_checksum",
    "git_object_id",
    "package_integrity",
    "uuid",
    "container_digest",
    "public_key",
    "resource_identifier",
    "unsigned_example_jwt",
    "template_reference",
    "encoded_nonsecret_blob",
)
LAYOUTS = (
    ("source", "src/settings.py"),
    ("source", "lib/integration.js"),
    ("configuration", "config/service.yaml"),
    ("configuration", "config/runtime.toml"),
    ("configuration", "deploy/application.env"),
    ("infrastructure", "infra/main.tf"),
    ("infrastructure", "deploy/values.yaml"),
    ("documentation", "docs/integration.md"),
    ("test", "tests/fixtures.py"),
    ("test", "tests/cases.json"),
)
NEUTRAL_NOTES = (
    "integration value retained for compatibility assessment",
    "authentication-shaped field included in repository content",
    "service configuration value awaiting policy evaluation",
    "deployment-related material processed by automated validation",
    "identifier-shaped content associated with an application component",
    "configuration entry included in a repository change",
)


def _chars(rng: random.Random, alphabet: str, length: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(length))


def _alnum(rng: random.Random, length: int) -> str:
    return _chars(rng, string.ascii_letters + string.digits, length)


def _upper(rng: random.Random, length: int) -> str:
    return _chars(rng, string.ascii_uppercase + string.digits, length)


def _b64(rng: random.Random, byte_count: int) -> str:
    raw = bytes(rng.randrange(0, 256) for _ in range(byte_count))
    return base64.b64encode(raw).decode("ascii")


def _positive(rng: random.Random, family: str) -> tuple[str, str]:
    if family == "aws_access_key":
        return "aws_access_key_id", "AKIA" + _upper(rng, 16)
    if family == "github_pat":
        return "github_token", "ghp_" + _alnum(rng, 36)
    if family == "gitlab_pat":
        return "gitlab_token", "glpat-" + _alnum(rng, 24)
    if family == "slack_bot_token":
        return (
            "slack_token",
            f"xoxb-{rng.randrange(10**10, 10**11)}-{rng.randrange(10**10, 10**11)}-{_alnum(rng, 24)}",
        )
    if family == "slack_webhook":
        return "webhook_url", "https://hooks.slack.com/services/" + "/".join(
            _alnum(rng, length) for length in (9, 11, 24)
        )
    if family == "stripe_secret":
        return "stripe_api_key", "sk_live_" + _alnum(rng, 32)
    if family == "sendgrid_key":
        return "sendgrid_api_key", f"SG.{_alnum(rng, 22)}.{_alnum(rng, 43)}"
    if family == "google_api_key":
        return "google_api_key", "AIza" + _alnum(rng, 35)
    if family == "jwt_hs256":
        payload = (
            base64.urlsafe_b64encode(
                json.dumps({"sub": "svc-" + _alnum(rng, 12), "aud": "api"}).encode()
            )
            .decode()
            .rstrip("=")
        )
        return "bearer_token", f"eyJhbGciOiJIUzI1NiJ9.{payload}.{_alnum(rng, 43)}"
    if family == "database_url":
        return (
            "database_url",
            f"postgresql://service:{_alnum(rng, 28)}@db.internal/application",
        )
    if family == "basic_auth":
        value = base64.b64encode(
            f"svc-{_alnum(rng, 8)}:{_alnum(rng, 24)}".encode()
        ).decode()
        return "authorization", "Basic " + value
    if family == "npm_token":
        return "npm_token", "npm_" + _alnum(rng, 36)
    if family == "azure_storage":
        return (
            "storage_connection",
            "DefaultEndpointsProtocol=https;AccountName=svcstore;AccountKey="
            + _b64(rng, 48)
            + ";EndpointSuffix=core.windows.net",
        )
    if family == "private_key":
        return (
            "private_key",
            "-----BEGIN PRIVATE KEY-----\n"
            + _b64(rng, 48)
            + "\n-----END PRIVATE KEY-----",
        )
    if family == "generic_runtime_secret":
        return "service_credential", "svc_live_" + _alnum(rng, 40)
    if family == "split_runtime_secret":
        return "client_secret", _alnum(rng, 18) + "-" + _alnum(rng, 18)
    raise ValueError(family)


def _negative(rng: random.Random, family: str) -> tuple[str, str]:
    values = {
        "documented_aws_example": ("aws_access_key_id", "AKIAIOSFODNN7EXAMPLE"),
        "placeholder_github_pat": (
            "github_token",
            "ghp_EXAMPLE_REPLACE_WITH_TOKEN________",
        ),
        "placeholder_gitlab_pat": ("gitlab_token", "glpat-EXAMPLE_REPLACE_TOKEN"),
        "placeholder_slack_token": ("slack_token", "xoxb-EXAMPLE-REPLACE-THIS_VALUE"),
        "placeholder_database_url": (
            "database_url",
            "postgresql://service:REPLACE_PASSWORD@db.internal/application",
        ),
        "placeholder_basic_auth": (
            "authorization",
            "Basic RVhBTVBMRV9OT1RfQUNSRURFTlRJQUw=",
        ),
        "template_reference": ("api_token", "${SERVICE_API_TOKEN}"),
        "unsigned_example_jwt": (
            "bearer_token",
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiJleGFtcGxlIn0.PLACEHOLDER",
        ),
        "public_key": (
            "ssh_public_key",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEPUBLICKEYONLY",
        ),
        "resource_identifier": (
            "resource_id",
            "arn:aws:iam::123456789012:role/application-runtime",
        ),
    }
    if family in values:
        return values[family]
    if family == "sha256_checksum":
        return "sha256", hashlib.sha256(_alnum(rng, 20).encode()).hexdigest()
    if family == "git_object_id":
        return "revision", hashlib.sha1(_alnum(rng, 20).encode()).hexdigest()
    if family == "package_integrity":
        return "integrity", "sha512-" + _b64(rng, 64)
    if family == "uuid":
        return (
            "request_id",
            f"{rng.randrange(2**32):08x}-{rng.randrange(2**16):04x}-4{rng.randrange(2**12):03x}-a{rng.randrange(2**12):03x}-{rng.randrange(2**48):012x}",
        )
    if family == "container_digest":
        return (
            "image_digest",
            "sha256:" + hashlib.sha256(_alnum(rng, 24).encode()).hexdigest(),
        )
    if family == "encoded_nonsecret_blob":
        value = base64.b64encode(
            b"schema-compatible metadata without account access"
        ).decode()
        return "metadata_blob", value
    raise ValueError(family)


def _render(path: str, key: str, value: str, note: str) -> str:
    suffix = Path(path).suffix
    if suffix == ".py":
        return f"# {note}\n{key} = {json.dumps(value)}\n"
    if suffix == ".js":
        return f"// {note}\nconst {key} = {json.dumps(value)};\n"
    if suffix in {".yaml", ".yml"}:
        return f"# {note}\nservice:\n  {key}: {json.dumps(value)}\n"
    if suffix == ".toml":
        return f"# {note}\n[integration]\n{key} = {json.dumps(value)}\n"
    if suffix == ".env":
        return f"# {note}\n{key.upper()}={value}\n"
    if suffix == ".tf":
        return f"# {note}\nlocals {{\n  {key} = {json.dumps(value)}\n}}\n"
    if suffix == ".md":
        return f"# Integration configuration\n\n{note.capitalize()}.\n\n```text\n{key}={value}\n```\n"
    if suffix == ".json":
        return json.dumps({"note": note, key: value}, indent=2) + "\n"
    raise ValueError(path)


def generate(count: int = 6000, seed: int = 170031) -> dict:
    if count < 600 or count % 30:
        raise ValueError(
            "operational corpus count must be at least 600 and divisible by 30"
        )
    root = experiment._research_root() / "raw" / SET_NAME
    experiment._assert_outside_git(root)
    if root.exists():
        raise RuntimeError(f"refusing to overwrite operational corpus: {root}")
    artifacts = root / "artifacts"
    artifacts.mkdir(parents=True, mode=0o700)
    rng = random.Random(seed)
    labels = [1] * (count // 3) + [0] * (count - count // 3)
    rng.shuffle(labels)
    repo_count = count // 20
    records = []
    canaries = []
    family_counts: Counter[str] = Counter()
    channel_counts: Counter[str] = Counter()
    partition_counts: Counter[str] = Counter()
    positive_index = negative_index = 0
    for index, label in enumerate(labels):
        repo_number = index % repo_count
        repo_id = f"repo-{repo_number:04d}"
        partition = "calibration" if repo_number % 5 == 0 else "holdout"
        if label:
            family = POSITIVE_FAMILIES[positive_index % len(POSITIVE_FAMILIES)]
            positive_index += 1
            key, value = _positive(rng, family)
        else:
            family = NEGATIVE_FAMILIES[negative_index % len(NEGATIVE_FAMILIES)]
            negative_index += 1
            key, value = _negative(rng, family)
        channel, relative = LAYOUTS[
            (index * 7 + rng.randrange(len(LAYOUTS))) % len(LAYOUTS)
        ]
        stem, suffix = str(Path(relative).with_suffix("")), Path(relative).suffix
        filename = f"{repo_id}/{stem}-{index:05d}{suffix}"
        note = NEUTRAL_NOTES[
            (index + rng.randrange(len(NEUTRAL_NOTES))) % len(NEUTRAL_NOTES)
        ]
        content = _render(filename, key, value, note)
        destination = artifacts / filename
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        destination.write_text(content, encoding="utf-8", newline="\n")
        artifact_id = f"SL-O-{index:05d}"
        records.append(
            {
                "artifact_id": artifact_id,
                "category": family,
                "channel": channel,
                "filename": filename,
                "label": label,
                "partition": partition,
                "repo_id": repo_id,
                "sha256": experiment._sha256_file(destination),
            }
        )
        if label:
            canaries.append(value)
        family_counts[family] += 1
        channel_counts[channel] += 1
        partition_counts[partition] += 1
    rng.shuffle(records)
    manifest = {
        "count": count,
        "positive_count": sum(labels),
        "negative_count": count - sum(labels),
        "protocol_version": PROTOCOL_VERSION,
        "context_label_independent": True,
        "repository_grouped_holdout": True,
        "repo_count": repo_count,
        "calibration_repo_count": repo_count // 5,
        "holdout_repo_count": repo_count - repo_count // 5,
        "records": records,
    }
    experiment._write_json(root / "ground_truth.json", manifest)
    experiment._write_json(root / "canary_index.json", {"canaries": canaries})
    lock = {
        "generator_sha256": experiment._sha256_file(Path(__file__)),
        "gitleaks_config_sha256": experiment._sha256_file(experiment.CONFIG),
        "manifest_sha256": experiment._sha256_file(root / "ground_truth.json"),
        "seed": seed,
    }
    experiment._write_json(root / "lock.json", lock)
    return {
        "set_name": SET_NAME,
        "artifact_count": count,
        "positive_count": sum(labels),
        "negative_count": count - sum(labels),
        "repo_count": repo_count,
        "partition_counts": dict(sorted(partition_counts.items())),
        "family_counts": dict(sorted(family_counts.items())),
        "channel_counts": dict(sorted(channel_counts.items())),
        **lock,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=6000)
    parser.add_argument("--seed", type=int, default=170031)
    args = parser.parse_args(argv)
    print(json.dumps(generate(args.count, args.seed), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
