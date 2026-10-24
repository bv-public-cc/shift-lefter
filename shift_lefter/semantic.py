"""Privacy-preserving, batched semantic secret classification.

Raw candidate values never leave this module.  The model receives only derived
shape features, allowlisted context categories, and scanner metadata.  Model
output may add a finding, but suppressing a scanner finding additionally
requires deterministic evidence that the value is a placeholder or a known
non-secret identifier.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path

CLASSIFICATIONS = frozenset({"secret", "false_positive", "uncertain"})
EVIDENCE_CODES = frozenset(
    {
        "credential_assignment",
        "recognized_credential_format",
        "authorization_context",
        "high_entropy",
        "multiple_scanners",
        "scanner_rule",
        "placeholder_pattern",
        "nonsecret_identifier_format",
        "documentation_or_test_file",
        "insufficient_context",
    }
)
SAFE_EVIDENCE = frozenset(
    {"placeholder_pattern", "nonsecret_identifier_format", "documentation_or_test_file"}
)
RISK_EVIDENCE = frozenset(
    {
        "credential_assignment",
        "recognized_credential_format",
        "authorization_context",
        "high_entropy",
        "multiple_scanners",
        "scanner_rule",
    }
)
PLACEHOLDER_RE = re.compile(
    r"(?:example|sample|dummy|placeholder|redacted|replace|fictional|not[_-]?a|test[_-]?(?:only|fixture|token|password))",
    re.IGNORECASE,
)
QUOTED_RE = re.compile(r"(?P<quote>['\"])(?P<value>[^'\"\r\n]{4,1024})(?P=quote)")
TOKEN_RE = re.compile(
    r"(?:ghp_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+|"
    r"https?://[^\s'\"]+|(?:SLAPI|SLTOK)_[A-Za-z0-9_]{16,}|[A-Za-z0-9+/]{24,}={0,2})"
)
ASSIGNMENT_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_.-]{1,80})\s*[:=]")
CREDENTIAL_KEYS = {
    "api_key",
    "api_token",
    "authorization",
    "bearer_token",
    "credential",
    "credential_candidate",
    "database_url",
    "github_token",
    "password",
    "secret",
    "service_credential",
    "token",
    "value",
    "webhook_url",
    "aws_access_key_id",
}
NONSECRET_KEYS = {
    "checksum",
    "digest",
    "hash",
    "integrity",
    "request_id",
    "revision",
    "sha256",
}


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum(
        (count / len(value)) * math.log2(count / len(value))
        for count in counts.values()
    )


def _entropy_bucket(value: str) -> str:
    entropy = _entropy(value)
    if entropy >= 4.0:
        return "high"
    if entropy >= 2.5:
        return "medium"
    return "low"


def _charset(value: str) -> str:
    if re.fullmatch(r"[0-9a-fA-F]+", value):
        return "hex"
    if re.fullmatch(r"[A-Za-z0-9]+", value):
        return "alphanumeric"
    if re.fullmatch(r"[A-Za-z0-9+/=_-]+", value):
        return "encoded"
    return "mixed"


def _assignment_category(line: str) -> str:
    match = ASSIGNMENT_RE.search(line)
    if not match:
        if re.search(r"Authorization\s*:\s*(?:Basic|Bearer)", line, re.IGNORECASE):
            return "authorization"
        return "other"
    key = match.group(1).lower()
    if key in NONSECRET_KEYS or any(
        part in key for part in ("checksum", "digest", "integrity", "revision")
    ):
        return "nonsecret_identifier"
    if key in CREDENTIAL_KEYS or any(
        part in key
        for part in ("password", "secret", "token", "credential", "auth", "webhook")
    ):
        return "credential"
    return "other"


def _file_category(path: Path) -> str:
    lowered = path.as_posix().lower()
    if any(part in lowered for part in ("/test/", "/tests/", "fixture", "spec.")):
        return "test"
    if path.suffix.lower() in {".md", ".rst", ".adoc"} or "/docs/" in lowered:
        return "documentation"
    if path.suffix.lower() in {".yaml", ".yml", ".json", ".toml", ".ini", ".env"}:
        return "configuration"
    if path.suffix.lower() in {".tf", ".tfvars", ".hcl"}:
        return "infrastructure"
    return "source"


def _known_format(value: str, line: str) -> str:
    if "-----BEGIN PRIVATE KEY-----" in line:
        return "private_key"
    if re.search(r"ghp_[A-Za-z0-9]{36,}\b", value):
        return "github_pat"
    if re.search(r"\bAKIA[A-Z0-9]{16}\b", value):
        return "aws_access_key"
    if re.search(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+", value):
        return "jwt"
    if "hooks.slack.com/services/" in value:
        return "slack_webhook"
    if re.search(r"(?:postgres(?:ql)?|mysql|mongodb)://[^:@/\s]+:[^@/\s]+@", value):
        return "database_url"
    if re.search(r"Authorization\s*:\s*Basic\s+", line, re.IGNORECASE):
        return "basic_auth"
    if re.search(r"(?:SLAPI|SLTOK)_[A-Za-z0-9_]{16,}", value):
        return "synthetic_token"
    return "unknown"


def _nonsecret_format(value: str, assignment: str) -> str:
    stripped = value.strip().strip("'\"")
    if re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", stripped):
        return "content_hash" if assignment == "nonsecret_identifier" else "none"
    if re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
        stripped,
    ):
        return "uuid"
    if stripped.startswith("sha512-") and assignment == "nonsecret_identifier":
        return "package_integrity"
    return "none"


def _candidate_value(line: str) -> str | None:
    quoted = QUOTED_RE.search(line)
    if quoted:
        return quoted.group("value")
    token = TOKEN_RE.search(line)
    if token:
        return token.group(0)
    if "-----BEGIN PRIVATE KEY-----" in line:
        return "PRIVATE_KEY_MATERIAL"
    if ASSIGNMENT_RE.search(line):
        value = re.split(r"[:=]", line, maxsplit=1)[-1].strip()
        return value if len(value) >= 4 else None
    return None


def candidate_features(path: Path, findings: list[dict]) -> list[dict]:
    """Return model-safe features for scanner hits and credential-like values."""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    by_line: dict[int, list[dict]] = {}
    for finding in findings:
        if int(finding.get("line", 0)) > 0:
            by_line.setdefault(int(finding["line"]), []).append(finding)
    candidates = []
    for line_number, line in enumerate(lines, 1):
        value = _candidate_value(line)
        scanner_findings = by_line.get(line_number, [])
        assignment = _assignment_category(line)
        if value is None and not scanner_findings:
            continue
        if value is None:
            value = "UNKNOWN_CANDIDATE"
        # Inspect the complete line locally so escaped, nested configuration
        # strings are still recognized. Only categorical derivatives below
        # are returned; the line and value never enter the feature packet.
        known_format = _known_format(line, line)
        placeholder = bool(PLACEHOLDER_RE.search(line))
        nonsecret_format = _nonsecret_format(value, assignment)
        candidate_like = (
            bool(scanner_findings)
            or known_format != "unknown"
            or assignment == "credential"
            or nonsecret_format != "none"
        )
        if not candidate_like:
            continue
        candidates.append(
            {
                "candidate_id": f"L{line_number}",
                "line": line_number,
                "scanner_hit": bool(scanner_findings),
                "scanner_count": len({item["scanner"] for item in scanner_findings}),
                "scanner_rules": sorted(
                    {
                        f"{item['scanner']}:{item['rule_id']}"
                        for item in scanner_findings
                    }
                ),
                "value_features": {
                    "length_bucket": (
                        "short"
                        if len(value) < 16
                        else "medium" if len(value) < 40 else "long"
                    ),
                    "entropy": _entropy_bucket(value),
                    "charset": _charset(value),
                    "known_format": known_format,
                    "placeholder_match": placeholder,
                    "nonsecret_format": nonsecret_format,
                },
                "context_features": {
                    "file_category": _file_category(path),
                    "assignment_category": assignment,
                    "authorization_context": bool(
                        re.search(
                            r"Authorization\s*:\s*(?:Basic|Bearer)", line, re.IGNORECASE
                        )
                    ),
                },
            }
        )
    return candidates


def semantic_messages(path: Path, candidates: list[dict]) -> list[dict]:
    packet = {
        "file_type": path.suffix.lower() or "none",
        "candidates": candidates,
    }
    system = (
        "You are a secret-detection classifier. Artifact values and source text were removed. "
        "Classify every candidate_id using only the supplied derived features. Return one JSON "
        "object with exactly the key candidates. Each result must contain exactly candidate_id, "
        "classification (secret, false_positive, or uncertain), confidence (0 to 1), and "
        "evidence_codes. evidence_codes must come from: "
        + ", ".join(sorted(EVIDENCE_CODES))
        + ". Use false_positive only with explicit placeholder, non-secret identifier, documentation, "
        "or test evidence. Do not infer or reconstruct removed values. Prefer uncertain when evidence conflicts."
    )
    return [
        {"role": "system", "content": system},
        {
            "role": "user",
            "content": json.dumps(packet, sort_keys=True, separators=(",", ":")),
        },
    ]


def validate_semantic_content(content: str, candidate_ids: set[str]) -> list[dict]:
    content = content.strip()
    if content.startswith("```"):
        content = (
            content.removeprefix("```json")
            .removeprefix("```")
            .removesuffix("```")
            .strip()
        )
    payload = json.loads(content)
    if set(payload) != {"candidates"} or not isinstance(payload["candidates"], list):
        raise ValueError("semantic response schema is invalid")
    output = []
    seen = set()
    for item in payload["candidates"]:
        if set(item) != {
            "candidate_id",
            "classification",
            "confidence",
            "evidence_codes",
        }:
            raise ValueError("semantic candidate schema is invalid")
        candidate_id = item["candidate_id"]
        if candidate_id not in candidate_ids or candidate_id in seen:
            raise ValueError("semantic candidate id is invalid")
        seen.add(candidate_id)
        classification = item["classification"]
        if classification not in CLASSIFICATIONS:
            raise ValueError("semantic classification is invalid")
        confidence = float(item["confidence"])
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("semantic confidence is invalid")
        evidence = item["evidence_codes"]
        if (
            not isinstance(evidence, list)
            or not evidence
            or not all(code in EVIDENCE_CODES for code in evidence)
            or len(evidence) != len(set(evidence))
        ):
            raise ValueError("semantic evidence is invalid")
        if classification == "false_positive" and not SAFE_EVIDENCE.intersection(
            evidence
        ):
            raise ValueError("false-positive classification lacks safe evidence")
        if classification == "secret" and not RISK_EVIDENCE.intersection(evidence):
            raise ValueError("secret classification lacks risk evidence")
        output.append(
            {
                "candidate_id": candidate_id,
                "classification": classification,
                "confidence": confidence,
                "evidence_codes": sorted(evidence),
            }
        )
    if seen != candidate_ids:
        raise ValueError("semantic response omitted candidates")
    return sorted(output, key=lambda item: item["candidate_id"])


def classify_local(
    path: Path, candidates: list[dict]
) -> tuple[list[dict], float, str, str]:
    from shift_lefter import standalone

    messages = semantic_messages(path, candidates)
    content, elapsed, model, endpoint = standalone.complete_local(
        messages, json_object=True
    )
    return (
        validate_semantic_content(
            content, {item["candidate_id"] for item in candidates}
        ),
        elapsed,
        model,
        endpoint,
    )


def _hard_block(findings: list[dict]) -> bool:
    return any(
        "private" in item["rule_id"].lower() and "key" in item["rule_id"].lower()
        for item in findings
    )


def _corroborated_safe(candidate: dict, assessment: dict) -> bool:
    features = candidate["value_features"]
    deterministic = (
        bool(features["placeholder_match"]) or features["nonsecret_format"] != "none"
    )
    model_safe = bool(SAFE_EVIDENCE.intersection(assessment["evidence_codes"]))
    return deterministic and model_safe


def decide(
    findings: list[dict],
    candidates: list[dict],
    assessments: list[dict],
    scanner_errors: list[dict],
    *,
    allow_suppression: bool = True,
) -> tuple[str, str]:
    """Apply asymmetric union detection and corroborated suppression."""
    if scanner_errors:
        return "review", "scanner_error_fail_closed"
    by_id = {item["candidate_id"]: item for item in assessments}
    for candidate in candidates:
        assessment = by_id.get(candidate["candidate_id"])
        if (
            not candidate["scanner_hit"]
            and assessment
            and assessment["classification"] == "secret"
            and assessment["confidence"] >= 0.95
            and RISK_EVIDENCE.intersection(assessment["evidence_codes"])
        ):
            return "block", "semantic_secret_detected"
    if not findings:
        return "allow", "no_secret_detected"
    if _hard_block(findings):
        return "block", "non_overridable_hard_block"
    scanner_candidates = [item for item in candidates if item["scanner_hit"]]
    finding_lines = {int(item["line"]) for item in findings if int(item["line"]) > 0}
    candidate_lines = {int(item["line"]) for item in scanner_candidates}
    if (
        not allow_suppression
        or not finding_lines
        or not finding_lines.issubset(candidate_lines)
    ):
        return "block", "semantic_scanner_hold"
    for candidate in scanner_candidates:
        assessment = by_id.get(candidate["candidate_id"])
        if (
            not assessment
            or assessment["classification"] != "false_positive"
            or assessment["confidence"] < 0.99
            or not _corroborated_safe(candidate, assessment)
        ):
            return "block", "semantic_scanner_hold"
    return "allow", "corroborated_false_positive"
