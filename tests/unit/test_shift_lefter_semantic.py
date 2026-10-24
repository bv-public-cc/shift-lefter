import json

import pytest

from shift_lefter import semantic


def _assessment(candidate_id, classification, confidence, evidence):
    return {
        "candidate_id": candidate_id,
        "classification": classification,
        "confidence": confidence,
        "evidence_codes": evidence,
    }


def test_feature_packet_never_contains_candidate(tmp_path):
    raw = "ghp_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S"
    artifact = tmp_path / "app.py"
    artifact.write_text(f'github_token = "{raw}"\n', encoding="utf-8")
    findings = [{"scanner": "gitleaks", "rule_id": "github-pat", "line": 1}]

    candidates = semantic.candidate_features(artifact, findings)
    serialized = json.dumps(semantic.semantic_messages(artifact, candidates))

    assert len(candidates) == 1
    assert raw not in serialized
    assert candidates[0]["value_features"]["known_format"] == "github_pat"
    assert candidates[0]["context_features"]["assignment_category"] == "credential"


def test_nested_placeholder_is_deterministically_visible_without_raw_value(tmp_path):
    artifact = tmp_path / "fixture.yaml"
    artifact.write_text(
        'value: "password = \\"EXAMPLE_NOT_A_PASSWORD\\""\n', encoding="utf-8"
    )
    findings = [{"scanner": "gitleaks", "rule_id": "password", "line": 1}]

    candidate = semantic.candidate_features(artifact, findings)[0]

    assert candidate["value_features"]["placeholder_match"] is True
    assert "EXAMPLE_NOT_A_PASSWORD" not in json.dumps(candidate)


def test_semantic_response_requires_every_candidate_and_safe_evidence():
    payload = json.dumps(
        {
            "candidates": [
                _assessment("L1", "false_positive", 0.99, ["placeholder_pattern"])
            ]
        }
    )

    result = semantic.validate_semantic_content(payload, {"L1"})

    assert result[0]["classification"] == "false_positive"
    with pytest.raises(ValueError, match="safe evidence"):
        semantic.validate_semantic_content(
            json.dumps(
                {
                    "candidates": [
                        _assessment("L1", "false_positive", 0.99, ["high_entropy"])
                    ]
                }
            ),
            {"L1"},
        )
    with pytest.raises(ValueError, match="omitted"):
        semantic.validate_semantic_content('{"candidates": []}', {"L1"})


def test_semantic_detector_recovers_scanner_miss(tmp_path):
    artifact = tmp_path / "app.py"
    artifact.write_text('password = "opaque-value-123456789"\n', encoding="utf-8")
    candidates = semantic.candidate_features(artifact, [])
    assessment = _assessment(
        candidates[0]["candidate_id"],
        "secret",
        0.97,
        ["credential_assignment", "high_entropy"],
    )

    verdict, reason = semantic.decide([], candidates, [assessment], [])

    assert verdict == "block"
    assert reason == "semantic_secret_detected"


def test_semantic_suppression_requires_model_and_deterministic_agreement(tmp_path):
    artifact = tmp_path / "example.py"
    artifact.write_text('api_token = "EXAMPLE_REPLACE_TOKEN"\n', encoding="utf-8")
    findings = [{"scanner": "gitleaks", "rule_id": "generic-token", "line": 1}]
    candidates = semantic.candidate_features(artifact, findings)
    assessment = _assessment(
        candidates[0]["candidate_id"],
        "false_positive",
        0.995,
        ["placeholder_pattern"],
    )

    assert semantic.decide(findings, candidates, [assessment], []) == (
        "allow",
        "corroborated_false_positive",
    )
    assessment["confidence"] = 0.89
    assert semantic.decide(findings, candidates, [assessment], [])[0] == "block"


def test_semantic_model_cannot_suppress_uncorroborated_credential(tmp_path):
    artifact = tmp_path / "app.py"
    artifact.write_text('api_token = "opaque-value-123456789"\n', encoding="utf-8")
    findings = [{"scanner": "gitleaks", "rule_id": "generic-token", "line": 1}]
    candidates = semantic.candidate_features(artifact, findings)
    assessment = _assessment(
        candidates[0]["candidate_id"],
        "false_positive",
        1.0,
        ["documentation_or_test_file"],
    )

    assert semantic.decide(findings, candidates, [assessment], []) == (
        "block",
        "semantic_scanner_hold",
    )


def test_private_key_remains_non_overridable(tmp_path):
    artifact = tmp_path / "key.txt"
    artifact.write_text(
        "-----BEGIN PRIVATE KEY-----\nEXAMPLE_VALUE\n", encoding="utf-8"
    )
    findings = [{"scanner": "gitleaks", "rule_id": "private-key", "line": 1}]
    candidates = semantic.candidate_features(artifact, findings)
    assessment = _assessment(
        candidates[0]["candidate_id"],
        "false_positive",
        1.0,
        ["placeholder_pattern"],
    )

    assert semantic.decide(findings, candidates, [assessment], []) == (
        "block",
        "non_overridable_hard_block",
    )
