import json
from types import SimpleNamespace

import requests

from shift_lefter import standalone


def test_standalone_classifier_sends_only_redacted_context(tmp_path, monkeypatch):
    candidate = "candidate-must-never-reach-model"
    artifact = tmp_path / "app.py"
    artifact.write_text(f"# documentation example\napi_key = '{candidate}'\n")
    monkeypatch.setenv("SHIFT_LEFTER_MODEL_ENDPOINT", "https://localhost:8001/v1")
    monkeypatch.setenv("SHIFT_LEFTER_MODEL_NAME", "local-test-model")
    monkeypatch.setenv("SHIFT_LEFTER_ALLOWED_MODEL_HOSTS", "localhost")
    monkeypatch.delenv("SHIFT_LEFTER_CA_BUNDLE", raising=False)
    captured = {}

    class Response:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "verdict": "allow",
                                    "confidence": 0.99,
                                    "reason_code": "documentation_example",
                                }
                            )
                        }
                    }
                ]
            }

    class Session:
        trust_env = True

        def post(self, url, **kwargs):
            captured["trust_env"] = self.trust_env
            captured["url"] = url
            captured.update(kwargs)
            return Response()

    monkeypatch.setattr(requests, "Session", Session)
    result, _elapsed, model, endpoint = standalone.classify_local(
        artifact,
        {"scanner": "gitleaks", "rule_id": "api-token", "line": 2},
    )

    serialized = json.dumps(captured["json"])
    assert candidate not in serialized
    assert "<REDACTED_CANDIDATE" in serialized
    assert captured["trust_env"] is False
    assert captured["allow_redirects"] is False
    assert captured["verify"] is True
    assert model == "local-test-model"
    assert endpoint == "https://localhost:8001/v1"
    assert result["verdict"] == "allow"


def test_non_allowlisted_model_host_is_rejected(monkeypatch):
    monkeypatch.setenv("SHIFT_LEFTER_MODEL_ENDPOINT", "https://external.example/v1")
    monkeypatch.setenv("SHIFT_LEFTER_MODEL_NAME", "model")
    monkeypatch.delenv("SHIFT_LEFTER_ALLOWED_MODEL_HOSTS", raising=False)

    try:
        standalone._model_config()
    except RuntimeError as exc:
        assert "allowlisted" in str(exc)
    else:
        raise AssertionError("external model host was accepted")


def test_non_loopback_plaintext_requires_second_exact_allowlist(monkeypatch):
    monkeypatch.setenv("SHIFT_LEFTER_MODEL_ENDPOINT", "http://198.51.100.42:8000/v1")
    monkeypatch.setenv("SHIFT_LEFTER_MODEL_NAME", "spark-model")
    monkeypatch.setenv("SHIFT_LEFTER_ALLOWED_MODEL_HOSTS", "198.51.100.42")
    monkeypatch.delenv("SHIFT_LEFTER_ALLOW_PLAINTEXT_MODEL_HOSTS", raising=False)

    try:
        standalone._model_config()
    except RuntimeError as exc:
        assert "require HTTPS" in str(exc)
    else:
        raise AssertionError("plaintext remote endpoint was accepted without opt-in")

    monkeypatch.setenv("SHIFT_LEFTER_ALLOW_PLAINTEXT_MODEL_HOSTS", "198.51.100.42")
    endpoint, model, allowed = standalone._model_config()
    assert endpoint == "http://198.51.100.42:8000/v1"
    assert model == "spark-model"
    assert allowed == {"198.51.100.42"}


def test_api_key_can_be_read_from_named_environment_without_logging(monkeypatch):
    monkeypatch.delenv("SHIFT_LEFTER_LOCAL_API_KEY_FILE", raising=False)
    monkeypatch.setenv("SHIFT_LEFTER_LOCAL_API_KEY_ENV", "TEST_LOCAL_MODEL_KEY")
    monkeypatch.setenv("TEST_LOCAL_MODEL_KEY", "test-only-value")

    assert standalone._api_key() == "test-only-value"

    monkeypatch.setenv("SHIFT_LEFTER_LOCAL_API_KEY_ENV", "invalid-name")
    try:
        standalone._api_key()
    except RuntimeError as exc:
        assert "name is invalid" in str(exc)
    else:
        raise AssertionError("invalid environment variable name was accepted")
