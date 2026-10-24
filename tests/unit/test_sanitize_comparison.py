import importlib.util
from pathlib import Path

import pytest

TOOL = Path(__file__).parents[2] / "tools" / "sanitize_comparison.py"
SPEC = importlib.util.spec_from_file_location("sanitize_comparison", TOOL)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_sanitize_assigns_distinct_labels_and_removes_private_keys():
    payload = {
        "source_commit": "private",
        "conditions": {
            "a": {"model_endpoints": ["private-a"], "metrics": {"value": 1}},
            "b": {"model_endpoints": ["private-b"], "metrics": {"value": 2}},
        },
    }

    result = MODULE.sanitize(payload, {"a": "Endpoint A", "b": "Endpoint B"})

    assert "source_commit" not in result
    assert result["conditions"]["a"]["model_endpoints"] == ["Endpoint A"]
    assert result["conditions"]["b"]["model_endpoints"] == ["Endpoint B"]
    assert result["conditions"]["a"]["endpoint_address_redacted_for_publication"]


def test_sanitize_requires_exact_condition_mapping():
    payload = {"conditions": {"a": {"model_endpoints": ["private"]}}}

    with pytest.raises(ValueError, match="exactly match"):
        MODULE.sanitize(payload, {"b": "Endpoint B"})
