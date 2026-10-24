import importlib.util
from pathlib import Path

TOOL = Path(__file__).parents[2] / "tools" / "public_safety_check.py"
SPEC = importlib.util.spec_from_file_location("public_safety_check", TOOL)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_allows_exact_synthetic_sentinel_and_ignores_bytecode(tmp_path):
    (tmp_path / "corpus.py").write_text('value = "glpat-EXAMPLE_REPLACE_TOKEN"\n')
    cache = tmp_path / "__pycache__"
    cache.mkdir()
    private_ip = "192" + ".168.20.110"
    (cache / "generated.pyc").write_bytes(private_ip.encode())

    assert MODULE.main(tmp_path) == 0


def test_rejects_real_token_shape_and_private_identifier(tmp_path):
    token = "gl" + "pat-0123456789abcdefghijklmn"
    private_ip = "192" + ".168.20.110"
    (tmp_path / "unsafe.txt").write_text(token + "\n" + private_ip + "\n")

    assert MODULE.main(tmp_path) == 2
