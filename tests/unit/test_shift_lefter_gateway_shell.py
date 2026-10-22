from pathlib import Path

from shift_lefter.container import gateway_shell


def test_container_requires_persistent_ssh_host_keys():
    container_dir = Path(gateway_shell.__file__).resolve().parent
    entrypoint = (container_dir / "entrypoint.sh").read_text()
    sshd_config = (container_dir / "sshd_config").read_text()

    assert "ssh-keygen -A" not in entrypoint
    assert "test -r /run/secrets/ssh_host_ed25519_key" in entrypoint
    assert "test -r /run/secrets/ssh_host_rsa_key" in entrypoint
    assert "HostKey /run/shift-lefter-host-keys/ssh_host_ed25519_key" in sshd_config


def test_gateway_shell_allows_only_configured_repository(monkeypatch):
    executed = []
    monkeypatch.setattr(
        gateway_shell,
        "_runtime_config",
        lambda: {"SHIFT_LEFTER_PROJECT_NAME": "project"},
    )
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", "git-receive-pack 'project.git'")
    monkeypatch.setattr(
        gateway_shell.os,
        "execvp",
        lambda executable, args: executed.append((executable, args)),
    )

    assert gateway_shell.main() == 2
    assert executed == [
        ("git-receive-pack", ["git-receive-pack", "/srv/git/project.git"])
    ]


def test_gateway_shell_rejects_traversal_and_arbitrary_commands(monkeypatch):
    monkeypatch.setattr(
        gateway_shell,
        "_runtime_config",
        lambda: {"SHIFT_LEFTER_PROJECT_NAME": "project"},
    )
    for command in (
        "git-receive-pack '../project.git'",
        "sh -c whoami",
        "git-upload-pack other.git",
    ):
        monkeypatch.setenv("SSH_ORIGINAL_COMMAND", command)
        assert gateway_shell.main() == 2


def test_gateway_shell_fails_closed_without_runtime_config(monkeypatch):
    monkeypatch.setattr(gateway_shell, "_runtime_config", lambda: {})
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", "git-receive-pack 'project.git'")

    assert gateway_shell.main() == 2


def test_runtime_config_rejects_unknown_or_nonstr_config(tmp_path, monkeypatch):
    config = tmp_path / "gateway.json"
    monkeypatch.setattr(gateway_shell, "CONFIG_PATH", config)
    config.write_text('{"UNKNOWN": "value"}', encoding="utf-8")
    assert gateway_shell._runtime_config() == {}
    config.write_text(
        '{"SHIFT_LEFTER_PROJECT_NAME": 7}',
        encoding="utf-8",
    )
    assert gateway_shell._runtime_config() == {}
