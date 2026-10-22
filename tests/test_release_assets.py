"""Release checks for required third-party license notices."""

from __future__ import annotations

import hashlib
from pathlib import Path

from shift_lefter import experiment, guard

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_LICENSES = {
    "DETECT-SECRETS-LICENSE.txt": "cd6e5b5e743ad29917fb1b13c81cbf9795a8959cb8b94df59ce2ef384642a455",
    "GITLEAKS-LICENSE.txt": "e3884b252b3bfc045e55be43a34d1e80da070bc6f804ac95bf4660e97d62ebc6",
    "TRUFFLEHOG-LICENSE.txt": "33d580ea3d93edcb787c2fa826bbf5afcec3058ce4c894a6beaad3eb4f389d2b",
}


def test_standalone_package_resolves_repository_root() -> None:
    assert experiment.ROOT == ROOT
    assert guard.ROOT == ROOT


def test_pinned_scanner_license_texts_are_present_and_unchanged() -> None:
    license_dir = ROOT / "THIRD_PARTY_LICENSES"
    for filename, expected_hash in EXPECTED_LICENSES.items():
        contents = (license_dir / filename).read_bytes()
        assert hashlib.sha256(contents).hexdigest() == expected_hash


def test_scanner_notice_names_every_pinned_component() -> None:
    notice = (ROOT / "THIRD_PARTY_LICENSES" / "NOTICE.md").read_text(encoding="utf-8")
    for expected in (
        "Gitleaks",
        "TruffleHog",
        "detect-secrets",
        "8.30.1",
        "3.99.1",
        "1.5.0",
    ):
        assert expected in notice


def test_reference_gateway_defaults_to_strict_policy() -> None:
    containerfile = (ROOT / "shift_lefter" / "container" / "Containerfile").read_text(
        encoding="utf-8"
    )
    assert "SHIFT_LEFTER_POLICY_MODE=strict" in containerfile


def test_expanded_scanner_rules_ship_with_the_package() -> None:
    config = (ROOT / "shift_lefter" / "gitleaks.toml").read_text(encoding="utf-8")
    assert 'id = "shift-credential-assignment"' in config
    assert 'id = "shift-active-mode-value"' in config


def test_scanner_installer_fetches_and_checks_every_external_binary() -> None:
    script = (ROOT / "shift_lefter" / "install_scanners.sh").read_text(encoding="utf-8")
    for expected in (
        'GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.30.1}"',
        "gitleaks-checksums.txt",
        'install -m 0755 "$temp_dir/gitleaks" "$TOOLS_DIR/gitleaks"',
        "trufflehog_${version}_checksums.txt",
        'install -m 0755 "$temp_dir/trufflehog" "$TOOLS_DIR/trufflehog"',
    ):
        assert expected in script
