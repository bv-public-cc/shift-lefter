#!/bin/sh
set -eu

# Installs research-only scanner dependencies outside the Git worktree.
# Override versions explicitly when validating an upgrade.
GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.30.1}"
TRUFFLEHOG_VERSION="${TRUFFLEHOG_VERSION:-v3.99.1}"
DETECT_SECRETS_VERSION="${DETECT_SECRETS_VERSION:-1.5.0}"
SHIFT_LEFTER_ROOT="${SHIFT_LEFTER_ROOT:-$HOME/.local/share/shift-lefter}"
TOOLS_DIR="$SHIFT_LEFTER_ROOT/tools"
PYTHON_BIN="${SHIFT_LEFTER_PYTHON:-$(pwd)/.venv/bin/python}"

mkdir -p "$TOOLS_DIR"

case "$(uname -m)" in
  x86_64) architecture=amd64; gitleaks_architecture=x64 ;;
  aarch64|arm64) architecture=arm64; gitleaks_architecture=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 2 ;;
esac

gitleaks_version="${GITLEAKS_VERSION#v}"
gitleaks_archive="gitleaks_${gitleaks_version}_linux_${gitleaks_architecture}.tar.gz"
gitleaks_release="https://github.com/gitleaks/gitleaks/releases/download/v${gitleaks_version}"
temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"' EXIT
curl --fail --silent --show-error --location \
  "$gitleaks_release/$gitleaks_archive" \
  --output "$temp_dir/$gitleaks_archive"
curl --fail --silent --show-error --location \
  "$gitleaks_release/gitleaks_${gitleaks_version}_checksums.txt" \
  --output "$temp_dir/gitleaks-checksums.txt"
(
  cd "$temp_dir"
  grep "  $gitleaks_archive\$" gitleaks-checksums.txt | sha256sum --check --strict -
  tar -xzf "$gitleaks_archive" gitleaks
)
install -m 0755 "$temp_dir/gitleaks" "$TOOLS_DIR/gitleaks"

version="${TRUFFLEHOG_VERSION#v}"
archive="trufflehog_${version}_linux_${architecture}.tar.gz"
release="https://github.com/trufflesecurity/trufflehog/releases/download/${TRUFFLEHOG_VERSION}"
curl --fail --silent --show-error --location "$release/$archive" --output "$temp_dir/$archive"
curl --fail --silent --show-error --location \
  "$release/trufflehog_${version}_checksums.txt" \
  --output "$temp_dir/checksums.txt"
(
  cd "$temp_dir"
  grep "  $archive\$" checksums.txt | sha256sum --check --strict -
  tar -xzf "$archive" trufflehog
)
install -m 0755 "$temp_dir/trufflehog" "$TOOLS_DIR/trufflehog"

"$PYTHON_BIN" -m pip install "detect-secrets==$DETECT_SECRETS_VERSION"

"$TOOLS_DIR/gitleaks" version
"$TOOLS_DIR/trufflehog" --no-update --version
"$PYTHON_BIN" -m detect_secrets --version
