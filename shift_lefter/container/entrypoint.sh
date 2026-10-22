#!/bin/sh
set -eu

: "${SHIFT_LEFTER_PROJECT_NAME:?set SHIFT_LEFTER_PROJECT_NAME}"
: "${SHIFT_LEFTER_UPSTREAM_URL:?set SHIFT_LEFTER_UPSTREAM_URL}"
: "${SHIFT_LEFTER_UPSTREAM_HOST:?set SHIFT_LEFTER_UPSTREAM_HOST}"
: "${SHIFT_LEFTER_MODEL_ENDPOINT:?set SHIFT_LEFTER_MODEL_ENDPOINT}"
: "${SHIFT_LEFTER_MODEL_NAME:?set SHIFT_LEFTER_MODEL_NAME}"
: "${SHIFT_LEFTER_ALLOWED_MODEL_HOSTS:?set SHIFT_LEFTER_ALLOWED_MODEL_HOSTS}"

case "$SHIFT_LEFTER_PROJECT_NAME" in
  *[!A-Za-z0-9._-]*|""|.*|*..*) echo "invalid project name" >&2; exit 2 ;;
esac

# OpenSSH deliberately builds a clean login environment, so arbitrary Docker
# variables are not inherited by the forced command or receive hook. Persist
# only the allowlisted non-secret runtime settings in protected ephemeral /run.
python - <<'PY'
import json
import os
from pathlib import Path

keys = (
    "PYTHONPATH",
    "SHIFT_LEFTER_PROJECT_NAME",
    "SHIFT_LEFTER_UPSTREAM_URL",
    "SHIFT_LEFTER_UPSTREAM_HOST",
    "SHIFT_LEFTER_ROOT",
    "SHIFT_LEFTER_TRANSIENT_ROOT",
    "SHIFT_LEFTER_GITLEAKS",
    "SHIFT_LEFTER_TRUFFLEHOG",
    "SHIFT_LEFTER_DETECT_SECRETS",
    "SHIFT_LEFTER_STANDALONE",
    "SHIFT_LEFTER_MODEL_ENDPOINT",
    "SHIFT_LEFTER_MODEL_NAME",
    "SHIFT_LEFTER_ALLOWED_MODEL_HOSTS",
    "SHIFT_LEFTER_ALLOW_PLAINTEXT_MODEL_HOSTS",
    "SHIFT_LEFTER_CA_BUNDLE",
    "SHIFT_LEFTER_LOCAL_API_KEY_FILE",
    "GIT_SSH_COMMAND",
)
config = {key: os.environ[key] for key in keys if os.environ.get(key)}
path = Path("/run/shift-lefter-gateway-config.json")
path.write_text(json.dumps(config, sort_keys=True), encoding="utf-8")
PY
chown root:git /run/shift-lefter-gateway-config.json
chmod 0440 /run/shift-lefter-gateway-config.json

repo="/srv/git/${SHIFT_LEFTER_PROJECT_NAME}.git"
# Bind mounts replace the ownership established by the image. Normalize the
# exact mount roots before cloning or inspecting the configured repository.
chown git:git /srv/git /srv/evidence
if [ ! -d "$repo" ]; then
  git clone --mirror "$SHIFT_LEFTER_UPSTREAM_URL" "$repo"
fi
chown -R git:git "$repo" /srv/evidence
test "$(git -c safe.directory="$repo" -C "$repo" rev-parse --is-bare-repository)" = true

hook="$repo/hooks/pre-receive"
cat >"$hook" <<'EOF'
#!/bin/sh
exec python -m shift_lefter.gateway \
  --repo "$PWD" \
  --upstream "$SHIFT_LEFTER_UPSTREAM_URL" \
  --allow-host "$SHIFT_LEFTER_UPSTREAM_HOST"
EOF
chmod 0700 "$hook"
chown -R git:git "$repo" /srv/evidence

install -d -m 0700 -o git -g git /home/git/.ssh
install -d -m 0700 -o git -g git /run/shift-lefter
install -m 0600 -o git -g git /run/secrets/authorized_keys /home/git/.ssh/authorized_keys
test -r /run/secrets/ssh_host_ed25519_key
test -r /run/secrets/ssh_host_rsa_key
install -d -m 0700 -o root -g root /run/shift-lefter-host-keys
install -m 0600 -o root -g root \
  /run/secrets/ssh_host_ed25519_key \
  /run/shift-lefter-host-keys/ssh_host_ed25519_key
install -m 0600 -o root -g root \
  /run/secrets/ssh_host_rsa_key \
  /run/shift-lefter-host-keys/ssh_host_rsa_key
exec /usr/sbin/sshd -D -e
