# Shift Lefter: Local Secret-Prevention Gateway and Reproducible Tests

This reference implementation evaluates deterministic secret scanning against
the same candidates plus a governed local contextual classifier. Its experiment
runner, model client, policy engine, evidence writer, and Git receive gateway
operate as a self-contained package.

Raw credential-shaped test files and the canary index must live outside every Git
worktree. A publishable ground-truth manifest may contain opaque IDs, labels,
categories, filenames, and hashes, but no candidate values. The runner stores
only hashes, rule identifiers, categorical verdicts, timing, and endpoint
metadata in its sanitized output. The standalone model client accepts only exact
allowlisted OpenAI-compatible local endpoints, rejects redirects, and ignores
ambient proxy configuration.

Create the standalone environment from the repository root:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
export SHIFT_LEFTER_ROOT="$HOME/.local/share/shift-lefter"
export SHIFT_LEFTER_PYTHON="$PWD/.venv/bin/python"
install -d -m 700 "$SHIFT_LEFTER_ROOT"
shift_lefter/install_scanners.sh
```

Validate the checkout from the repository root before generating data or
starting a gateway:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python tools/public_safety_check.py --root .
```

The full 3,000-item protocol is documented in [STANDALONE-REPRODUCTION.md](shift_lefter/STANDALONE-REPRODUCTION.md).
The review findings, implemented controls, and corrected rerun namespace are
recorded in [REVIEW-REMEDIATIONS.md](REVIEW-REMEDIATIONS.md). The experimental
batched detector for measuring scanner-miss recovery and corroborated
false-positive suppression is documented in
[SEMANTIC-DETECTOR.md](SEMANTIC-DETECTOR.md).

The publishable labeled test-data manifest is in
[`results/test-data/ground_truth.json`](results/test-data/ground_truth.json),
with its generation lock in [`results/test-data/lock.json`](results/test-data/lock.json).
These files show item IDs, labels, categories, channels, filenames, and hashes.
They intentionally omit credential-shaped values. The reproduction guide
generates those inert raw test files into a protected directory outside Git.

A small pilot can be run with:

```bash
export SHIFT_LEFTER_ROOT="$HOME/.local/share/shift-lefter"
export SHIFT_LEFTER_GITLEAKS="$SHIFT_LEFTER_ROOT/tools/gitleaks"

.venv/bin/python -m shift_lefter.standalone generate --set pilot --count 50 --seed 5009
.venv/bin/python -m shift_lefter.standalone primary-run --set pilot --repeats 1
.venv/bin/python -m shift_lefter.standalone primary-verify --set pilot
.venv/bin/python -m shift_lefter.standalone primary-analyze --set pilot
```

For a direct file check during research or troubleshooting, run:

```bash
.venv/bin/python -m shift_lefter.experiment gate --path /path/to/test-file
```

The command returns exit code `0` only for `allow`; `review` and `block` return
exit code `2`. It does not stage, commit, push, or publish the file. This
manual command is not the recommended developer integration; the transparent
gateway below preserves ordinary Git commands without a required workstation
hook.

## Recommended transparent front-door gateway

The developer gate adds Gitleaks, TruffleHog, and detect-secrets adapters while
preserving the locked experiment above. The recommended integration is a
Git-protocol gateway deployed in front of the authoritative Git host. The
implementation is not tied to GitLab: its SSH upstream may be GitLab, GitHub,
or another compatible Git receive service that supports the required atomic
ref transaction. Laboratory validation used GitLab; GitHub remains an
integration target rather than a tested result.
Organization-managed clone URLs or DNS point at the gateway. Developers keep
using the normal remote and ordinary commands:

```bash
git commit -m "change"
git push
```

The gateway's bare repository invokes this pre-receive command:

```bash
.venv/bin/python -m shift_lefter.gateway \
  --repo /srv/git-gateway/project.git \
  --upstream ssh://git@git.example.internal/group/project.git \
  --allow-host git.example.internal
```

Git supplies `<old-sha> <new-sha> <ref>` records on standard input. The gateway
scans every object newly reachable from the quarantined proposed tips, including
intermediate history and commit/tag messages, and atomically forwards the exact
ref transaction to the allowlisted upstream only after an `allow` decision.
It then accepts its own ref update. `review`, scanner/model errors, policy
blocks, and upstream-forward errors return nonzero, so the gateway transaction
is rejected and its quarantine is discarded. The reference SSH container starts
with the privileges required by `sshd` and runs Git sessions as an unprivileged
`git` user; it must not be described as rootless. No developer workstation
scanner, hook, or model runtime is required.

See [GATEWAY.md](shift_lefter/GATEWAY.md) for front-door, GitHub,
and self-managed hook integration notes, security boundaries, limitations, and
staged rollout.

This boundary prevents rejected bytes from reaching the upstream Git host,
becoming reachable in the authoritative repository, or triggering its CI and
repository consumers. It does
not prevent the original local commit from existing in the developer's clone.
If the requirement is
literally "no secret may enter even local Git object storage," a client-side
control at `git add` is unavoidable because Git has no server interaction at
that point.

## Optional strict-local mode

For repositories that require the stronger local-object guarantee, install the
clean filter once per clone:

```bash
export SHIFT_LEFTER_ROOT="$HOME/.local/share/shift-lefter"
export SHIFT_LEFTER_GITLEAKS="$SHIFT_LEFTER_ROOT/tools/gitleaks"
export SHIFT_LEFTER_TRUFFLEHOG="$SHIFT_LEFTER_ROOT/tools/trufflehog"
export SHIFT_LEFTER_DETECT_SECRETS="$(pwd)/.venv/bin/detect-secrets"

.venv/bin/python -m shift_lefter.guard install --repo "$(pwd)"
```

After installation, developers continue to use ordinary `git add`, `git commit`,
and `git push` commands:

1. A required clean filter checks every blob, including NUL-containing input,
   before Git accepts it during
   `git add`. An `allow` result streams the original bytes unchanged. A
   `review` or `block` result emits no bytes and makes `git add` fail.
2. A pre-commit hook scans the exact staged blobs, not potentially different
   working-tree files.
3. A pre-push hook scans all new objects in the outgoing commit range,
   including intermediate blobs and commit/tag messages.

The enforcement path is deliberately scanner-only and strict. Scanner reports
are parsed in memory and raw-object copies use ephemeral storage. Raw source,
raw values, and scanner reports are never durably logged. Missing scanners and
unknown outcomes fail closed as `review`. The contextual model is isolated in
the experiment runner and is not consulted by `git add`, hooks, or the gateway.

The gateway and workstation controls require
`SHIFT_LEFTER_POLICY_MODE=strict`. Any other value fails closed. Contextual
model decisions exist only as measured research conditions and cannot clear an
enforcement finding.

A confirmed false positive can be approved without weakening the scanner policy
by setting `SHIFT_LEFTER_FALSE_POSITIVE_ALLOWLIST` to an administrator-managed
JSON file outside every Git worktree. Each entry contains the exact artifact
SHA-256, exact sorted `scanner:rule` keys, an expiry with timezone, and a review
ticket. Invalid, stale, or changed entries fail closed, and private-key findings
cannot be excepted. See [REVIEW-REMEDIATIONS.md](REVIEW-REMEDIATIONS.md).

The gate deliberately does not rewrite a credential into a guessed placeholder.
Silent source rewriting can corrupt code or hide a credential that must be
revoked. Instead, it prevents the blob from entering Git and tells the
developer to replace the value with a Vault reference or an explicit safe
placeholder. This keeps the normal Git workflow transparent without making an
unsafe source-code decision on the developer's behalf.

The locked primary evaluation uses 300 test items and three hybrid repetitions.
The corrected v4 experiment uses 3,000 test items and one model pass per test item,
with bounded workers applied consistently to every model condition. Its v3
predecessor is retained as defect-discovery evidence rather than rewritten.
Do not generate a locked test dataset until the pilot passes and the protocol
is frozen.

The same runner supports a single-scanner contribution test through repeated
`--scanner gitleaks`, `--scanner trufflehog`, or `--scanner detect-secrets`
conditions. Each run records the selected scanner in every result row and the
run manifest. The reproduction guide shows how to compare models within one
scanner and how to summarize different scanners without pretending that they
produced identical candidates.

The archived v4/v5 corpus contains class-correlated context vocabulary and is
retained only as historical defect-discovery evidence. New runs must use
`independent-context-evaluation`; its neutral context templates are distributed
across both labels, and candidate-line words are not projected into prompts.

## Third-party scanners

The reference container pins Gitleaks 8.30.1, TruffleHog 3.99.1, and
detect-secrets 1.5.0. Their exact upstream license texts and a component notice
are stored in [`THIRD_PARTY_LICENSES/`](THIRD_PARTY_LICENSES/NOTICE.md).
