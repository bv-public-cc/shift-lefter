# Shift Lefter Secret-Detection Experiment and Developer Gate

This reference implementation compares standard secret scanning with the same
potential secrets reviewed by a controlled local classifier. Its experiment
runner, model client, policy engine, evidence writer, and Git receive gateway
operate as a self-contained package.

Raw artifacts and ground truth must live outside every Git worktree. The runner
stores only hashes, rule identifiers, categorical verdicts, timing, and endpoint
metadata in its sanitized output. The standalone model client accepts only exact
allowlisted OpenAI-compatible local endpoints, rejects redirects, and ignores
ambient proxy configuration.

Typical commands from the repository root:

```bash
export SHIFT_LEFTER_ROOT="$HOME/.local/share/shift-lefter"
export SHIFT_LEFTER_GITLEAKS="$SHIFT_LEFTER_ROOT/tools/gitleaks"

.venv/bin/python -m shift_lefter.standalone generate --set pilot --count 50 --seed 5009
.venv/bin/python -m shift_lefter.standalone primary-run --set pilot --repeats 1
.venv/bin/python -m shift_lefter.standalone primary-verify --set pilot
.venv/bin/python -m shift_lefter.standalone primary-analyze --set pilot
```

For a developer-facing pre-source-control decision, run:

```bash
.venv/bin/python -m shift_lefter.experiment gate --path /path/to/staged-artifact
```

The command returns exit code `0` only for `allow`; `review` and `block` return
exit code `2`, suitable for a pre-commit hook or an editor/CLI wrapper. It does
not stage, commit, push, or publish the artifact.

## Recommended transparent front-door gateway

The developer gate adds Gitleaks, TruffleHog, and detect-secrets adapters while
preserving the locked experiment above. The recommended integration is a
Git-protocol gateway deployed in front of the authoritative Git host. The
implementation is not tied to GitLab: its SSH upstream may be GitLab, GitHub,
or another compatible Git receive service. Laboratory validation used GitLab;
GitHub remains an integration target rather than a tested result.
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

See [GATEWAY.md](GATEWAY.md) for front-door, GitHub, and self-managed hook
integration notes, security boundaries, limitations, and staged rollout.

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

The enforcement path is scanner-only and strict. Scanner reports are parsed in
memory and raw-object copies use ephemeral storage. Raw source, raw values, and
scanner reports are never durably logged. Missing scanners and unknown outcomes
fail closed as `review`. The contextual model is isolated in the experiment
runner and is not consulted by `git add`, hooks, or the gateway.

The gateway and workstation controls require
`SHIFT_LEFTER_POLICY_MODE=strict`. Any other value fails closed. Contextual
model decisions exist only as measured research conditions and cannot clear an
enforcement finding.

Confirmed false positives use an administrator-managed, expiring exception file
outside Git. Entries bind the exact artifact SHA-256 to the exact sorted
`scanner:rule` set and a review ticket. Invalid, stale, or changed entries fail
closed, and private-key findings cannot be excepted. The schema is documented in
`REVIEW-REMEDIATIONS.md`.

The gate deliberately does not rewrite a credential into a guessed placeholder.
Silent source rewriting can corrupt code or hide a credential that must be
revoked. Instead, it prevents the blob from entering Git and tells the
developer to replace the value with a Vault reference or an explicit safe
placeholder. This keeps the normal Git workflow transparent without making an
unsafe source-code decision on the developer's behalf.

The historical evaluations remain archived. New runs use the separately named
`independent-context-evaluation` protocol described in
`REVIEW-REMEDIATIONS.md`; do not combine its results with the v4/v5 archive.
The optional `--semantic-batch` v7 test sends one feature summary without raw
values per file. It measures both additional detections and suppressions that
fixed rules independently confirm. It remains outside Git enforcement; see
`SEMANTIC-DETECTOR.md`.
