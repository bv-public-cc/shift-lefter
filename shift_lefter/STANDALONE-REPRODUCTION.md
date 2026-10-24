# Standalone Reproduction Guide

This guide reproduces the Shift Lefter three-scanner experiment and exercises the receive gateway using only the reference implementation. It requires Python, Git, Gitleaks, TruffleHog, detect-secrets, and an OpenAI-compatible local model endpoint. No agent framework or orchestration service is required. The raw test data remains outside Git; only reviewed, content-free results are publishable.

## 1. What this protocol reproduces

The recommended protocol is the separately versioned
`evaluation-v6-independent-context` study:

- the same frozen 3,000-item synthetic test dataset for every condition: 1,000 planted secret cases and 2,000 safe cases;
- five file channels and fifteen secret, false-positive, and clean-control categories;
- Gitleaks 8.30.1 with its standard rules plus the research rules;
- TruffleHog 3.99.1 with update and online verification disabled;
- detect-secrets 1.5.0 with online verification disabled;
- structured/redacted context sent to each local model;
- lines containing potential secrets represented only by a hash and approved meaning and structure details;
- strict `allow`, `review`, or `block` response validation, including verdict/reason consistency;
- rule-based fail-closed policy, which blocks on errors, and private-key findings that the model cannot override;
- one classification pass per artifact, with the earlier 300-item pilot retaining three repetitions for stability evidence;
- four limited workers, with output always written in test-manifest order;
- separate result sets for each model and a comparison that refuses unequal scanner inputs or source hashes.

The original fixed Gitleaks-only study and the 300-item v2 combined-scanner test remain archived results. The original study's limited prompt included raw generated source context. The 3,000-item v3 run is kept because it uncovered scanner misses, unsafe contextual downgrades, and an unauthenticated model condition. The v4/v5 `expanded-evaluation` test set also contains context words that reveal the expected label. Do not present these tests as independent validation or combine their statistics across versions. New runs use `independent-context-evaluation` and v6 result names as specified in `REVIEW-REMEDIATIONS.md`.

## 2. Security boundary

Use only synthetic, nonfunctional values. Do not substitute production credentials. Create the research root outside every Git worktree and restrict it to the experiment operator.

The v4 path provides these controls:

- scanner reports are parsed from process memory rather than written to disk;
- temporary Git-object materialization uses `SHIFT_LEFTER_TRANSIENT_ROOT`, which should be a private tmpfs or other ephemeral directory;
- TruffleHog uses `--no-update --no-verification` and detect-secrets uses `--no-verify`;
- model hosts require an exact allowlist, redirects are rejected, ambient proxies are disabled, and non-loopback HTTP is rejected unless a second exact-host lab exception is configured;
- model prompts contain no raw source line or potential secret value;
- result records reject raw-content field names and contain hashes, identifiers, categorical decisions, timing, and versions only;
- scanner, transport, response-schema, or model failures become `review`, which rejects a gateway transaction.

Hashes of files and redacted lines are still sensitive information. Protect the research folder and set a retention period even though result records do not contain the raw values being checked.

## 3. Minimal directory

Clone the repository or copy the top-level `shift_lefter/` package and retain:

```text
shift_lefter/__init__.py
shift_lefter/context_markers.json
REVIEW-REMEDIATIONS.md
shift_lefter/scanner_test.py
shift_lefter/experiment.py
shift_lefter/gateway.py
shift_lefter/gitleaks.toml
shift_lefter/guard.py
shift_lefter/install_scanners.sh
shift_lefter/standalone.py
```

`standalone.py` installs the self-contained model client before any optional integration adapter can execute. The commands in this guide require only the files listed above and the declared runtime dependencies.

## 4. Runtime and pinned scanners

The recorded study used Python 3.12, Gitleaks 8.30.1, TruffleHog 3.99.1, and detect-secrets 1.5.0.

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install requests==2.34.2 detect-secrets==1.5.0

export SHIFT_LEFTER_ROOT="$HOME/.local/share/shift-lefter-reproduction"
export SHIFT_LEFTER_TRANSIENT_ROOT="/dev/shm/shift-lefter-$USER"
export SHIFT_LEFTER_PYTHON="$PWD/.venv/bin/python"
install -d -m 700 "$SHIFT_LEFTER_ROOT" "$SHIFT_LEFTER_TRANSIENT_ROOT"

shift_lefter/install_scanners.sh
export SHIFT_LEFTER_GITLEAKS="$SHIFT_LEFTER_ROOT/tools/gitleaks"
export SHIFT_LEFTER_TRUFFLEHOG="$SHIFT_LEFTER_ROOT/tools/trufflehog"
export SHIFT_LEFTER_DETECT_SECRETS="$PWD/.venv/bin/detect-secrets"
```

Record versions before execution:

```bash
"$SHIFT_LEFTER_GITLEAKS" version
"$SHIFT_LEFTER_TRUFFLEHOG" --no-update --version
"$SHIFT_LEFTER_DETECT_SECRETS" --version
.venv/bin/python --version
git rev-parse HEAD
git status --porcelain --untracked-files=no
```

The combined-scanner runner refuses a tracked dirty worktree and refuses to overwrite an existing result set. It explicitly measures contextual model allows. Gateway and workstation enforcement are scanner-only, require strict policy, and do not invoke the model.

## 5. Generate and lock the test dataset

Use a new empty research root. Generation refuses to overwrite an existing raw set.

```bash
.venv/bin/python -m shift_lefter.standalone \
  generate --set independent-context-evaluation --count 3000 --seed 83017
```

Keep these files inside the protected raw root:

```text
$SHIFT_LEFTER_ROOT/raw/independent-context-evaluation/artifacts/
$SHIFT_LEFTER_ROOT/raw/independent-context-evaluation/ground_truth.json
$SHIFT_LEFTER_ROOT/raw/independent-context-evaluation/canary_index.json
$SHIFT_LEFTER_ROOT/raw/independent-context-evaluation/lock.json
```

Record SHA-256 hashes for `ground_truth.json`, `canary_index.json`, `gitleaks.toml`, `guard.py`, `scanner_test.py`, and `context_markers.json`. The runner records these again in each condition's `run-summary.json`.

## 6. Configure a local model

For a TLS-protected endpoint:

```bash
export SHIFT_LEFTER_MODEL_ENDPOINT="https://model.example.internal:8001/v1"
export SHIFT_LEFTER_MODEL_NAME="exact-model-identifier"
export SHIFT_LEFTER_ALLOWED_MODEL_HOSTS="model.example.internal"
export SHIFT_LEFTER_CA_BUNDLE="$HOME/.config/shift-lefter/internal-ca.pem"
```

Loopback HTTP is accepted. A non-loopback plaintext endpoint is rejected by default. A lab-only exception requires the host in both allowlists:

```bash
export SHIFT_LEFTER_MODEL_ENDPOINT="http://192.0.2.40:8000/v1"
export SHIFT_LEFTER_ALLOWED_MODEL_HOSTS="192.0.2.40"
export SHIFT_LEFTER_ALLOW_PLAINTEXT_MODEL_HOSTS="192.0.2.40"
```

Do not use that exception in production. Prefer authenticated TLS or a protected loopback tunnel.

For authentication, use a mode-0600 file:

```bash
export SHIFT_LEFTER_LOCAL_API_KEY_FILE="$HOME/.config/shift-lefter/model-key"
test "$(stat -c %a "$SHIFT_LEFTER_LOCAL_API_KEY_FILE")" = 600
```

The runner can alternatively read an existing environment variable by name without copying its value into an argument:

```bash
export SHIFT_LEFTER_LOCAL_API_KEY_ENV="VLLM_API_KEY"
```

Do not set both key mechanisms. Never print the key, include it in a URL, or store it in the repository.

## 7. Run one versioned model condition

Choose a unique slug containing the protocol version and model label:

```bash
RESULT_NAME="evaluation-v6-independent-context-local-model-a"

.venv/bin/python -m shift_lefter.standalone \
  scanner-test-run --source-set independent-context-evaluation --repeats 1 --workers 4 \
  --result-name "$RESULT_NAME"
.venv/bin/python -m shift_lefter.standalone \
  scanner-test-analyze --source-set independent-context-evaluation --result-name "$RESULT_NAME"
.venv/bin/python -m shift_lefter.standalone \
  scanner-test-verify --source-set independent-context-evaluation --result-name "$RESULT_NAME"
```

Do not proceed if verification exits nonzero, any scanner is unavailable, the endpoint is absent or outside the local allowlist, the result cardinality differs from ground truth, or a raw canary exists outside `$SHIFT_LEFTER_ROOT/raw`.

Repeat the three commands with a new result name and model configuration for every model. Do not edit code, test data, context markers, or scanner configuration between conditions.

## 8. Compare model conditions

After every condition has an `analysis.json` and passing `safety-verification.json`:

```bash
.venv/bin/python -m shift_lefter.scanner_test compare \
  --result-name evaluation-v6-independent-context-local-model-a \
  --result-name evaluation-v6-independent-context-local-model-b \
  --result-name evaluation-v6-independent-context-local-model-c \
  --output-name evaluation-v6-independent-context-model-comparison
```

The command fails if scanner findings differ, source hashes differ, a condition lacks passing safety evidence, or result names are duplicated. It writes:

```text
$SHIFT_LEFTER_ROOT/sanitized-results/evaluation-v6-independent-context-model-comparison.json
```

Report each model separately. Do not select the best model after inspection and present it as a preregistered result. This comparison is part of the same research program.

### 8.1 Run the single-scanner comparison

After the corrected combined-scanner conditions pass verification, repeat the test with one scanner at a time. Use a distinct result name and one `--scanner` argument for each scanner/model pair:

```bash
.venv/bin/python -m shift_lefter.standalone scanner-test-run \
  --source-set independent-context-evaluation --repeats 1 --workers 4 \
  --scanner gitleaks \
  --result-name evaluation-v5-gitleaks-local-model-a
```

Valid scanner names are `gitleaks`, `trufflehog`, and `detect-secrets`. Run all three scanners separately against all three model conditions, then analyze and verify every result. Use `scanner_test compare` only for the three model results that share the same selected scanner. Scanner outputs are expected to differ across scanners, so do not use the model-comparison command to compare Gitleaks with TruffleHog or detect-secrets. Report that cross-scanner summary separately.

After all nine conditions pass verification, create that descriptive summary by supplying all nine unique result names:

```bash
.venv/bin/python -m shift_lefter.scanner_test summarize \
  --result-name evaluation-v5-gitleaks-local-model-a \
  --result-name evaluation-v5-gitleaks-local-model-b \
  --result-name evaluation-v5-gitleaks-local-model-c \
  --result-name evaluation-v5-trufflehog-local-model-a \
  --result-name evaluation-v5-trufflehog-local-model-b \
  --result-name evaluation-v5-trufflehog-local-model-c \
  --result-name evaluation-v5-detect-secrets-local-model-a \
  --result-name evaluation-v5-detect-secrets-local-model-b \
  --result-name evaluation-v5-detect-secrets-local-model-c \
  --output-name evaluation-v5-single-scanner-summary
```

The summary requires passing safety evidence, exactly one selected scanner per condition, and identical execution-source hashes. It does not require identical findings across scanners.

## 9. Independent safety checks

The built-in verifier searches the repository worktree, the optional `SHIFT_LEFTER_STATE_ROOT` if configured, and every non-raw path under the research root. It deliberately excludes only `$SHIFT_LEFTER_ROOT/raw`.

Also inspect ephemeral storage, Git refs, model service logs, and network metadata independently. Search by loading canaries from `canary_index.json`; do not print them. Record only hit counts and sanitized paths. Packet or connection capture should retain addresses, ports, timestamps, and counters but no payloads.

If a process is interrupted, verify that `SHIFT_LEFTER_TRANSIENT_ROOT` contains no regular files. Treat any residual raw material as a safety failure, move it into the protected raw root, correct the cause, and rerun from a new result name.

## 10. Exercise the standalone gateway

Set `SHIFT_LEFTER_STANDALONE=1` and the same model/scanner variables in a bare gateway repository's environment. Its `pre-receive` hook runs:

```bash
export SHIFT_LEFTER_POLICY_MODE=strict
.venv/bin/python -m shift_lefter.gateway \
  --repo /srv/git/project.git \
  --upstream ssh://git@git.example.internal/group/project.git \
  --allow-host git.example.internal
```

Test at minimum:

1. a clean initial push is accepted and the same ref reaches the upstream;
2. a push containing a generated test secret is rejected and neither ref moves;
3. a test secret added in one commit and removed in a later commit is still rejected;
4. scanner and model outages reject the transaction;
5. a concurrent upstream ref change causes the per-ref lease to reject forwarding;
6. multi-ref forwarding is atomic;
7. audit storage failure before forwarding rejects without contacting upstream.

The reference container provides SSH for one mapped repository. It hashes the accepted developer public-key record into each audit event, while the upstream still sees the gateway service identity. It is not a complete Git-host replacement: smart HTTP, upstream pusher-identity preservation, push options, signed-push metadata, dynamic authorization, LFS payload scanning, load testing, and high availability remain production integration work. GitLab was the tested upstream. A GitHub deployment needs a separately validated GitHub App or repository-scoped write credential plus rules that prevent developers from bypassing the gateway.

## 11. Publishable artifacts

Never publish `$SHIFT_LEFTER_ROOT/raw`. After manual canary scanning, the following are designed to be publishable:

```text
$SHIFT_LEFTER_ROOT/sanitized-results/<condition>/records.jsonl
$SHIFT_LEFTER_ROOT/sanitized-results/<condition>/run-summary.json
$SHIFT_LEFTER_ROOT/sanitized-results/<condition>/analysis.json
$SHIFT_LEFTER_ROOT/sanitized-results/<condition>/safety-verification.json
$SHIFT_LEFTER_ROOT/sanitized-results/evaluation-v6-independent-context-model-comparison.json
```

Preserve exact hashes, scanner versions, endpoint labels, model identifiers, execution commit, test output, and all deviations. A model identifier is not a cryptographic weight hash; if exact weights cannot be hashed, state that limitation.
