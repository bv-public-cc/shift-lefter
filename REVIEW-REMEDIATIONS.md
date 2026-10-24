# Review Remediations and Experiment Reset

This file records the remediation of the findings reviewed on 2026-10-23. The
committed v4 and v5 result bundles are historical evidence. They used the
`expanded-evaluation` test set, whose safe and positive examples contained
words that revealed the expected label. Do not present those measurements as
proof that the system works on new data or combine them with results produced
after this change.

## Implemented changes

1. **Answer clues in test data:** the new `independent-context-evaluation` test
   uses the same four neutral context templates for both labels. Words from the
   line containing the potential secret are no longer copied into the model
   prompt. The
   manifest records `protocol_version=independent-context-v1` and
   `context_label_independent=true`.
2. **Enforcement/model ambiguity:** `scan_file`, the clean filter, hooks, and
   receive gateway now accept only strict scanner enforcement. They do not
   invoke the model. Setting another enforcement policy fails closed. The
   contextual classifier remains isolated in `scanner_test.py` for research.
   Confirmed false positives use a content-addressed, expiring exception file;
   private-key findings remain non-overridable.
3. **Intermediate commits:** pre-push now enumerates and scans every new blob,
   commit message, and annotated tag reachable in the outgoing revision range,
   including content removed before the final tip.
4. **NUL-containing files:** the clean filter no longer passes these files
   through. All bytes are materialized for the scanners; an unsupported-file
   scanner error fails closed.
5. **Pusher attribution:** the reference SSH gateway enables OpenSSH
   `ExposeAuthInfo`, derives a content-free SHA-256 identifier from the accepted
   public-key record, requires it on receive, and includes it in every audit
   event. Raw key records and fingerprints are not logged.

## False-positive exception schema

Store this file outside every Git worktree, make it readable by the enforcement
service, and remove group/world write permission. Set its path in
`SHIFT_LEFTER_FALSE_POSITIVE_ALLOWLIST`.

```json
{
  "schema_version": 1,
  "entries": [
    {
      "artifact_sha256": "<64 lowercase hexadecimal characters>",
      "finding_keys": ["gitleaks:rule-id"],
      "expires_utc": "2026-12-31T23:59:59Z",
      "ticket": "SEC-1234"
    }
  ]
}
```

Use the exact sorted `scanner:rule_id` values returned by `scan-file`. Approval
is invalidated by any content or finding-set change. The exception file itself
is the durable approval record and should follow the organization's security
change process.

## Required rerun

Use a new, empty research root or remove only the unneeded external raw/result
directories after preserving any evidence required by the research record.
Do not overwrite the committed v4/v5 archive.

```bash
export SHIFT_LEFTER_ROOT="$HOME/.local/share/shift-lefter-rerun"

.venv/bin/python -m shift_lefter.standalone generate \
  --set independent-context-evaluation --count 3000 --seed 83017

.venv/bin/python -m shift_lefter.standalone scanner-test-run \
  --source-set independent-context-evaluation --repeats 1 --workers 4 \
  --result-name evaluation-v6-independent-context-local-model-a
.venv/bin/python -m shift_lefter.standalone scanner-test-analyze \
  --source-set independent-context-evaluation \
  --result-name evaluation-v6-independent-context-local-model-a
.venv/bin/python -m shift_lefter.standalone scanner-test-verify \
  --source-set independent-context-evaluation \
  --result-name evaluation-v6-independent-context-local-model-a
```

Repeat under unique result names for every frozen model condition. Commit the
code and run from a clean worktree before `scanner-test-run`; the runner refuses
a Git worktree with uncommitted tracked changes. This generated test removes
context words that reveal the expected label, but it is not a separately
created set of real repositories. Any claim about real-world performance still
requires a separately sourced and labeled dataset.
