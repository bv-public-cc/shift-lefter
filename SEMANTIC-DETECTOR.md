# Batched Local-Model Context Review

This experiment tests whether a local model can use general characteristics
about potential secrets to improve both sides of secret detection:

- recover potential secrets missed by all configured scanners; and
- suppress scanner false positives only when a fixed safety rule and a
  very-high-confidence model decision agree.

It is not enabled in the Git enforcement path. Production hooks and the
gateway remain strict scanner-only controls while this condition is evaluated.

## Privacy boundary

`shift_lefter.semantic.candidate_features` examines each potential secret only
inside the local scanning process. The model receives general characteristics:
length and entropy buckets, character class, known-format category,
placeholder match, non-secret identifier category, assignment category, file
category, and scanner details. It contains no source text, potential secret
values, reversible fragments, or hashes of those values.

One model request covers all potential secrets in a file. The API must return a
JSON object that follows the required format and classifies every record ID
using only the approved reason codes.

## Asymmetric decisions

A scanner miss becomes an additional detection only when the model returns
`secret` with confidence at least `0.90` and risk evidence. A scanner finding
is suppressed only when every scanner finding maps to a potential secret, each one is
classified `false_positive` with confidence at least `0.90`, and a fixed local
rule independently finds a placeholder or recognized
non-secret identifier. Private-key findings are never suppressible.
Both thresholds are explicit CLI options and are recorded in the run summary.

An invalid or unavailable model response falls back to the original scanner
decision. Thus the experimental classifier cannot turn a scanner block into an
allow through error, timeout, malformed JSON, or unsupported evidence.

## V7 execution

Generate the repository-grouped test set outside Git, then use a
clean committed worktree:

```sh
python -m shift_lefter.operational_corpus --count 6000 --seed 170031

python -m shift_lefter.standalone scanner-test-run \
  --source-set operational-holdout-v1 \
  --result-name evaluation-v7-operational-local-qwen \
  --repeats 1 --workers 4 --semantic-batch

python -m shift_lefter.standalone scanner-test-analyze \
  --source-set operational-holdout-v1 \
  --result-name evaluation-v7-operational-local-qwen

python -m shift_lefter.standalone scanner-test-verify \
  --source-set operational-holdout-v1 \
  --result-name evaluation-v7-operational-local-qwen
```

Repeat with distinct result names for each model, then use
`shift_lefter.scanner_test compare` to confirm identical scanner inputs and
source hashes.

## Required interpretation

The analysis reports recovered false negatives, introduced false negatives,
suppressed false positives, and introduced false positives separately. A
precision increase is not considered a success if recall falls.

The `operational-holdout-v1` test set contains 6,000 files distributed across
300 simulated repositories. It includes sixteen synthetic but structurally
realistic secret families, sixteen non-secret lookalike families, ten common
repository layouts, and a repository-grouped 20% calibration/80% holdout split.
Only the holdout partition supports the final effectiveness result. Raw
artifacts remain outside Git.

Even this operational emulation cannot prove performance on every real
repository. Before suppression can affect enforcement, test it on a separately
sourced and labeled dataset or run it in production monitoring-only mode. In
either case, it must introduce no false negatives.
