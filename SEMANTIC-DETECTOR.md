# Batched Semantic Detector

The batched semantic detector is an experimental, local-model condition that
measures whether derived features can improve both sides of secret detection:

- recover credential-like candidates missed by all configured scanners; and
- suppress scanner false positives only when deterministic safe evidence and
  a very-high-confidence model classification agree.

It is not enabled in the Git enforcement path. Production hooks and the
gateway remain strict scanner-only controls while this condition is evaluated.

## Privacy boundary

`shift_lefter.semantic.candidate_features` examines candidate material only in
the local scanning process. The model packet contains categorical derivatives:
length and entropy buckets, character class, known-format category,
placeholder match, non-secret identifier category, assignment category, file
category, and scanner metadata. It contains neither source text nor candidate
values, reversible fragments, or candidate hashes.

One model request covers all candidates in a file. API-level JSON-object mode
is requested, and the response must classify every candidate ID with an exact
schema and allowlisted evidence codes.

## Asymmetric decisions

A scanner miss becomes a semantic detection only when the model returns
`secret` with confidence at least `0.95` and risk evidence. A scanner finding
is suppressed only when all findings map to candidates, each candidate is
classified `false_positive` with confidence at least `0.99`, and local
deterministic extraction independently finds a placeholder or recognized
non-secret identifier. Private-key findings are never suppressible.

An invalid or unavailable model response falls back to the original scanner
decision. Thus the experimental classifier cannot turn a scanner block into an
allow through error, timeout, malformed JSON, or unsupported evidence.

## V7 execution

Use a clean committed worktree and the same locked
`independent-context-evaluation` source set as v6:

```sh
python -m shift_lefter.standalone scanner-test-run \
  --source-set independent-context-evaluation \
  --result-name evaluation-v7-semantic-local-qwen \
  --repeats 1 --workers 4 --semantic-batch

python -m shift_lefter.standalone scanner-test-analyze \
  --source-set independent-context-evaluation \
  --result-name evaluation-v7-semantic-local-qwen

python -m shift_lefter.standalone scanner-test-verify \
  --source-set independent-context-evaluation \
  --result-name evaluation-v7-semantic-local-qwen
```

Repeat with distinct result names for each model, then use
`shift_lefter.scanner_test compare` to confirm identical scanner inputs and
source hashes.

## Required interpretation

The analysis reports recovered false negatives, introduced false negatives,
suppressed false positives, and introduced false positives separately. A
precision increase is not considered a success if recall falls. Synthetic v7
results are regression evidence; enabling suppression in enforcement still
requires an independently sourced, repository-separated holdout with no
introduced false negatives.
