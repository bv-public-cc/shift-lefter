# V7 Operational Secret-Detection Results

## Outcome

The privacy-preserving, batched local-model review reduced both types of scanner
error without weakening enforcement. The final single-model Spark Qwen policy
used a 0.85 secret-detection threshold and a separately gated 0.85
false-positive-suppression threshold.

| Holdout metric (4,800 artifacts) | Scanner baseline | Calibrated hybrid |
| --- | ---: | ---: |
| True positives | 1,492 | 1,596 |
| False negatives | 111 | 7 |
| False positives | 1,966 | 1,905 |
| True negatives | 1,231 | 1,292 |
| Precision | 0.4315 | 0.4559 |
| Recall | 0.9308 | 0.9956 |
| F1 | 0.5896 | 0.6254 |

Incremental holdout outcomes were 104 recovered false negatives, 61 suppressed
false positives, zero introduced false negatives, and zero introduced false
positives. Across all 6,000 artifacts, the corresponding counts were 125, 75,
zero, and zero.

All 125 private-key artifacts produced `non_overridable_hard_block`. The final
run recorded 473 model errors (374 on holdout); every error used the scanner
decision. Median model review time was 4.929816 seconds and p95 time was
6.163084 seconds. The complete live run took 3,442.066 seconds with 16 workers.

## Model comparison

| Model condition | Detection / suppression | Holdout value | Median / p95 model review time |
| --- | --- | --- | --- |
| Local Qwen | Live 0.90 / 0.90; calibration selects detection 0.85 | At calibrated 0.85, recovers 23 misses; no added false positives | 3.421s / 4.440s |
| Local Gemma | 0.90 / 0.90 | Suppresses 266 false positives; recovers 0 misses | 3.609s / 4.573s |
| Spark Qwen calibrated | 0.85 / 0.85 | Recovers 104 misses and suppresses 61 false positives | 4.930s / 6.163s |

The Qwen 0.85 figure was recalculated at that threshold using its saved,
sanitized model outputs. Gemma remains at 0.90 because lower detection
thresholds did not improve calibration recall. Spark Qwen was rerun live with
both frozen 0.85 thresholds and is the final recommended research condition.

## Threshold protocol

Thresholds were selected using only the 60 calibration repositories. The rule
maximized recovered calibration false negatives subject to zero introduced
false positives and zero introduced false negatives, preferring the highest
threshold on ties. The 240 holdout repositories were evaluated only after the
threshold was frozen.

For Spark Qwen, detection 0.85 recovered all 21 available calibration misses
with no added false positives. Suppression at 0.85 still required a fixed rule
to independently confirm a placeholder or known non-secret format. A 0.75 detection
threshold was rejected because it introduced 67 calibration false positives.

## Privacy and enforcement

- One feature packet groups all potential secrets found in a file. Their raw
  values, source text, file hashes, and source paths are not sent to the model.
- Published records contain decisions, bucketed features, hashes, and reason
  codes, never the values being checked or the original files.
- False-positive suppression requires both a model decision and independent
  confirmation by a fixed placeholder or known non-secret-format rule.
- Private keys cannot be overridden by the model.
- Malformed output, HTTP failures, and other model errors retain the scanner
  decision.
- Safety verification found zero raw-canary copies outside the approved raw
  research root, and every endpoint satisfied the local allowlist policy.

## Test set and reproducibility

The fixed `operational-holdout-v1` test set contains 6,000 files: 2,000
positives and 4,000 negatives across 300 simulated repositories. It includes 16
realistic credential families, 16 safe lookalike families, and 10 operational
layouts spanning source, configuration, infrastructure-as-code,
documentation, and tests. All 2,000 files known to contain a secret produce a
potential-secret record for model review. Repository grouping prevents files
from one simulated project from crossing calibration and holdout.

- Generator SHA-256: `b4c330d716c1eda3be52778d06de7c309224ac13893ff4b83607ac8cf8124752`
- Ground-truth manifest SHA-256: `b3cf4b9783999f750694e596cd635542ed6ebfcd1a29af7456cdf6d18b089310`
- Gitleaks configuration SHA-256: `8bfa17e8326cf3578e8e07909e34ba325583a14f84f732390f0d657b68d13251`
- Seed: `170031`
- Calibrated archived records SHA-256: `f1a16795e34cec2df91e56b5a92d64e3ca62e7fb0a8388067fbfdc808e2a0a78`

The committed ground truth is content-free. Raw generated artifacts and the
canary index intentionally remain outside Git.

## Evidence locations

- `sanitized-results/evaluation-v7-operational-local-qwen/`
- `sanitized-results/evaluation-v7-operational-local-gemma/`
- `sanitized-results/evaluation-v7-operational-spark-qwen-calibrated/`
- `sanitized-results/evaluation-v7-operational-model-comparison.json`
- `test-data/operational-holdout-v1/`

## Scope limitation

The result is clear for this fixed test set and shows repeatable behavior across
realistic file layouts and credential families. It does not prove that the
system will catch every type of secret, repository convention, unusual
encoding, or future model version. A later test using separately sourced real
repositories would give stronger evidence about real-world performance.
