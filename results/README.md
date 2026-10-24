# Published Research Evidence

This directory contains reviewed, content-free result bundles. Raw synthetic test files and the canary index remain outside Git because they intentionally contain credential-shaped values.

Each published condition contains:

- `records.jsonl`: one sanitized decision record per condition/repeat;
- `run-summary.json`: versions, hashes, timing, and execution metadata;
- `analysis.json`: confusion-matrix counts, plain accuracy measures, model errors, and latency;
- `safety-verification.json`: canary-containment and endpoint-policy checks.
- `threshold-analysis.json` (v7): calibration-only threshold selection and
  untouched holdout outcomes derived from sanitized classifier outputs.

## Where to view the test data

- `test-data/ground_truth.json` lists every labeled test item, its category, file channel, filename, and SHA-256 digest without publishing the planted value.
- `test-data/lock.json` records the generator settings and hashes that lock the 3,000-item dataset.
- `test-data/independent-context-evaluation/` contains the v6 ground-truth manifest and lock file without raw candidate values.
- `expanded-evaluation-test-data.json` summarizes the positive and safe-item counts by category and channel.
- `independent-context-evaluation-test-data.json` summarizes the corrected v6 protocol and dataset counts.
- `shift_lefter/experiment.py` contains the deterministic generator and templates used to reproduce the instantiated files in a protected research directory.
- `sanitized-results/` contains the publishable decision records and analyses after execution.

The instantiated positive files are deliberately absent from Git because even nonfunctional credential-shaped examples can be copied into logs, demonstrations, or detection systems. Regeneration produces those files locally from the published seed and generator; it does not make them publication material.

The committed generator, fixed seed, ground-truth manifest, and test-data lock let a reviewer regenerate and verify the test dataset without storing the instantiated candidates in source control. Internal endpoint addresses are replaced by stable labels in the public copy. The research archive retains the original content-free records and hashes.

The 300-item v2 experiment is a pilot. The 3,000-item v3 execution is retained as defect-discovery evidence, and the v4 experiment evaluates the corrections against the same locked test data. Both are part of the research. The chronology and reuse of inspected data are stated so readers do not mistake v4 for a new independent holdout test. The v5 single-scanner experiment isolates the contribution of Gitleaks, TruffleHog, and detect-secrets across the same three model conditions.

## Post-review status

The committed v4/v5 bundles also use context vocabulary correlated with the
ground-truth class. They demonstrate behavior on that synthetic generator but
must not be cited as evidence of model generalization. The corrected rerun uses
the separately named `independent-context-evaluation` protocol and v6 result
names. See `REVIEW-REMEDIATIONS.md`. Existing result files are intentionally
unchanged so the historical record and its hashes remain intact.

## V6 independent-context results

The corrected v6 publication contains 3,000 artifacts (1,000 positive and
2,000 negative), with 6,000 sanitized records for each model condition. The
context template is selected independently of the ground-truth label. All
three safety-verification reports pass, use redacted endpoint labels, and
report zero raw-canary hits outside the approved research root.

The scanner baseline achieved precision `0.403361`, recall `0.96`, and F1
`0.568047`. Neither Gemma nor Spark Qwen changed the effective metrics or
reduced false positives. Local Qwen allowed one additional positive, reducing
recall to `0.959` and F1 to `0.567624`, with no false-positive reduction.
Gemma produced 1,224 semantically invalid classifier responses; those were
recorded as fail-closed reviews.

The published bundles are:

- `sanitized-results/evaluation-v6-independent-context-local-qwen/`;
- `sanitized-results/evaluation-v6-independent-context-local-gemma/`;
- `sanitized-results/evaluation-v6-independent-context-spark-qwen/`;
- `sanitized-results/evaluation-v6-independent-context-model-comparison.json`.

## Operational holdout v7

The v7 evaluation replaces the earlier shallow synthetic protocol with 6,000
artifacts grouped into 300 simulated repositories. Sixty repositories (1,200
artifacts) are reserved for calibration and 240 repositories (4,800 artifacts)
form an untouched holdout. The corpus covers 16 credential families, 16 safe
lookalike families, 10 source/configuration/infrastructure/documentation/test
layouts, and both direct and split runtime assignments. Context is generated
independently of the label.

The final calibrated Spark Qwen condition uses separate 0.85 detection and
suppression thresholds. On holdout it recovered 104 scanner false negatives,
suppressed 61 false positives, and introduced zero false negatives and zero
false positives. Across the full 6,000 artifacts it recovered 125 and
suppressed 75. Private-key findings remained non-overridable, and 473 model
errors fell back to scanner decisions. Median semantic latency was 4.93 seconds
and p95 latency was 6.16 seconds.

See `V7-OPERATIONAL-RESULTS.md` for the complete per-model results, method,
hashes, and limitations. The v7 evidence is conclusive for this locked corpus;
it is credible operational emulation, not a claim that a synthetic corpus
establishes universal performance on every real repository.
