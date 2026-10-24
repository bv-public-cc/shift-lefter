# Published Research Evidence

This directory contains reviewed, content-free result bundles. Raw synthetic test files and the canary index remain outside Git because they intentionally contain credential-shaped values.

Each published condition contains:

- `records.jsonl`: one sanitized decision record per condition/repeat;
- `run-summary.json`: versions, hashes, timing, and execution metadata;
- `analysis.json`: confusion-matrix counts, plain accuracy measures, model errors, and latency;
- `safety-verification.json`: canary-containment and endpoint-policy checks.

## Where to view the test data

- `test-data/ground_truth.json` lists every labeled test item, its category, file channel, filename, and SHA-256 digest without publishing the planted value.
- `test-data/lock.json` records the generator settings and hashes that lock the 3,000-item dataset.
- `expanded-evaluation-test-data.json` summarizes the positive and safe-item counts by category and channel.
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
