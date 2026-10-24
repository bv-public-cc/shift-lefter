# Operational holdout v1

This directory publishes the content-free manifest and lock for the v7
operational evaluation. Raw generated artifacts and `canary_index.json` remain
outside Git because they contain credential-shaped values.

- 6,000 artifacts in 300 simulated repositories
- 2,000 positive and 4,000 negative artifacts
- 60 calibration repositories (1,200 artifacts)
- 240 untouched holdout repositories (4,800 artifacts)
- repository-grouped split with label-independent context
- 16 credential families, 16 safe lookalike families, and 10 layouts
- deterministic seed `170031`

`ground_truth.json` contains artifact IDs, labels, partitions, categories,
channels, filenames, repository IDs, and SHA-256 digests only. `lock.json`
binds the generator, manifest, scanner configuration, and seed. `summary.json`
contains the top-level counts without the per-artifact records.
