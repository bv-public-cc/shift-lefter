# Execution Snapshot and Standalone Extraction

The v3 3,000-item execution is retained as defect-discovery evidence. It exposed scanner misses, unsafe contextual downgrades, and a missing Spark endpoint credential. The corrected v4 execution used the same locked test data after those defects were addressed. Each content-free result bundle hashes the study runner, scanner policy, marker allowlist, scanner configuration, test-data manifests, and sanitized records. The hashes prove cross-condition identity and allow direct checking of published manifests, rules, and records. Execution-file hashes describe the private execution snapshot; they are not presented as proof that this later extraction is byte-identical.

This repository is a standalone copy prepared after the experiment ran. The
copy removed unused integration imports, moved the package from its former
nested name to the top-level `shift_lefter` name, and sends both older and
redacted prompts through the included local-model client with an approved-host
list. Both combined-scanner experiments selected that client before checking
any file, so this package-name change does not alter the scanner, prompt, model
response checks, or rule-based decision path recorded for either run. We added
public-safety checks, dependency-license files, release documentation, and a
corrected convenience installer that fetches the same pinned Gitleaks version
after the experiment.

For that reason, source-file hashes in an archived v4 run summary attest to the execution snapshot and will not all equal the hashes of this later release. The v5 single-scanner study was different: all nine conditions ran from the exact standalone release after its public-safety and unit-test checks passed. Its published summaries state whether the execution source matches the release, while all studies retain their own source-file and result hashes. Reviewers can therefore distinguish archived v4 equivalence from direct v5 release execution without relying on an inaccessible private commit identifier.

The extracted repository was tested independently with its unit suite and its real-scanner/local-model gateway integration test before publication.
