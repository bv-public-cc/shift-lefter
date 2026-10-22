# Security Policy

Use only synthetic or revoked credentials in tests. Never attach a live secret to an issue, merge request, log, or result bundle.

Report suspected vulnerabilities privately to the project owner through GitLab. Include reproduction steps without credential values. If a real credential may have crossed the gateway, revoke it first and follow the affected system's incident-response process.

The reference gateway is research software. Its documented exclusions—including Git LFS payloads, smart HTTP, web/API commits, imports, mirrors, authorization mapping, high availability, and SHA-256 Git repositories—must be resolved before production use.
