# Third-Party Scanner Notices

Shift Lefter invokes these scanners as separate command-line programs. The reference container downloads the pinned upstream release archives and includes the detect-secrets Python package.

| Component | Pinned version | License | Upstream |
|---|---:|---|---|
| Gitleaks | 8.30.1 | MIT | https://github.com/gitleaks/gitleaks |
| TruffleHog | 3.99.1 | GNU Affero General Public License v3.0 | https://github.com/trufflesecurity/trufflehog |
| detect-secrets | 1.5.0 | Apache License 2.0 | https://github.com/Yelp/detect-secrets |

The adjacent files reproduce the license text from each pinned upstream tag. Those licenses govern their respective third-party components. They do not replace the license for original Shift Lefter code. The reference container copies this directory to `/usr/share/licenses/shift-lefter/scanners`.

Source snapshots used for the license copies:

- https://github.com/gitleaks/gitleaks/blob/v8.30.1/LICENSE
- https://github.com/trufflesecurity/trufflehog/blob/v3.99.1/LICENSE
- https://github.com/Yelp/detect-secrets/blob/v1.5.0/LICENSE
