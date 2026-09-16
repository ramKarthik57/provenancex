# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

ProvenanceX is a security research and supply-chain integrity verification framework. If you discover a security vulnerability or bypass within ProvenanceX itself, please report it responsibly.

### Disclosure Process

1. **Do not create a public GitHub issue** for undisclosed security vulnerabilities.
2. Submit vulnerability details directly to the project maintainers via email at:
   `ramkarthik5757@gmail.com`
3. Include detailed steps to reproduce, sample proof-of-concept evidence files or manifests, and observed vs expected behavior.
4. Maintainers will acknowledge receipt within 48 hours and coordinate remediation before public disclosure.

## Security Principles within ProvenanceX

ProvenanceX enforces defensive design internally:
- **Zero Host Trust**: Untrusted build artifacts and repositories must be isolated; untrusted commands must never execute directly in uncontrolled host environments.
- **Strict Input Validation & Path Traversal Guards**: Evidence bundles and archives are verified to prevent path traversal (`../`) and zip-slip attacks.
- **Mandatory Redaction**: Sensitive build credentials, tokens, and keys are scrubbed by the environment fingerprint and execution engines before persistence.
- **Deterministic Decisions**: Security verdicts (`TRUSTED`, `WARNING`, `REJECTED`) are rule-based, fully explainable, and never based on opaque or probabilistic scoring.
