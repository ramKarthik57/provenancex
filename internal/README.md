# ProvenanceX Internal Packages

* `artifact/`: SHA-256 hashing, MIME detection, and Merkle tree generation.
* `bundle/`: Portable evidence bundle generation and tarball extraction.
* `correlation/`: Cross-layer evidence correlation and contradiction detection.
* `decision/`: Deterministic decision engine (`TRUSTED`, `WARNING`, `REJECTED`).
* `delta/`: Build-to-build diff and comparison engine.
* `dependency/`: Multi-language dependency parsers (Python, Node.js, Docker).
* `environment/`: Build environment fingerprinting with secret redaction.
* `evidence/`: Normalized evidence model and lifecycle tracking.
* `execution/`: Command execution wrapper and telemetry recorder.
* `experiment/`: Benchmark scenario harness and evaluation runner.
* `filesystem/`: Controlled boundary filesystem change detector.
* `localization/`: Earliest trust-break localization algorithm.
* `network/`: Network destination recording and allowlist verification.
* `policy/`: YAML-driven policy parser and validator.
* `process/`: Windows and Linux process hierarchy capture.
* `provenance/`: SLSA v1.0 and in-toto provenance attestation validation.
* `repository/`: Git metadata, tree SHA, and uncommitted change inspector.
* `reproducibility/`: Rebuild comparison and divergence classifier.
* `sbom/`: CycloneDX and SPDX parser and generator.
* `signature/`: Cryptographic signature verification.
* `storage/`: Database persistence layer.
