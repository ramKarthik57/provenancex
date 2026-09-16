# ProvenanceX

> **A Cross-Layer Framework for Software Supply-Chain Integrity Verification**

[![CI](https://github.com/ramKarthik57/provenancex/actions/workflows/ci.yml/badge.svg)](https://github.com/ramKarthik57/provenancex/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.23%2B-00ADD8.svg)](https://go.dev/)
[![React](https://img.shields.io/badge/React-18%2F19-61DAFB.svg)](https://react.dev/)

---

## 1. Research Overview

Software supply chains rely on isolated trust assertions: Git commit signatures, package manager lockfiles, Software Bills of Materials (SBOMs), build provenance attestations (e.g. SLSA, in-toto), and artifact signing (e.g. Sigstore/Cosign). However, attackers frequently exploit the semantic gaps **between** these layers—such as dependency substitution, build script tampering, uncommitted file injections, unauthorized network egress during compilation, or deceptive provenance claims.

**ProvenanceX** investigates the core research question:

> *Given a software artifact, can we independently determine whether its production history is trustworthy, reproducible, policy-compliant, and internally consistent, and pinpoint exactly where trust breaks when contradictory evidence exists?*

ProvenanceX does not replace existing CI/CD runners, SBOM generators, or signature tools. Instead, it operates as an **independent security verification and cross-layer evidence-correlation layer** around build pipelines.

```
SOURCE ──► DEPENDENCIES ──► BUILD CONFIG ──► BUILD ENVIRONMENT ──► BUILD EXECUTION
                                                                         │
                                                PROCESS / FS / NETWORK EVIDENCE
                                                                         │
                                                                         ▼
SECURITY DECISION ◄── TRUST-BREAK LOCALIZATION ◄── CROSS-LAYER CORRELATION ◄── ARTIFACT + SBOM + PROVENANCE
```

---

## 2. Core Modules & Architecture

* **Repository Integrity**: Commits, parent hashes, source tree hashes, uncommitted inputs.
* **Dependency Intelligence**: Multi-ecosystem resolution (Python, Node.js, Docker), lockfile drift detection.
* **Build Environment Fingerprint**: OS, toolchains, container digests, with deterministic secret redaction.
* **Execution & Process Monitor**: Command tracking, PID hierarchy trees, execution duration, and exit codes.
* **Filesystem & Network Evidence**: Controlled evidence boundary tracking (`Unexpected = Observed - Expected`) and registry allowlists.
* **Artifact Integrity**: Cryptographic hashing (SHA-256), multi-artifact Merkle trees.
* **SBOM & Provenance Engines**: CycloneDX, SPDX, SLSA v1.0, and in-toto attestation validation.
* **Cryptographic Signatures**: Standard asymmetric verification (ECDSA, Ed25519, RSA).
* **Cross-Layer Evidence Correlator**: Multi-layer consistency validation yielding `VERIFIED`, `MATCH`, `MISMATCH`, `UNOBSERVED`, or `CONTRADICTED`.
* **Unknown Input Detector**: Flags stealthily injected files or uncommitted assets.
* **Trust-Break Localization**: Pinpoints the earliest causal failure layer in the software generation lifecycle.
* **Policy & Decision Engine**: Deterministic decisions (`TRUSTED`, `WARNING`, `REJECTED`) with transparent reasoning.
* **Reproducibility Engine**: Deterministic rebuild comparison and divergence categorization.
* **Offline Verifier**: Self-contained bundle verification (`manifest.json`) without trusting original build hosts.
* **Security Experiment Suite**: 10 controlled supply-chain attack scenarios measuring detection rates, latency, and overhead.
* **Interactive Dashboard**: Real-time visual graph, trust break breadcrumbs, build diffs, and experiment benchmarks.

---

## 3. Directory Layout

```text
provenancex/
├── cmd/
│   └── provenancex/        # Main CLI entrypoint
├── internal/
│   ├── artifact/           # Artifact hashing & Merkle tree
│   ├── bundle/             # Portable evidence bundle & manifest
│   ├── correlation/        # Cross-layer evidence correlation engine
│   ├── decision/           # Security decision engine (TRUSTED/WARNING/REJECTED)
│   ├── delta/              # Build delta & comparison engine
│   ├── dependency/         # Lockfile & dependency graph parsers
│   ├── environment/        # Environment fingerprint & secret redactor
│   ├── evidence/           # Normalized evidence models
│   ├── execution/          # Build execution & command runner
│   ├── experiment/         # Controlled security experiment framework
│   ├── filesystem/         # Filesystem boundary monitoring
│   ├── localization/       # Trust-break localization algorithm
│   ├── network/            # Network evidence & registry allowlists
│   ├── policy/             # YAML policy engine
│   ├── process/            # Process hierarchy tracking
│   ├── provenance/         # SLSA & in-toto provenance validators
│   ├── repository/         # Git repository integrity collectors
│   ├── reproducibility/    # Rebuild & divergence engine
│   ├── sbom/               # CycloneDX & SPDX parsers
│   ├── signature/          # Cryptographic signature verification
│   └── storage/            # Build history SQLite store
├── pkg/
│   ├── crypto/             # SHA-256, Merkle trees, and signature primitives
│   └── version/            # Version and build telemetry
├── web/                    # React + Vite + Tailwind + React Flow dashboard
├── schemas/                # JSON Schemas for evidence, bundles, and policies
├── policies/               # Default YAML policy configurations
├── experiments/            # Controlled supply-chain attack scenarios
├── tests/                  # Integration & security test suites
├── docs/                   # Academic papers, threat models, and research docs
├── scripts/                # Development & experiment automation scripts
├── docker/                 # Container definitions for sandbox builds
├── migrations/             # Database migrations
├── .github/workflows/      # Continuous integration workflows
├── go.mod                  # Go module definition
├── Makefile                # Build automation
├── docker-compose.yml      # Local development stack
├── LICENSE                 # Apache 2.0
└── SECURITY.md             # Responsible disclosure guidelines
```

---

## 4. Quickstart

### Prerequisites
* Go 1.23+
* Node.js 20+ & npm
* Git

### Building the CLI
```bash
# Build binary
go build -o bin/provenancex.exe ./cmd/provenancex

# Inspect version
./bin/provenancex.exe version

# Inspect help
./bin/provenancex.exe --help
```

### Running the Dashboard
```bash
cd web
npm install
npm run dev
```

---

## 5. Development Protocol (10-Day Plan)

* **Day 1**: Foundation, Toolchains, Directory Scaffolding, CLI Scaffold, Web Scaffold, CI. *(Current)*
* **Day 2**: Source & Artifact Integrity (Git metadata, SHA-256, Merkle trees, `inspect`, `hash`).
* **Day 3**: Dependency Intelligence & Environment Fingerprint (Python/Node/Docker graphs, secret redactor).
* **Day 4**: Build Execution, Process Hierarchy, Filesystem Boundary, Network Evidence.
* **Day 5**: SBOM (CycloneDX/SPDX), Provenance (SLSA/in-toto), Signature Verification.
* **Day 6**: Cross-Layer Correlation, Unknown Input Detector, Trust-Break Localization, Decision Engine.
* **Day 7**: Reproducibility Engine, Build Delta Engine, Offline Portable Evidence Verifier.
* **Day 8**: Controlled Security Experiment Suite (10 Attack Scenarios & Evaluation Metrics).
* **Day 9**: Interactive Research Dashboard (Evidence Graph, Trust Break Visualizer, Comparisons).
* **Day 10**: Research Validation, Security Hardening, Academic Documentation, Paper Artifacts.

---

## 6. License
Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
