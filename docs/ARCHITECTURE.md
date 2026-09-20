# ProvenanceX Architecture Specification

## 1. System Overview

ProvenanceX is a cross-layer verification and trust-break localization framework designed to secure software supply chains against stealth injection, dependency confusion, compiler tampering, untracked inputs, unauthorized network egress, and attestation forgery.

Unlike conventional signature checkers or isolated SBOM analyzers that blindly trust builder self-attestations, ProvenanceX independently cross-examines declared claims against directly observed build execution behavior.

```
+-------------------------------------------------------------------------------+
|                             PROVENANCEX PLATFORM                              |
+-------------------------------------------------------------------------------+
|                                                                               |
|  [Declared Plane]                                        [Observed Plane]     |
|   - Git Repository Commit / Tree                          - Process Tree      |
|   - Manifests (requirements.txt / package.json)           - Filesystem Delta  |
|   - Lockfiles (poetry.lock / package-lock.json)           - Network Sockets   |
|   - CycloneDX / SPDX SBOM                                 - Environment FP    |
|   - in-toto / SLSA v1.0 Attestation                       - Rebuild Digest    |
|   - Digital Signatures (ECDSA/Ed25519)                                        |
|                       \                                /                      |
|                        v                              v                       |
|               +------------------------------------------------+              |
|               |       12-Layer Evidence Model & Merkle Log     |              |
|               +------------------------------------------------+              |
|                                       |                                       |
|                                       v                                       |
|               +------------------------------------------------+              |
|               |       Multi-Plane Consistency Correlator       |              |
|               +------------------------------------------------+              |
|                                       |                                       |
|                                       v                                       |
|               +------------------------------------------------+              |
|               |    Earliest Causal Trust-Break Localizer       |              |
|               +------------------------------------------------+              |
|                                       |                                       |
|                                       v                                       |
|               +------------------------------------------------+              |
|               |   Policy Decision Engine (TRUSTED/WARN/REJECT) |              |
|               +------------------------------------------------+              |
|                                       |                                       |
|               +-----------------------+------------------------+              |
|               |                                                |              |
|               v                                                v              |
|      [CLI / CI/CD Gate]                             [Web Explainability UI]   |
+-------------------------------------------------------------------------------+
```

---

## 2. 12-Layer Normalized Evidence Model

ProvenanceX formalizes software supply chain evidence into 12 chronological, causal planes:

| Layer Index | Plane | Category | Ground Truth Mechanism |
| :--- | :--- | :--- | :--- |
| `01` | **SOURCE** | Direct | Git commit SHA, tree hash, and working tree dirty/untracked detection. |
| `02` | **DEPENDENCIES** | Direct | AST parsing of `requirements.txt`, `package.json`, and `Dockerfile`. |
| `03` | **LOCKFILE** | Derived | Dependency pinning and SHA-256 package hash verification. |
| `04` | **ENVIRONMENT** | Direct | OS, CPU architecture, runtime toolchains, and redacted env variables. |
| `05` | **BUILD** | Direct | Monitored execution runner recording exit codes, duration, and arguments. |
| `06` | **PROCESS** | Direct | Process tree snapshotting, detecting suspicious shell pipes (`curl \| bash`). |
| `07` | **FILESYSTEM** | Direct | Pre/post snapshot delta: \(\text{Unexpected} = \text{Observed} \setminus \text{Expected}\). |
| `08` | **NETWORK** | Direct | Socket auditing against permitted package registry allowlists. |
| `09` | **ARTIFACT** | Derived | SHA-256 binary hashing and RFC 6962-compliant Merkle tree root. |
| `10` | **SBOM** | External | CycloneDX v1.5 / SPDX 2.3 parser and dependency cross-validator. |
| `11` | **PROVENANCE** | External | in-toto Statement v1 / SLSA v1.0 attestation subject cross-check. |
| `12` | **SIGNATURE** | External | Asymmetric cryptographic verification (ECDSA P-256, Ed25519, RSA). |

---

## 3. Multi-Plane Consistency & Contradiction Detection

Let \(L = \{L_1, L_2, \dots, L_{12}\}\) denote the set of evidence layers.
For any pair of related layers \((L_i, L_j)\), the consistency function \(C(L_i, L_j)\) evaluates whether claims made in \(L_i\) agree with claims in \(L_j\).

A **Contradiction** occurs when:
\[
C(L_i, L_j) = \text{False} \iff \text{Claim}(L_i) \neq \text{Claim}(L_j)
\]

Key Contradiction Pairs evaluated in ProvenanceX:
1. **Source vs Build**: Repository commit recorded vs source code tree at compile time.
2. **Dependencies vs Lockfile**: Manifest dependency request vs lockfile resolved package and registry.
3. **Dependencies vs SBOM**: Observed build dependencies vs components declared in CycloneDX/SPDX.
4. **Build vs Process**: Declared compiler binary vs processes observed in execution tree.
5. **Expected vs Filesystem**: Declared input files vs files read/mutated on disk.
6. **Network vs Allowlist**: Permitted package registries vs actual egress socket destinations.
7. **Artifact vs Provenance**: Computed artifact SHA-256 vs in-toto SLSA attestation subject digest.
8. **Artifact vs Signature**: Binary bytes vs cryptographic signature assertion.

---

## 4. Earliest Causal Trust-Break Localization

When inconsistencies or contradictions exist, traditional scanners report isolated warnings without causal context.
ProvenanceX employs a causal ordering algorithm based on the chronological sequence of software generation:

\[
\text{PipelineOrder} = [\text{SOURCE} \to \text{DEPS} \to \text{LOCKFILE} \to \text{ENV} \to \text{BUILD} \to \text{PROCESS} \to \text{FS} \to \text{NET} \to \text{ARTIFACT} \to \text{SBOM} \to \text{PROV} \to \text{SIG}]
\]

The **Earliest Trust-Break Layer** \(L^*\) is determined by:
\[
L^* = \min_{k} \{ L_k \in \text{PipelineOrder} \mid \text{Status}(L_k) \in \{\text{CONTRADICTED}, \text{MISMATCH}\} \}
\]

By isolating the earliest corrupted plane \(L^*\), ProvenanceX immediately pinpoints whether an issue originated at the developer's workstation, in dependency resolution, inside the build container, or post-compilation.

---

## 5. Bitwise Reproducibility & Divergence Diagnostics

ProvenanceX implements dual-run controlled rebuilds and isolates root causes of non-determinism:
- **Timestamp Variations**: Clamps dates to `SOURCE_DATE_EPOCH` and flags PE/archive header variances.
- **Build Path Leakage**: Scans binary strings for host file paths (`/home/runner/...` or `C:\Users\...`) and recommends compiler flags (`-trimpath` or `-fdebug-prefix-map`).
- **Archive Member Ordering**: Detects out-of-order zip or tar packaging.
- **Dependency Drift**: Compares historical build manifests.

---

## 6. Portable Air-Gapped Evidence Bundles

ProvenanceX packages artifacts, provenance, SBOMs, signatures, public keys, and append-only hash chains into portable `.tar.gz` archives with a root `bundle-manifest.json`.
The bundle can be verified 100% offline in air-gapped environments without database or network dependencies.
