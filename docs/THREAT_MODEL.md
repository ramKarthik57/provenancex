# ProvenanceX Threat Model & Security Analysis

## 1. Scope & System Assets

ProvenanceX safeguards software supply chains against adversarial attacks spanning source inception to binary distribution.

### Critical Assets:
1. **Source Code & Git State**: Integrity of commits, tags, and tree objects.
2. **Build Toolchain & Environment**: Compilers, runtimes, environment variables, and build scripts.
3. **Third-Party Dependencies**: Direct and transitive packages, registries, and lockfiles.
4. **Build Execution Boundary**: Filesystem workspace, processes, and network egress sockets.
5. **Output Artifacts**: Compiled binaries, libraries, archives, and container images.
6. **Provenance & Attestations**: in-toto statements, SLSA v1.0 metadata, and SBOMs.
7. **Cryptographic Signatures**: Private signing keys and public key identity assertions.

---

## 2. Threat Actor Profiles

1. **Malicious Insider / Compromised Developer**: Has commit access; attempts to sneak backdoors into source or dependencies.
2. **Upstream Dependency Adversary**: Compromises open-source packages (typosquatting, account takeover, malicious version release).
3. **Compromised Build Runner / CI Infrastructure**: Has control over the build container or host; can inject code during compilation (SolarWinds style).
4. **Man-in-the-Middle (MitM) / Network Attacker**: Attempts to poison package downloads or redirect egress connections.
5. **Post-Build Tamperer**: Modifies binary artifacts after build execution but before distribution.

---

## 3. Threat Classification (STRIDE Mapping)

| Threat | Attack Scenario | ProvenanceX Detection Layer | Mitigation / Defense |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Forged commit identity or fabricated SLSA builder ID. | `SOURCE`, `PROVENANCE` | Git GPG commit verification & SLSA builder identity validation. |
| **Tampering** | In-flight source modification or binary patch after compile. | `SOURCE`, `ARTIFACT` | Working tree dirty check, pre/post file hashing & Merkle root. |
| **Repudiation** | Builder denies executing build with malicious flags. | `BUILD`, `PROCESS` | Monitored execution runner & RFC 6962 append-only hash log. |
| **Information Disclosure** | Secret leakage in build args or environment variables. | `ENVIRONMENT`, `BUILD` | Deterministic secret scrubber replacing tokens with `[REDACTED]`. |
| **Denial of Service** | Corrupted lockfiles or missing dependency resolution. | `LOCKFILE`, `DEPENDENCIES` | AST dependency parser & unpinned version drift auditor. |
| **Elevation of Privilege** | Build script spawning unauthorized shell exfiltration. | `PROCESS`, `NETWORK` | Process hierarchy monitor & registry egress allowlist enforcement. |

---

## 4. Trust Boundaries & Security Invariants

### Invariant 1: Multi-Plane Verification Principle
> *No claim from an attestation plane (SBOM, in-toto, SLSA) is accepted as true unless corroborated by directly observed execution telemetry or cryptographic proof.*

### Invariant 2: Append-Only Audit Integrity
> *Every evidence item generated during build monitoring is cryptographically chained to its predecessor using SHA-256 hash pointers (\(H_n = \text{SHA256}(H_{n-1} \parallel \text{Item}_n)\)). Retroactive modification breaks the chain.*

### Invariant 3: Air-Gapped Verifiability
> *All cryptographic assertions and artifact digests packaged inside a portable bundle must be verifiable completely offline without network or database dependencies.*
