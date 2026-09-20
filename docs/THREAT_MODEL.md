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

---

## 5. Threat Observability Taxonomy (Day 16 Observability Hardening)

To maintain scientific integrity, ProvenanceX explicitly categorizes software supply chain threats into three distinct observability tiers based on physical host boundaries and telemetry architecture:

### 5.1. Observable Threats (100% Deterministic Detection within Monitored Scope)
* **Source & Repository State**:
  * Uncommitted in-tree modifications, untracked malicious files, and unauthorized branch checkouts.
  * Forged git commit author/committer identities and unsigned or untrusted commit signatures.
  * Discrepancies between git tree hashes and declared build inputs.
* **Dependencies & Materials**:
  * Transitive lockfile tampering and semantic version drift.
  * Discrepancies between declared SBOM components, lockfiles, and resolved dependency graphs.
  * Unpinned version wildcards or unauthorized package registries.
* **Build Execution & Runtime (Elevated Mode B)**:
  * Runtime process creation and exit when running with Administrator Kernel ETW (`Microsoft-Windows-Kernel-Process`).
  * Process command line modifications and unapproved binary executions.
  * Cryptographic artifact digest contradictions against SLSA/in-toto subject hashes.
  * Signature tampering or expired/untrusted OIDC identity assertions in Rekor transparency logs.

### 5.2. Partially Observable Threats (Bounded Detection / Conditional Visibility)
* **Ephemeral Processes in User-Mode (Mode C)**:
  * Processes with lifespans between $10\text{ ms}$ and $100\text{ ms}$ are observed via high-frequency user-mode polling and Job Object accounting (**62.5% lifetime coverage**). Processes with lifespans $<10\text{ ms}$ evade user-mode observation due to Windows non-realtime scheduler quantization.
* **Transient Filesystem Activity (Mode B Event Streaming)**:
  * Rapid create-and-delete operations lasting $\ge 5\text{ ms}$ within the monitored workspace and temp directories are captured via asynchronous directory change event streaming (`ReadDirectoryChangesW`) (**71.4% event coverage**). However, final state diffing alone sees 0% recall, and user-mode events do not associate the file operation with originating process PIDs.
* **Allowed-Domain Subdomain DNS Tunneling**:
  * High-entropy, excessively long, or heavily nested subdomain tunneling under allowed suffixes (e.g., `*.pkg.go.dev`) is flagged as `SUSPICIOUS` via multi-feature heuristics (Shannon entropy, label length, hex ratio) and escalated to `REJECTED` when correlated with anomalous process execution. However, plain dictionary-word encoding without execution anomalies remains bounded.
* **In-Tree Generated Build Intermediates**:
  * Legitimate build-time generated mocks matching declared policy patterns (`DeclaredGeneratedPaths`) are accepted without triggering false alarms. Undeclared untracked files and modified tracked source files remain strictly rejected.

### 5.3. Unobservable Threats (Fundamentally Outside Current Architectural Primitives)
* **Kernel-Level Evasion without Administrator Privilege**:
  * Sub-10ms ephemeral child processes executed in unprivileged CI runner environments where Windows Administrator elevation (`SeCreateGlobalPrivilege`) is denied.
* **Arbitrary Unconfigured Volume Writes**:
  * Filesystem writes to unmonitored external drive letters (e.g., `E:\SharedBuildCache\`) or Windows core system paths (`C:\Windows\System32\`) without continuous kernel minifilter instrumentation (`FLTMGR.sys`) or OS container isolation.
* **Encrypted Network Tunnels (DoH / DoT)**:
  * Out-of-band DNS-over-HTTPS (DoH) or TLS tunneling directly opened by malware via custom sockets bypassing the Windows OS DNS client. Requires network egress firewall / network namespace isolation.
* **Reflective In-Memory Code Injection**:
  * Attacks that inject shellcode directly into existing legitimate compiler processes (e.g., process hollowing) without spawning new child processes.
