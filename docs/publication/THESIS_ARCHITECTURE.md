# ProvenanceX Doctoral / Master's Thesis Architecture

## Comprehensive 15-Chapter Blueprint

**Thesis Title**: Cross-Layer Software Supply-Chain Verification: Bridging the Attestation-Reality Divergence via Causal Trust Graphs and Epistemic Telemetry  
**Author**: Karthik Ram  
**Discipline**: Computer Science & Cybersecurity  

---

### Chapter 1: Introduction & Problem Statement
- **1.1 The Software Supply-Chain Crisis**: Growth of open-source ecosystems, complex transitive dependency trees, and modern CI/CD automation.
- **1.2 Real-World Case Studies**: Deconstruction of SolarWinds Sunburst, Codecov Bash Uploader, and the XZ Utils Backdoor (CVE-2024-3094).
- **1.3 The Attestation-Reality Divergence**: Why self-attestation is mathematically vulnerable to build-runner subversion ("the runner verifying itself").
- **1.4 Thesis Statement & Core Hypotheses**: Cross-layer multi-plane evidence correlation enables independent detection and causal root-cause localization of build-time supply chain attacks with bounded overhead and zero false alarms on policy-declared variations.
- **1.5 Principal Research Contributions**: 12-layer evidence plane model, topological root-cause localization, air-gapped standalone verifier, 19,777-trial empirical benchmark suite, and an 18-point limitations ledger.
- **1.6 Thesis Roadmap**: Detailed structural overview of subsequent chapters.

### Chapter 2: Background & Literature Review
- **2.1 Software Integrity Standards**: Supply-chain Levels for Software Artifacts (SLSA v1.0), in-toto layout semantics, TUF key hierarchies.
- **2.2 Software Bills of Materials (SBOMs)**: SPDX and CycloneDX specifications, NTIA minimum elements, dependency graph reconciliation challenges.
- **2.3 Cryptographic Signing Infrastructure**: Sigstore, Cosign, Fulcio OpenID Connect binding, Rekor transparency logs, and PKI limitations.
- **2.4 Kernel Tracing & Runtime Security**: Linux eBPF/Tetragon, Windows Event Tracing (ETW), system call interception, and user-space ptrace overheads.
- **2.5 Graph-Based Security Analytics**: Knowledge graphs in software security (GUAC, Macaron, CodeQL) and their limitations regarding dynamic runtime execution.

### Chapter 3: Threat Model & Formal Mathematical Definitions
- **3.1 System Environment & Trust Boundaries**: Delineation of developer workstation, remote source repository, CI/CD runner host, and consumer release gates.
- **3.2 Adversary Capabilities (Three-Tier Model)**:
  - *Tier 1 (In-Scope)*: Runner process tampering, in-flight file injection, dependency typosquatting, attestation forgery, and socket/DNS exfiltration.
  - *Tier 2 (Privilege/Scheduler Bounded)*: Sub-10ms ephemeral execution, sub-1ms transient file coalescing, dictionary DNS tunneling, and out-of-workspace writes.
  - *Tier 3 (TCB Assumptions / Out-of-Scope)*: Ring-0 kernel rootkits, hardware side-channels, and compromised root private keys.
- **3.3 Epistemic Classification of Evidence**: Formal definitions of Direct Observations ($\mathcal{E}_{\text{direct}}$), Derived Evidence ($\mathcal{E}_{\text{derived}}$), and External Assertions ($\mathcal{E}_{\text{external}}$).
- **3.4 Mathematical Definition of Contradiction**: Axiomatic basis for identifying trust breaks across epistemic classes.

### Chapter 4: The 12-Layer Multi-Plane Evidence Model
- **4.1 Architecture of the Evidence Planes**: Detailed specification of Planes $L_1$ through $L_{12}$ (Source, Dependencies, Lockfile, SBOM, Environment, Build Process, Process Hierarchy, Filesystem, Network, Artifact, Attestation, Signature).
- **4.2 Normalization Engine**: Abstract Syntax Tree (AST) representations, canonical JSON representations, and path normalization across OS variants.
- **4.3 Append-Only Cryptographic Merkle Chain**: RFC 6962 hash linking ($H_i = \text{SHA-256}(H_{i-1} \parallel L_i \parallel D_i)$) and non-repudiation guarantees.
- **4.4 Evidence Gap Taxonomy**: Formal definition and classification of Gaps ($G_1$ unobserved, $G_2$ unpinned, $G_3$ unsigned, $G_4$ out-of-boundary).

### Chapter 5: Cross-Layer Multi-Plane Correlation Semantics
- **5.1 Pairwise Correlation Invariants**: Mathematical formulation of correlation functions $\mathcal{C}(L_i, L_j) \in \{\text{True}, \text{False}\}$.
- **5.2 Process-Filesystem Causality Verification**: Proving whether file write operations map strictly to authorized compiler PID trees.
- **5.3 Dependency-Network Egress Isolation**: Correlating network sockets with declared package registries in lockfiles.
- **5.4 Source Cleanliness & In-Tree Generated Path Policies**: Distinguishing malicious working tree mutations from authorized build artifacts.
- **5.5 Temporal Order & Monotonic Consistency**: Causal timestamp checks preventing retroactively backdated commits and forward-dated build logs.

### Chapter 6: Trust-Graph 2.0 & Causal Trust-Break Localization
- **6.1 Graph Formulation**: Representing multi-layer evidence as a directed acyclic graph $G = (V, E)$.
- **6.2 Topological Sort via Kahn's Algorithm**: Establishing strict causal execution order $\Pi = [L_{\pi_1}, \dots, L_{\pi_{12}}]$.
- **6.3 The Earliest Broken Layer Theorem**: Formal proof that the minimum topologically sorted contradicted node $L^*$ corresponds to the root-cause plane.
- **6.4 Graph Compression & Large-Scale Scaling**: Algorithmic optimizations ensuring $O(V + E)$ linear traversal over 100,000 nodes without polynomial blowup.

### Chapter 7: Deterministic Policy Decision Engine
- **7.1 Policy Configuration Schema**: YAML-based declarative rules for repository cleanliness, network egress, process ancestry, and signature enforcement.
- **7.2 Categorical Verdict Semantics**: Elimination of non-deterministic numeric risk scoring; formal definitions of `TRUSTED`, `WARNING`, and `REJECTED`.
- **7.3 Machine-Readable Causal Explanation Framework**: Structuring JSON explanations containing contradicted evidence nodes, violating PIDs/paths, and remediation guidelines.

### Chapter 8: Implementation & Engineering Realization
- **8.1 ProvenanceX Core Subsystems**: Modular Go architecture, decoupling data capture from decision evaluation.
- **8.2 Windows Kernel ETW Telemetry Engine**: Implementation of session creation, event tracing, and non-admin high-frequency polling fallbacks.
- **8.3 ReadDirectoryChangesW Asynchronous Filesystem Streams**: Implementation of recursive directory watching and I/O buffer management.
- **8.4 Air-Gapped Standalone Verifier (`provenancex-verifier`)**: Zero-dependency Go binary for consumer deployment gates.
- **8.5 Cross-Platform Considerations**: Portability pathways for Linux eBPF and macOS Endpoint Security.

### Chapter 9: Empirical Evaluation Methodology
- **9.1 Testbed Configuration & Hardware Rigor**: AMD64 8-core/16-thread testbed, NVMe storage benchmarks, and Windows 11 Enterprise ETW subsystem.
- **9.2 The Closed Experimental Identity**: Enforcing $N = TP + FN + TN + FP$ across all campaigns.
- **9.3 Disentanglement of Populations**: Methodological separation of micro-campaigns, macro-evaluations, benign campaigns, and targeted stress hunts.
- **9.4 Data Leakage & Feature Disjointness Audit**: Verifying zero test-train overlap and zero hardcoded test signatures.

### Chapter 10: Adversarial Campaign & Baseline Discovery (Day 12)
- **10.1 Taxonomy of 25 Adversarial Attack Families**: Design of 5,000 attack trials and 1,250 benign trials.
- **10.2 Experimental Results & The 80.00% Baseline**: Demonstration that 21 families are detected with 100% recall, while 4 families expose empirical blind spots.
- **10.3 In-Depth Analysis of the Four Demonstrated Blind Spots**:
  - Unsigned commit author identity spoofing ($F_6$)
  - Sub-10ms ephemeral helper processes ($F_{13}$)
  - Transient in-flight filesystem create-and-delete races ($F_{14}$)
  - Ephemeral subdomain DNS tunneling ($F_{15}$)

### Chapter 11: Blind-Spot Remediation & Controlled Re-Evaluation (Day 13)
- **11.1 Remediation Engineering**: Integrating cryptographic commit verification, kernel ETW hooks, asynchronous filesystem streams, and Shannon entropy heuristics.
- **11.2 Micro-Campaign Evaluation ($N=4,000$)**: Integer trial validation proving pre-remediation (0.00% recall) vs post-remediation (87.50% recall).
- **11.3 Multi-Run Macro Attack Recall (98.75%)**: Full 25-family macro average synthesis.
- **11.4 The Out-of-Workspace Filesystem Boundary**: Isolating why unconfigured external directories cannot be observed without container sandbox isolation.

### Chapter 12: Generalization, Robustness & Scalability (Day 14)
- **12.1 Holdout Generalization on 11 Unseen Attacks ($N=5,500$)**: Verifying 100% recall on previously unmodeled mutation vectors.
- **12.2 Multi-Stage Composed Attacks ($N=750$)**: Validating 100% accuracy in isolating root-cause broken layers across multi-vector attacks.
- **12.3 Benign Environmental Variability ($N=1,250$)**: Proving zero false alarms across path relocations, dynamic timestamps, and authorized lockfile upgrades.
- **12.4 Scalability Stress Testing**: Empirical evaluation of artifact hashing (1GB), transitive dependency trees (500 packages), and graph nodes (100,000 nodes).

### Chapter 13: Independent Benchmark Audit & Claim Hardening (Days 15–17)
- **13.1 Independent Audit Methodology**: Adversarial verification of historical datasets, CSV immutability hashes, and code-result consistency.
- **13.2 The Research Claim Matrix (C1–C10)**: Formal status, evidence sources, and bounded claims for every core research hypothesis.
- **13.3 Disentangling Benign Populations & Targeted Stress Hunts (Day 16)**: Demonstrating 100% specificity on 1,000 benign builds and cataloging 81.25% recall on kernel boundary probes.
- **13.4 Offline Verifier Air-Gap Audit**: Verifying zero network socket calls and standalone deterministic execution.

### Chapter 14: Limitations Ledger, Boundaries & Open Problems
- **14.1 The 18-Point Limitations Ledger**: Exhaustive documentation of kernel privilege requirements, timer quantization, transient file coalescing, and DNS lexical limitations.
- **14.2 Hardware & OS Scheduler Realities**: Why user-mode software cannot overcome 15.6ms OS timer quantization without kernel drivers.
- **14.3 Open Scientific Challenges**: Enclave-assisted build runners, cross-compilation non-determinism, and semantic dependency analysis.

### Chapter 15: Conclusion & Future Directions
- **15.1 Summary of Research Impact**: How ProvenanceX transforms software supply-chain security from unverified self-attestation to causally grounded, cross-layer verification.
- **15.2 Transition to Level 5 Publication Readiness**: Open-source release, reproducible Docker/PowerShell test harnesses, and community engagement.
- **15.3 Concluding Remarks**: A call for honest, boundary-aware cybersecurity research.