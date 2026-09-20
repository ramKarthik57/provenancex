# ProvenanceX Viva Voce Final Defense Presentation Deck (18 Slides)

**Candidate**: Karthik Ram  
**Title**: ProvenanceX: A Cross-Layer Framework for Software Supply-Chain Integrity Verification  
**Subtitle**: Bridging the Attestation-Reality Divergence via Causal Trust Graphs and Epistemic Telemetry  
**Target Duration**: 10–15 Minutes  

---

## Slide 1: Title & Research Context

### Slide Content
- **Title**: PROVENANCEX
- **Subtitle**: A Cross-Layer Framework for Software Supply-Chain Integrity Verification
- **Candidate**: Karthik Ram
- **Research Scope**: Software Supply-Chain Security, Causal Evidence Correlation, Deterministic Policy Gates
- **Repository Baseline**: Branch `research-validation` (Commit: `48dbcfa`)

### Speaker Notes
- **Speaker Objective**: Formally introduce the dissertation topic and state the core research scope clearly.
- **30–60 Second Explanation**: "Good morning, members of the examination committee. Modern software engineering relies heavily on third-party dependencies, automated CI/CD runners, and distributed release infrastructure. ProvenanceX investigates how to verify the integrity of this pipeline independently. Rather than trusting build runners to report their own behavior, ProvenanceX correlates declared metadata against direct host telemetry, localizing where trust breaks."
- **Likely Examiner Interruption**: *"Are you claiming to build an intrusion detection system for build servers?"*
- **Answer**: "No. ProvenanceX is not a general host IDS or antivirus engine. It is an independent cross-layer consistency verification framework that checks whether the physical reality of a build execution matches the declared metadata and release policy."

---

## Slide 2: Problem Statement — The Attestation-Reality Divergence

### Slide Content
- **The Core Problem**: Build artifacts can be validly signed while their production history contains contradictions.
- **Current Trust Paradigm**:
  - Developers sign artifacts using Cosign/Sigstore.
  - Runners emit SLSA Provenance v1.0 attestations and CycloneDX/SPDX SBOMs.
- **The Vulnerability**:
  - If an adversary compromises the build runner (e.g., SolarWinds Sunburst), the compromised runner compiles backdoored binaries and simultaneously outputs syntactically valid attestations and authentic signatures.
  - Downstream consumers verify a cryptographically valid, signed trojan.

### Speaker Notes
- **Speaker Objective**: Expose the fundamental architectural flaw of self-attestation.
- **30–60 Second Explanation**: "The core problem is what we define as the Attestation-Reality Divergence. Today's supply-chain standards standardize metadata syntax, but they rely on self-attestation. If a runner is subverted, it has the cryptographic authority to sign a compromised binary. Downstream release gates verify the signature and accept the trojan because the attestation matches the artifact, even though build execution violated integrity."
- **Likely Examiner Interruption**: *"Doesn't SLSA Level 3 or 4 prevent this by requiring isolated build environments?"*
- **Answer**: "SLSA isolation reduces external tampering during execution, but it still relies on the runner to generate the provenance statement. If an adversary introduces an in-flight compiler modification or an unapproved helper daemon, the runner's generated attestation does not self-report the attack."

---

## Slide 3: Motivation & Supply-Chain Attack Surface

### Slide Content
- **Software Pipeline Stages Subject to Divergence**:
  - **Source**: Unsigned commit spoofing, uncommitted source modifications.
  - **Dependencies**: Lockfile hash tampering, typosquatted transitive packages.
  - **Build Environment**: Unpinned compiler versions, poisoned environment variables.
  - **Execution**: Unauthorized helper daemons, hijacked compiler flags.
  - **Artifact**: Post-compilation binary replacement prior to packaging.
  - **Provenance**: Forged or replayed attestation statements.
- **Historical Parallels**: SolarWinds (in-flight source tampering), Codecov (credential exfiltration via socket), XZ Utils (macro injection).

### Speaker Notes
- **Speaker Objective**: Map out the multi-stage attack surface where divergence occurs.
- **30–60 Second Explanation**: "Each stage of the build pipeline can diverge from declared intent. In SolarWinds, source code was altered while the compiler was running. In Codecov, CI credentials were stolen via transient egress sockets. In XZ Utils, malicious M4 macros modified the build script. A point-in-time check at the end of the pipeline cannot detect in-flight execution anomalies unless execution telemetry is captured and correlated."
- **Likely Examiner Interruption**: *"Aren't these three completely different kinds of attacks?"*
- **Answer**: "They span different layers, but they share one invariant: they create observable contradictions between what was declared in repository metadata and what physically occurred on the host. ProvenanceX bridges these disparate layers into a unified evidence graph."

---

## Slide 4: Research Gap

### Slide Content
- **State-of-the-Art Approaches**:
  - *Metadata Standards (SLSA, in-toto)*: Define schema and layout; accept runner self-reporting.
  - *Signatures (Sigstore, Cosign)*: Guarantee signer non-repudiation; blind to payload legitimacy.
  - *SBOM Analyzers (Scorecard, GUAC)*: Inspect component inventories; operate post-facto on static metadata.
  - *Host Monitors (ptrace/wrappers)*: Capture isolated command runs; lack unified multi-layer DAG reasoning.
- **Identified Gap**:
  - Existing mechanisms provide valuable evidence, but an independent cross-layer consistency layer can correlate that evidence and localize contradictions across layers.

### Speaker Notes
- **Speaker Objective**: Position ProvenanceX with respect to existing literature without disparaging existing tools.
- **30–60 Second Explanation**: "Existing mechanisms provide essential security primitives: Sigstore gives non-repudiation, in-toto gives layout semantics, and GUAC aggregates enterprise knowledge. However, each operates in isolation. There is no independent framework that correlates host runtime telemetry directly against declared lockfiles and SBOMs to localize causal contradictions."
- **Likely Examiner Interruption**: *"Are you claiming existing systems universally lack correlation?"*
- **Answer**: "No. Many tools correlate specific pairs of artifacts, such as matching an SBOM to CVE databases. However, independent cross-layer correlation unifying direct kernel execution telemetry with declared cryptographic provenance in an acyclic graph is missing."

---

## Slide 5: Research Question

### Slide Content
> **Central Research Question**:  
> *Can an independent verification layer correlate heterogeneous software supply-chain evidence to identify contradictions and localize the earliest observable trust break while explicitly accounting for observation boundaries?*

- **Decomposition of Hypotheses**:
  - **H1 (Cross-Layer Detection)**: Pairwise correlation detects multi-layer attacks that evade single-layer checks.
  - **H2 (Causal Localization)**: A topological DAG isolates the earliest broken layer rather than downstream symptoms.
  - **H3 (Epistemic Bounds)**: Characterizing privilege tiers and scheduler limits provides defensible, bounded guarantees.

### Speaker Notes
- **Speaker Objective**: Ground the defense in a formal, scientifically falsifiable research question.
- **30–60 Second Explanation**: "Our thesis centers on this question: Can an independent verification layer correlate heterogeneous evidence to detect contradictions and localize the earliest observable trust break, while explicitly accounting for observation boundaries? We evaluate this through three hypotheses: detection capability, causal localization, and boundary characterization."
- **Likely Examiner Interruption**: *"Why emphasize observation boundaries so heavily?"*
- **Answer**: "Because in cybersecurity, claiming universal visibility without accounting for OS scheduler quantization or filesystem boundary limits produces fragile research. Defensibility requires defining exactly where observation stops."

---

## Slide 6: Threat Model & Trust Boundaries

### Slide Content
- **In-Scope Adversary Capabilities**:
  - Repository tampering & unsigned author spoofing.
  - Dependency substitution & lockfile hash divergence.
  - Unexpected build subprocesses & hijacked toolchains.
  - Filesystem mutations inside configured build workspaces.
  - High-entropy DNS tunneling & unauthorized TCP/UDP sockets.
  - Target artifact modification & provenance replay.
- **Bounded / Out-of-Scope (TCB Assumptions)**:
  - Ring-0 kernel rootkits hooking OS dispatch tables (`ntoskrnl.exe`).
  - Hardware microarchitectural attacks (Spectre, Meltdown, Rowhammer).
  - Physical hardware cryptographic key extraction.
  - Unsupported or unmonitored telemetry environments.

### Speaker Notes
- **Speaker Objective**: Delineate in-scope capabilities from out-of-scope physical assumptions.
- **30–60 Second Explanation**: "We establish a three-tier threat model. In scope are adversary mutations at the repository, dependency, process, filesystem, network, and artifact layers. Out of scope are Ring-0 kernel rootkits, hardware side-channels, and physical key theft. The OS kernel and cryptographic primitives form our trusted computing base."
- **Likely Examiner Interruption**: *"What if an attacker has root or administrator access on the CI runner?"*
- **Answer**: "Under Windows Administrator privileges, ProvenanceX leverages Kernel ETW, which captures sub-millisecond process lifecycles. However, if the adversary possesses Ring-0 kernel execution, they can unhook ETW dispatchers. We explicitly treat Ring-0 compromise as outside the user-mode/kernel-telemetry threat model."

---

## Slide 7: Complete System Architecture

### Slide Content
- **Architecture Flow (Figure 2)**:
  - `Evidence Ingestion` (Planes $L_1 - L_{12}$)
  - `Evidence Normalization Engine`
  - `RFC 6962 Append-Only Integrity Log` ($H_i = 	ext{SHA-256}(H_{i-1} \parallel L_i \parallel D_i)$)
  - `Trust Graph Formulation` (Kahn's DAG)
  - `Cross-Layer Multi-Plane Correlation` ($\mathcal{C}(L_i, L_j)$)
  - `Causal Trust-Break Localization` ($L^*$)
  - `Policy Decision Engine` (`TRUSTED`, `WARNING`, `REJECTED`)
  - `Air-Gapped Standalone Verifier` (`provenancex-verifier`)

### Speaker Notes
- **Speaker Objective**: Walk through the end-to-end dataflow of ProvenanceX.
- **30–60 Second Explanation**: "Figure 2 illustrates the architecture. Evidence is collected across 12 planes, normalized, and bound into an append-only RFC 6962 Merkle log. The Trust Graph constructs a DAG of evidence dependencies. The correlation engine evaluates pairwise invariants. When contradictions occur, the localization engine isolates the earliest broken layer, and the policy engine emits a deterministic verdict."
- **Likely Examiner Interruption**: *"Why use an append-only Merkle chain if you already have a DAG?"*
- **Answer**: "The Merkle log provides temporal tamper-evidence: it ensures that telemetry records cannot be retroactively modified or reordered after emission. The DAG provides causal structure: it represents functional dependencies between build stages."

---

## Slide 8: The Twelve-Layer Evidence Model

### Slide Content
- **The 12 Normalized Planes**:
  - $L_1$ Source Repository • $L_2$ Declared Dependencies • $L_3$ Lockfile Resolution
  - $L_4$ Software Bill of Materials • $L_5$ Environment Fingerprint • $L_6$ Build Process
  - $L_7$ Process Hierarchy • $L_8$ Filesystem Mutations • $L_9$ Network Connections
  - $L_{10}$ Target Artifacts • $L_{11}$ Attestations & Lineage • $L_{12}$ Cryptographic Signatures
- **Epistemic Classification**:
  - **Direct Observations ($\mathcal{E}_{	ext{direct}}$)**: Host sensors (ETW, filesystem, sockets).
  - **Derived Evidence ($\mathcal{E}_{	ext{derived}}$)**: Mathematically computed digests and Merkle roots.
  - **External Assertions ($\mathcal{E}_{	ext{external}}$)**: Claims authored by runners or third parties (SLSA, SBOM).

### Speaker Notes
- **Speaker Objective**: Detail the 12 evidence planes and explain the epistemic triad.
- **30–60 Second Explanation**: "Figure 3 organizes reality into 12 planes and three epistemic classes: Direct observations captured by host sensors, Derived evidence computed cryptographically, and External assertions claimed by third parties. Contradictions occur whenever external claims diverge from direct host observations or derived calculations."
- **Likely Examiner Interruption**: *"Why are there 12 planes? Is 12 an arbitrary number?"*
- **Answer**: "12 corresponds to the discrete structural stages of modern software distribution, from initial Git commit, through dependency locking, compiler process spawning, disk writes, and network calls, to final binary packaging and signing. Each plane possesses a unique schema and observation sensor."

---

## Slide 9: Cross-Layer Pairwise Correlation

### Slide Content
- **Algorithmic Flow**:
  - `Observe` $ightarrow$ `Normalize` $ightarrow$ `Correlate` $ightarrow$ `Detect Contradiction` $ightarrow$ `Localize` $ightarrow$ `Decide`
- **Key Pairwise Correlation Invariants**:
  - **Process-Filesystem $\mathcal{C}(L_7, L_8)$**: Every modified file must map to an authorized compiler PID.
  - **Dependency-Network $\mathcal{C}(L_3, L_9)$**: Socket connections must map strictly to package registries declared in lockfiles.
  - **Artifact-Attestation $\mathcal{C}(L_{10}, L_{11})$**: Target binary SHA-256 must match SLSA subject bit-for-bit.
  - **Source-Cleanliness $\mathcal{C}(L_1, L_8)$**: Untracked working tree files must match declared generated path policies.

### Speaker Notes
- **Speaker Objective**: Demonstrate how pairwise correlation exposes multi-layer contradictions.
- **30–60 Second Explanation**: "Single-layer checks are easily evaded by attacks that maintain internal consistency within one plane. ProvenanceX evaluates pairwise correlation invariants. For example, invariant C(L3, L9) checks whether network socket connections match the registries declared in lockfiles. If a build connects to an unapproved mirror, a contradiction is declared even if the lockfile itself is syntactically valid."
- **Likely Examiner Interruption**: *"What if a build tool legitimately downloads dependencies during compilation?"*
- **Answer**: "If policy permits dynamic dependency retrieval, the observed endpoints must match declared registries. If network isolation is enforced, any egress triggers a rejection. The policy engine evaluates user-defined organizational rules deterministically."

---

## Slide 10: Trust-Graph Localization Engine ($L^*$)

### Slide Content
- **The Challenge**: Cascading downstream failures obscure the true root cause.
  - *Example*: Binary hash mismatch ($L_{10}$) causes SLSA attestation failure ($L_{11}$) and signature invalidation ($L_{12}$).
- **Topological Localization Algorithm**:
  - Construct DAG $G = (V, E)$ where edges represent causal prerequisites.
  - Compute topological sort $\Pi = [L_{\pi_1}, \dots, L_{\pi_{12}}]$ via Kahn's algorithm.
  - Isolate earliest broken plane:
    $$L^* = rg\min_{L_k \in \Pi} \{ k \mid 	ext{EvidenceState}(L_k) = 	ext{CONTRADICTED} \}$$
- **Key Scientific Distinction**:
  - *ProvenanceX identifies the earliest observable inconsistent layer rather than claiming to identify the attacker's true physical origin.*

### Speaker Notes
- **Speaker Objective**: Explain the mathematical localization algorithm and state its precise epistemic scope.
- **30–60 Second Explanation**: "When multi-stage attacks occur, downstream evidence breaks in a cascade. Security teams need to know where the failure started. ProvenanceX performs Kahn's topological sort on the evidence DAG and identifies L*, the earliest contradicted plane. Across evaluated composed attack scenarios, this achieved 100% correct localization. Crucially, we emphasize that this identifies the earliest observable inconsistent layer, not necessarily the attacker's physical entry point."
- **Likely Examiner Interruption**: *"Could an attacker compromise an earlier layer in a way that leaves no observable evidence?"*
- **Answer**: "Yes. If an attack occurs completely outside configured telemetry, the graph cannot observe it. That is why we formally define L* as the earliest observable broken layer within the evidence graph, preserving scientific precision."

---

## Slide 11: Policy Engine & Categorical Decision Semantics

### Slide Content
- **Rejection of Arbitrary Numerical Risk Scores**:
  - No arbitrary formulas (e.g., `Risk: 72/100`).
  - Strict, deterministic categorical verdicts:
    - **`TRUSTED`**: Zero contradictions, all cryptographic proofs valid, zero undeclared evidence gaps.
    - **`WARNING`**: Non-fatal policy deviations (e.g., unsigned commit on development branch, minor monotonic timestamp skew).
    - **`REJECTED`**: Fatal contradictions (digest mismatch, unapproved process execution, unauthorized network egress).
- **Declarative Policy Schema**: YAML-based rules specifying repository cleanliness, allowed registries, and compiler ancestry.

### Speaker Notes
- **Speaker Objective**: Justify categorical verdicts over arbitrary heuristic scores.
- **30–60 Second Explanation**: "Many commercial security tools output arbitrary risk scores like 72 out of 100, which have no formal semantic meaning. ProvenanceX enforces deterministic categorical verdicts: TRUSTED, WARNING, or REJECTED. Every verdict is backed by an explicit policy rule and a machine-readable JSON explanation showing the contradicted nodes."
- **Likely Examiner Interruption**: *"Isn't categorical classification too rigid for modern development workflows?"*
- **Answer**: "Rigidity is essential at deployment gates: a binary either satisfies release policy or it does not. However, policy rules are configurable, allowing organizations to declare generated path exemptions or non-release warning policies."

---

## Slide 12: Standalone Air-Gapped Verification

### Slide Content
- **Standalone Binary (`provenancex-verifier`)**:
  - Deploys as an independent binary at consumer release gates.
  - Evaluates self-contained `.tar.gz` release bundles.
- **Verification Workflow**:
  - `Bundle Extraction` $ightarrow$ `Archive Integrity Check` $ightarrow$ `Digest Match` $ightarrow$ `Signature Validation` $ightarrow$ `Attestation Consistency` $ightarrow$ `Verdict`
- **Environmental Independence in the Tested Configuration**:
  - **0 Network Sockets Initiated**
  - **0 Central Database Connections**
  - Self-contained standard library cryptographic mathematics (Ed25519, ECDSA, RSA, SHA-256).

### Speaker Notes
- **Speaker Objective**: Present the standalone verifier and its offline verification property.
- **30–60 Second Explanation**: "Downstream consumers often operate in air-gapped or restricted networks where querying central databases or transparency logs is impossible. We developed provenancex-verifier, a standalone Go binary that verifies release bundles locally. In our tested configuration, it operates with zero network sockets and zero database connections."
- **Likely Examiner Interruption**: *"How do you handle certificate revocation without network connectivity?"*
- **Answer**: "In air-gapped mode, dynamic CRL or OCSP queries are physically impossible. ProvenanceX relies on pre-distributed root public keys or bundled signed certificate chains with embedded validity windows, which we document as an operational trade-off."

---

## Slide 13: Empirical Evaluation Methodology

### Slide Content
- **Hardware & Environment Testbed**:
  - AMD64 Architecture (8 physical cores / 16 logical threads, 3.8 GHz), 32 GB DDR4 RAM, NVMe SSD (>2,500 MB/s read).
  - Windows 11 Enterprise (Build 26100) with Kernel ETW & user-mode polling fallbacks.
  - Go 1.23.6 windows/amd64 toolchain.
- **Empirical Rigor**:
  - **19,777 Total Raw Trials** across 7 frozen benchmark campaigns.
  - Strict closed identity enforced: $N = TP + FN + TN + FP$.
  - Immutable SHA-256 hashed baseline datasets (`results/day12_baseline/` through `results/day17/`).
  - Zero test-train data leakage confirmed via feature disjointness audit.

### Speaker Notes
- **Speaker Objective**: Demonstrate methodological rigor and experimental reproducibility.
- **30–60 Second Explanation**: "Our empirical evaluation spans 19,777 raw trials across 7 frozen benchmark campaigns. Every physical trial enforces the closed mathematical identity N = TP + FN + TN + FP. All baseline datasets are hashed and frozen. A feature disjointness audit verified zero data leakage between attack generators and detection logic."
- **Likely Examiner Interruption**: *"Are these real-world attacks or synthetic mutations?"*
- **Answer**: "They are controlled adversarial mutations modeled directly after real-world supply-chain attack techniques—including Sunburst process injection, Codecov socket exfiltration, and XZ Utils build drift—evaluated across 25 distinct threat families."

---

## Slide 14: Comprehensive Results & Population Disentanglement

### Slide Content
- **Audited Experimental Populations**:
  - **Day 12 Baseline ($N=6,250$)**: $TP=4,000, FN=1,000, TN=1,250, FP=0 \implies \mathbf{80.00\%}$ Attack Recall (4 blind spots discovered).
  - **Day 13 Remediation Micro-Campaign ($N=4,000$)**:
    - *Pre-Remediation ($N=2,000$)*: $TP=0, FN=2,000 \implies \mathbf{0.00\%}$ Recall.
    - *Post-Remediation ($N=2,000$)*: $TP=1,750, FN=250 \implies \mathbf{87.50\%}$ Recall.
    - *Combined Micro-Total*: $N=4,000, TP=1,750, FN=2,250 \implies 43.75\%$ (not post-remediation capability).
  - **Day 13 Multi-Run Macro Attack Recall**: $\mathbf{98.75\%}$ mean across all 25 evaluated attack families.
  - **Day 14 Closed Holdout ($N=7,500$)**: $\mathbf{100.00\%}$ Recall on evaluated closed holdout population.
  - **Day 16 Dedicated Benign Campaign ($N=1,000$)**: $\mathbf{100.00\%}$ Specificity (0 FP observed with declared path policies).
  - **Day 16 Targeted Stress Probes ($N=27$)**: $\mathbf{81.25\%}$ Recall (13 TP, 3 FN, 11 TN, 0 FP) probing kernel boundaries.

### Speaker Notes
- **Speaker Objective**: Present results transparently with strict population separation.
- **30–60 Second Explanation**: "Slide 14 presents our core empirical findings with strict population disentanglement. On Day 12, our baseline recall was 80.00%, exposing 4 blind spots. Day 13 remediation resolved 3 of the 4, achieving 98.75% macro recall across 25 families. In our dedicated 1,000-trial benign campaign, zero false positives were observed when generated paths were declared. Stress probes confirmed our theoretical kernel boundaries with 81.25% recall."
- **Likely Examiner Interruption**: *"Why was Day 13 combined recall only 43.75%?"*
- **Answer**: "43.75% is the combined total of testing 2,000 pre-remediation trials (0% recall) and 2,000 post-remediation trials (87.50% recall). It is an artifact of pooling two different system configurations and must never be presented as post-remediation capability."

---

## Slide 15: Observability Findings & Sensor Boundaries

### Slide Content
- **Empirical Sensor Characterization**:
  - **Windows Kernel ETW**: 100% event capture across all evaluated process lifetimes down to sub-millisecond execution.
  - **User-Mode Polling Fallback**: Bounded by ~15.6 ms OS scheduler quantization; sub-10ms ephemeral processes achieve 0% capture, bounding overall user-mode process recall to 62.50%.
  - **Filesystem Telemetry**: Snapshot diffing misses transient in-flight file drops; asynchronous directory streams achieve 71.43% capture (bounded by <1ms OS buffer coalescing).
  - **DNS Telemetry**: Multi-feature Shannon entropy (>3.8) detects encoded tunneling (92.3% recall); low-entropy dictionary subdomains evade lexical filters in isolation.

### Speaker Notes
- **Speaker Objective**: Present experimental proof of hardware and OS telemetry limitations.
- **30–60 Second Explanation**: "Our observability experiments proved that telemetry depends on privilege and OS mechanics. Administrator Kernel ETW achieves 100% process visibility, while user-mode polling is fundamentally bounded by the 15.6 ms OS timer quantization. In-flight transient file drops evade snapshot diffing, and dictionary-encoded DNS tunneling evades lexical entropy filters in isolation."
- **Likely Examiner Interruption**: *"Doesn't this mean ProvenanceX fails in unprivileged CI environments?"*
- **Answer**: "It means user-mode observation is bounded. ProvenanceX explicitly flags when non-admin privileges prevent sub-10ms process monitoring, informing administrators of the exact observation boundary rather than providing false assurances."

---

## Slide 16: Performance Disentanglement

### Slide Content
- **Algorithmic vs Physical Scope Disentanglement**:
  - **In-Memory Graph Correlation**: **12.4 µs** (mean latency across pre-ingested evidence structs in RAM).
  - **Physical CI Build Overhead**: **0.24%** (~2.4 ms added to a 1,000 ms Go physical compilation).
  - **Sequential Artifact Hashing**: **48.2 ms** for a 100 MB binary (NVMe bus throughput: ~2,074 MB/s).
  - **Local Dependency Parsing**: **3.20 ms** for 500 transitive packages (excludes remote network download).
  - **Graph Scalability**:
    - *Theoretical*: $O(V + E)$ linear complexity for Kahn's topological sort.
    - *Empirical*: **48.2 ms** under the tested 100,000-node synthetic graph configuration.

### Speaker Notes
- **Speaker Objective**: Prevent confusion by disentangling algorithmic speed from hardware I/O.
- **30–60 Second Explanation**: "We rigorously disentangle algorithmic speed from physical hardware I/O. In-memory graph correlation requires 12.4 microseconds in RAM. End-to-end build tax on physical Go compilations is just 0.24%, or 2.4 milliseconds. Artifact hashing is storage bus-bound, requiring 48.2 milliseconds for a 100MB binary on NVMe storage."
- **Likely Examiner Interruption**: *"Why emphasize 12.4 µs if physical hashing takes 48 ms?"*
- **Answer**: "Because they measure different subsystems. 12.4 µs measures our algorithmic decision engine. 48 ms measures physical storage hardware bandwidth. Conflating algorithmic complexity with hardware I/O obscures the true computational cost of the framework."

---

## Slide 17: Research Limitations Ledger

### Slide Content
- **Major Documented Operational Boundaries**:
  1. **Privilege-Dependent Telemetry**: Sub-10ms process capture requires Windows Administrator ETW elevation (`SeCreateGlobalPrivilege`).
  2. **Scheduler Timer Quantization**: Non-admin user-mode collectors are bounded by ~15.6 ms OS scheduling intervals.
  3. **Transient File Coalescing**: Rapid create-and-delete operations executing in <1 ms can coalesce in OS I/O buffers.
  4. **Observation-Boundary Dependence**: File writes outside configured workspace roots evade user-mode watchers (ADV-HUNT-01).
  5. **Encrypted Network Sockets**: DNS-over-HTTPS (DoH) / TLS (DoT) bypasses local OS DNS parsers without network egress firewalls.
  6. **Finite Controlled Evaluation**: Empirical validation reflects 25 evaluated attack families and closed holdouts; novel OS evasion primitives remain possible.

### Speaker Notes
- **Speaker Objective**: Demonstrate scientific integrity by presenting documented limitations.
- **30–60 Second Explanation**: "Slide 17 summarizes our limitations ledger. We catalog 6 primary operational boundaries: privilege requirements for sub-ms processes, timer quantization in user mode, transient file coalescing in OS buffers, unmonitored directory escapes, encrypted DNS evasion, and the bounded nature of finite testbeds."
- **Likely Examiner Interruption**: *"Doesn't listing so many limitations weaken your thesis?"*
- **Answer**: "On the contrary, characterizing exact failure boundaries is what transforms an engineering prototype into rigorous scientific research. A system that claims universal security without boundaries is unscientific."

---

## Slide 18: Contributions & Concluding Statement

### Slide Content
- **Summary of Research Contributions**:
  - Formalized the **12-Layer Cross-Layer Verification Model** to bridge the Attestation-Reality Divergence.
  - Designed and proved the **Topological Earliest Trust-Break Localization Algorithm** ($L^*$).
  - Developed a **Standalone Air-Gapped Verifier** operating with 0 network sockets and 0 database connections in tested configurations.
  - Published an **Empirical Benchmark Suite** of 19,777 raw trials across 7 frozen datasets achieving Level 5 reproducibility.
- **Authoritative Concluding Defense**:
  > *"ProvenanceX does not claim universal attack visibility. It provides an independent mechanism for correlating observable evidence, identifying contradictions, localizing the earliest observable trust break, and explicitly representing where stronger conclusions cannot be justified."*

### Speaker Notes
- **Speaker Objective**: Deliver the authoritative concluding thesis statement.
- **30–60 Second Explanation**: "In conclusion, ProvenanceX demonstrates that cross-layer multi-plane verification effectively bridges the Attestation-Reality Divergence. We do not claim universal attack visibility. ProvenanceX provides an independent mechanism for correlating observable evidence, identifying contradictions, localizing the earliest observable trust break, and explicitly representing where stronger conclusions cannot be justified. Thank you, and I welcome your questions."
- **Likely Examiner Interruption**: *"Final question: If you had to deploy this in production tomorrow, what is the single biggest operational challenge?"*
- **Answer**: "Managing policy declarations for in-tree generated files. As demonstrated in our benign variability experiments, developers frequently use code generators like protobuf and mockgen that write untracked files during builds. Enforcing clean repository policies without developer friction requires automated policy inference for legitimate generated paths."