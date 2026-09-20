# ProvenanceX Viva Defense Presentation Deck (18 Slides)

**Candidate**: Karthik Ram  
**Title**: ProvenanceX: Cross-Layer Verification & Causal Trust-Break Localization for Software Supply Chains  
**Target Examination**: Doctoral / Master's Thesis Viva Voce Defense  

---

## Slide 1: Title & Overview
- **Title**: ProvenanceX: A Cross-Layer Framework for Software Supply-Chain Integrity Verification
- **Subtitle**: Bridging the Attestation-Reality Divergence via Causal Trust Graphs
- **Candidate**: Karthik Ram
- **Committee**: External Examiners & Defense Panel
- **Visual**: ProvenanceX Logo, Multi-Layer Evidence Stack diagram.
- **Speaker Notes**: "Good morning, members of the committee. Today I present ProvenanceX, a framework designed to solve one of the most critical vulnerabilities in modern computing: the fundamental divergence between declared software provenance and physical build execution."

---

## Slide 2: The Supply Chain Crisis & Real-World Failures
- **Bullet Points**:
  - Open source software drives 90%+ of modern enterprise infrastructure.
  - Attacks have shifted from runtime exploitation to build-time supply chain poisoning.
  - Real-world breaches: SolarWinds Sunburst, Codecov Bash Uploader, XZ Utils Backdoor (CVE-2024-3094).
- **Visual**: Timeline of major supply chain attacks (2020–2024).
- **Speaker Notes**: "In SolarWinds, malware modified source code in-flight while the compiler was running. In Codecov, CI credentials were stolen via unauthorized sockets. In XZ Utils, malicious build macros compromised sshd. Current defenses failed to catch all three."

---

## Slide 3: The Root Problem: The Attestation-Reality Divergence
- **Bullet Points**:
  - Current standards (SLSA, in-toto, Sigstore) rely on *self-attestation*.
  - The build runner authors claims about its own integrity.
  - **The Dilemma**: A compromised runner compiles a backdoored binary and simultaneously writes a valid SLSA attestation matching that binary.
  - Downstream consumers verify a cryptographically authentic, perfectly signed trojan.
- **Visual**: Architectural split showing Runner declaring trust vs Host reality.
- **Speaker Notes**: "The root cause is structural: self-attestation. If the build runner is compromised, it has the keys and the authority to lie. ProvenanceX enforces an uncompromising architectural axiom: the build system does not get to verify itself."

---

## Slide 4: ProvenanceX Core Thesis & Contributions
- **Bullet Points**:
  - **Core Thesis**: Independent cross-layer correlation of declared metadata against direct host execution traces enables deterministic attack detection and causal root-cause localization.
  - **Key Contributions**:
    1. 12-Plane Multi-Layer Evidence Model.
    2. Kahn's Topological Earliest Trust-Break Localization ($L^*$).
    3. Air-Gapped Standalone Verifier with zero network dependencies.
    4. 19,777-Trial Empirical Benchmark Suite across 25 threat families.
    5. Formally Bounded 18-point Limitations Ledger.
- **Speaker Notes**: "Rather than claiming universal magic, ProvenanceX provides mathematically grounded correlation, causal root-cause localization, and honest boundary characterization."

---

## Slide 5: System Architecture & The 12 Evidence Planes
- **Bullet Points**:
  - Spans 12 discrete planes: $L_1$ (Source) through $L_{12}$ (Signatures).
  - Epistemic Triad: Direct Observations ($\mathcal{E}_{\text{direct}}$), Derived Evidence ($\mathcal{E}_{\text{derived}}$), External Assertions ($\mathcal{E}_{\text{external}}$).
  - Append-Only RFC 6962 Cryptographic Merkle Evidence Chain.
- **Visual**: Figure 1 System Architecture diagram.
- **Speaker Notes**: "Every plane is cryptographically chained. Retroactive tampering with build telemetry or source metadata immediately invalidates the Merkle root."

---

## Slide 6: Dual-Tier Telemetry: Administrator ETW vs Non-Admin Polling
- **Bullet Points**:
  - **Tier 1 (Admin ETW)**: Hooks Windows Kernel Process, Filesystem, and DNS dispatchers. 100% catch rate down to sub-millisecond ephemeral executions.
  - **Tier 2 (Non-Admin CI)**: Unprivileged container fallback using high-frequency polling and `ReadDirectoryChangesW`.
  - Honest Characterization: Polling is bounded by 15.6ms OS scheduler quantization. Sub-10ms ephemeral tasks require kernel ETW.
- **Speaker Notes**: "We do not pretend unprivileged code has kernel superpowers. We explicitly architected two tiers: privileged ETW for full visibility, and non-admin fallback with documented scheduler bounds."

---

## Slide 7: Cross-Layer Pairwise Correlation Semantics
- **Bullet Points**:
  - Isolated checks miss cross-layer attacks; ProvenanceX evaluates pairwise invariants $\mathcal{C}(L_i, L_j)$.
  - **Process-Filesystem**: Every file write must originate from an authorized compiler PID tree.
  - **Dependency-Network**: Network sockets must connect only to registries declared in lockfiles.
  - **Artifact-Attestation**: Artifact digest must match SLSA subjects bit-for-bit.
- **Visual**: Matrix of cross-plane invariants.
- **Speaker Notes**: "An attacker who modifies an object file using an unauthorized daemon immediately violates the process-filesystem causality invariant."

---

## Slide 8: Causal Trust-Break Localization ($L^*$)
- **Bullet Points**:
  - Multi-stage attacks trigger cascades of downstream failures.
  - Downstream symptom (Signature mismatch at $L_{12}$) obscures root cause ($L_8$ file injection or $L_7$ rogue process).
  - **Topological Localization**: Constructs DAG $G=(V, E)$, computes topological order $\Pi$, and terminates at earliest broken plane:
    $$L^* = \arg\min_{L_k \in \Pi} \{ k \mid \text{State}(L_k) = \text{CONTRADICTED} \}$$
  - 100% correct localization across the evaluated composed-attack scenarios ($N=750$).
- **Visual**: Figure 2 DAG with highlighted red root-cause node.
- **Speaker Notes**: "Security operations teams do not need 10 alarms saying the binary changed; they need to know that at 14:02:11 an unauthorized helper compiler injected code at Layer 8."

---

## Slide 9: Deterministic Policy Engine & Air-Gapped Verifier
- **Bullet Points**:
  - Zero non-deterministic "risk scores" (e.g. no arbitrary "72/100" numbers).
  - Strict categorical verdicts: `TRUSTED`, `WARNING`, `REJECTED`.
  - **Standalone Verifier (`provenancex-verifier`)**:
    - Evaluates `.tar.gz` release bundles at consumer gates.
    - Zero network sockets, zero database connections, zero external APIs.
- **Speaker Notes**: "In air-gapped defense or SCADA environments, you cannot query Rekor or cloud servers. The standalone verifier runs entirely offline using standard cryptographic mathematics."

---

## Slide 10: Empirical Methodology & Disentangled Populations
- **Bullet Points**:
  - 19,777 raw trials across 7 frozen benchmark campaigns.
  - Closed mathematical identity: $N = TP + FN + TN + FP$.
  - Methodological rigor: Zero test-train data leakage, immutable SHA-256 hashed datasets, strict separation of micro-campaigns and macro-averages.
- **Visual**: Summary table of the 7 frozen campaigns.
- **Speaker Notes**: "Every single trial is archived with its raw confusion matrix. We never report fractional counts for physical trials, and we never inflate numbers by pooling incompatible populations."

---

## Slide 11: Day 12 Adversarial Discovery: The 80.00% Baseline
- **Bullet Points**:
  - Evaluated 5,000 attack trials across 25 families and 1,250 benign trials.
  - **Baseline Result**: 80.00% recall (4,000 TP / 1,000 FN).
  - **Four Demonstrated Blind Spots (0% Recall)**:
    1. Unsigned Commit Author Spoofing ($F_6$)
    2. Sub-10ms Ephemeral Subprocesses ($F_{13}$)
    3. Transient File In-Flight Injection ($F_{14}$)
    4. Ephemeral Subdomain DNS Tunneling ($F_{15}$)
- **Speaker Notes**: "Day 12 was deliberately hostile. Rather than celebrating an artificial 100%, we searched for where ProvenanceX broke. We discovered four distinct empirical blind spots."

---

## Slide 12: Day 13 Targeted Remediation: 98.75% Macro Recall
- **Bullet Points**:
  - Remediated the four blind spots using cryptographic commit verification, kernel ETW hooks, asynchronous filesystem streams, and Shannon entropy heuristics.
  - **Targeted Micro-Campaign ($N=4,000$)**: 0.00% pre-remediation recall vs 87.50% post-remediation recall (isolating the residual out-of-boundary filesystem blind spot).
  - **Post-Remediation Macro Recall across 25 Families**: **98.75%**.
- **Visual**: Figure 3 Bar comparison of Day 12 vs Day 13.
- **Speaker Notes**: "We remediated 3 of the 4 blind spots completely. For the fourth—out-of-workspace writes—we proved that unconfigured directories cannot be observed without container sandbox isolation, formally documenting the boundary."

---

## Slide 13: Component Ablation Study
- **Bullet Points**:
  - Benchmarked ProvenanceX against 5 single-layer baselines across 1,000 trials.
  - SHA-256 alone: 20% detection (80% blind).
  - Digital signatures alone: 30% detection (70% blind).
  - SBOM reconciliation alone: 20% detection (80% blind).
  - SLSA attestations alone: 30% detection (70% blind).
  - **Full ProvenanceX**: **98.75% detection**.
- **Speaker Notes**: "This ablation proves that isolated metadata checks fail in 50% to 80% of supply chain attacks. Cross-layer correlation is mathematically necessary."

---

## Slide 14: Generalization & Scalability (Day 14)
- **Bullet Points**:
  - **11 Unseen Attack Scenarios ($N=5,500$)**: 100.00% recall within evaluated boundary.
  - **3 Composed Multi-Stage Attacks ($N=750$)**: 100% correct localization across the evaluated composed-attack scenarios.
  - **Benign Environmental Variability ($N=1,250$)**: 0.00% false alarms when generated paths are declared.
  - **Graph Scalability**: Theoretical: $O(V+E)$ for specified traversal; Empirical: 48.2 ms under tested 100,000-node configuration.
- **Visual**: Figure 5 Scalability Curve.
- **Speaker Notes**: "The graph engine scales strictly linearly. Even on a massive 100,000-node dependency graph, full topological traversal executes in under 50 milliseconds."

---

## Slide 15: Hardware Performance Disentanglement
- **Bullet Points**:
  - In-Memory Decision Engine Latency: **12.4 µs** (mean).
  - Physical End-to-End Build Tax on Go Compilations: **0.24%** (~2.4 ms).
  - Hashing Throughput: 2,074 MB/s (NVMe bus-bound).
  - Lockfile Parsing: 3.20 ms for 500 packages (excludes remote network download).
- **Speaker Notes**: "We rigorously separate algorithmic speed from physical hardware I/O. Microsecond correlation runs in RAM; physical build tax on actual compilations is just 0.24%."

---

## Slide 16: Research Claim Matrix & Independent Audit (Days 15–17)
- **Bullet Points**:
  - Claims C1 through C10 independently verified against immutable CSV datasets.
  - 100% Specificity confirmed on 1,000 dedicated benign builds.
  - 81.25% Recall cataloged on targeted stress hunts probing kernel limits.
  - Level 5 Empirical Reproducibility achieved.
- **Visual**: Table 4 Research Claim Matrix.
- **Speaker Notes**: "Every claim made in the thesis is backed by a specific immutable CSV file in the repository. Nothing is hand-waved or estimated."

---

## Slide 17: The 18-Point Limitations Ledger
- **Bullet Points**:
  - 1. Kernel privilege requirement for sub-ms processes.
  - 2. User-mode 15.6ms timer quantization.
  - 3. Sub-1ms transient file coalescing in OS I/O buffers.
  - 4. Unmonitored directory escape without container isolation.
  - 5. Low-entropy dictionary DNS tunneling.
  - 6. In-tree generated files require policy declarations.
  - 7. Detection and gate halting, not kernel inline blocking.
- **Speaker Notes**: "True scientific progress requires documenting where a system stops working. We catalog 18 concrete operational boundaries, giving practitioners clear guidance on where ProvenanceX must be paired with sandbox isolation."

---

## Slide 18: Conclusion & Viva Examination Traps
- **Bullet Points**:
  - ProvenanceX transforms software supply-chain security from self-attested trust to causally verified reality.
  - Open-source, reproducible, air-gapped, and empirically validated across 19,777 trials.
- **Examiner Trap 1**: *"Why didn't you achieve 100% recall on Day 13?"*
  - **Defensible Answer**: "Because claiming 100% on filesystem attacks without kernel filesystem drivers or container jails is mathematically and empirically false. An unmonitored directory escape cannot be observed by workspace monitors. We chose scientific truth over marketing perfection."
- **Examiner Trap 2**: *"Is 12.4 µs realistic for end-to-end verification?"*
  - **Defensible Answer**: "12.4 µs is the in-memory graph correlation latency across pre-parsed structs in RAM. End-to-end physical verification includes NVMe disk hashing (48 ms for 100MB) and build execution tax (2.4 ms / 0.24%), which we explicitly disentangle in Section 14."
- **Speaker Notes**: "Thank you for your time. I am now open to questions from the committee."