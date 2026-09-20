# ProvenanceX Examiner Question Bank & Technical Defense Guide

This document prepares the doctoral/master's candidate for viva voce examination, defense panels, and technical audits. It contains 30 rigorous questions across six categories with direct, evidence-based, and bounded answers.

---

## Category 1: Research Motivation

### Q1: Why is ProvenanceX necessary?
**Direct Answer**: ProvenanceX is necessary because prevailing supply-chain integrity mechanisms rely on self-attestation. If a build runner is compromised, it can compile backdoored binaries while simultaneously authoring cryptographically valid SLSA attestations and authentic signatures over those backdoored binaries. ProvenanceX provides an independent cross-layer verification layer to detect when physical execution contradicts declared metadata.

### Q2: What exact problem does it solve?
**Direct Answer**: It solves the *Attestation-Reality Divergence*: the vulnerability where signed metadata asserts a benign build pipeline while physical host execution (processes, filesystem I/O, network sockets) contains unapproved tampering or data exfiltration.

### Q3: Why isn't artifact signing sufficient?
**Direct Answer**: Digital signing (e.g., Sigstore, Cosign) provides non-repudiation of signer identity, but it is semantically blind to the integrity of the compilation process itself. A valid signature merely proves that a specific key authorized the payload; it does not prove that the payload was compiled without in-flight process injection or unapproved dependency manipulation.

### Q4: What is the Attestation-Reality Divergence?
**Direct Answer**: The structural divergence where declared metadata claims (source commit, lockfile hashes, declared dependencies, builder ID) diverge from the observed ground truth captured by physical host execution telemetry during the build.

---

## Category 2: System Architecture

### Q5: Why use multiple evidence layers?
**Direct Answer**: Attacks on the software supply chain rarely violate all layers simultaneously; sophisticated attacks preserve apparent validity in one layer while mutating another (e.g., keeping package.json unchanged while modifying object files on disk). Correlating 12 discrete planes ensures that tampering in any single layer creates a detectable contradiction against adjacent planes.

### Q6: Why a trust graph?
**Direct Answer**: A flat list of events cannot represent the causal prerequisites of software compilation. A trust graph structures evidence into nodes representing discrete planes and edges representing causal dependencies (e.g., lockfile resolution must precede compilation).

### Q7: Why a Directed Acyclic Graph (DAG)?
**Direct Answer**: Software builds follow a strictly causal, forward-in-time progression: source checkout precedes dependency resolution, which precedes compilation, which precedes packaging and signing. Cycles represent temporal impossibilities or recursive tampering. An acyclic graph enables deterministic topological sorting via Kahn's algorithm.

### Q8: Why cross-layer correlation?
**Direct Answer**: Single-layer validation yields high false acceptance rates (50% to 80% in our ablation study). Cross-layer pairwise correlation evaluates invariants across independent subsystems (e.g., verifying that network sockets at Plane $L_9$ connect only to package registries declared in lockfiles at Plane $L_3$).

### Q9: Why deterministic policy instead of risk scores?
**Direct Answer**: Numerical risk scores (e.g., `Risk: 72/100`) lack formal semantics and create arbitrary, non-reproducible deployment gate decisions. ProvenanceX uses an explicit declarative schema and evaluates deterministic categorical verdicts (`TRUSTED`, `WARNING`, `REJECTED`) where every rejection is tied to an explicit rule violation.

### Q10: Why an offline verifier?
**Direct Answer**: Consumer release gates often operate in air-gapped, isolated, or regulated industrial environments (SCADA, defense, avionics) where querying external cloud transparency logs or databases is prohibited. The standalone verifier validates release bundles using purely local cryptographic mathematics.

---

## Category 3: Security & Observability

### Q11: What happens if evidence is missing?
**Direct Answer**: ProvenanceX classifies missing evidence as an explicit *Evidence Gap* ($G_1$ unobserved layer, $G_2$ unpinned dependency, $G_3$ unsigned commit, $G_4$ out-of-boundary activity). Missing evidence is never equated with trust; depending on policy, gaps trigger either a `WARNING` or a fatal `REJECTED` verdict.

### Q12: Can an attacker evade telemetry?
**Direct Answer**: In unprivileged user-mode CI runners without kernel ETW elevation, yes: ephemeral subprocesses executing in under 10 ms (ADV-HUNT-03) and rapid file operations coalescing in under 1 ms can evade user-mode polling. Under Administrator Kernel ETW, however, process events are captured directly from kernel dispatchers with 100% visibility down to sub-millisecond lifecycles.

### Q13: What happens outside the observation boundary?
**Direct Answer**: Activity outside configured observation boundaries (e.g., an unmonitored directory escape writing to `D:\Temp\` as demonstrated in ADV-HUNT-01) cannot be observed by workspace monitors. ProvenanceX explicitly catalogs this as an unobservable condition requiring operating-system-level container or sandbox isolation.

### Q14: Can ProvenanceX detect kernel-level attacks?
**Direct Answer**: No. Ring-0 kernel rootkits that modify kernel page tables or hook `ntoskrnl.exe` dispatch tables are formally outside the threat model. The OS kernel and CPU hardware form the trusted computing base (TCB).

### Q15: Can DNS tunneling evade the system?
**Direct Answer**: High-entropy Base64/Hex DNS tunneling is detected with 92.3% recall via Shannon entropy heuristics (>3.8). However, low-entropy dictionary-word subdomain tunneling (e.g., `update.check.pkg.go.dev`) evades lexical filters in isolation unless correlated with unexpected process sockets.

### Q16: Can a malicious file hide inside a declared generated path?
**Direct Answer**: If an adversary writes a malicious payload matching a declared generated path wildcard (e.g., `mock_auth.go`), static cleanliness checks will not flag it as an uncommitted file. However, if the malicious file is written by an unapproved process PID or initiates network sockets, cross-layer process-filesystem invariants will detect it.

---

## Category 4: Empirical Evaluation

### Q17: Why is Day 14 100%?
**Direct Answer**: The 100.00% recall on Day 14 ($6,250 / 6,250$ trials) reflects performance strictly on the evaluated closed holdout population comprising 11 novel unseen attack variants and 3 composed attacks within configured workspace paths.

### Q18: Why isn't that presented as universal 100% detection?
**Direct Answer**: Because presenting holdout success as universal security is unscientific. The 100% holdout result is bounded by configured observation paths and Administrator ETW telemetry. Attacks operating outside those physical conditions (e.g., unmonitored directory writes) evade detection.

### Q19: What does the 98.75% number actually mean?
**Direct Answer**: 98.75% is the post-remediation *macro attack recall across the 25 evaluated attack families* ($[21 	imes 100\% + 3 	imes 100\% + 1 	imes 68.75\%] / 25$). It represents the unweighted mean family recall, reflecting that 24 families achieve 100% detection while the residual out-of-boundary filesystem family achieves 68.75% bounded recall.

### Q20: Why is Day 13 combined recall only 43.75%?
**Direct Answer**: 43.75% ($1,750 / 4,000$) is an artifact of pooling 2,000 pre-remediation baseline trials (0% recall) with 2,000 post-remediation trials (87.50% recall). It represents a combined historical test run and must never be cited as post-remediation system capability.

### Q21: Why separate the 1,000 benign trials from the 27 stress trials?
**Direct Answer**: Because they evaluate distinct operational scopes. The 1,000-trial benign campaign evaluated production-style builds under normal development variation (path relocations, dynamic timestamps, declared generated files) to measure false alarm rates (0 FP). The 27 stress trials deliberately probed kernel boundaries and lexical limits to establish where sensors break (81.25% recall).

### Q22: How was data leakage prevented?
**Direct Answer**: Through a formal feature disjointness audit (`docs/DATA_LEAKAGE_AUDIT.md`). Detection algorithms evaluate abstract invariant rules (PID ancestry, lockfile AST hashes, Shannon entropy) and contain zero hardcoded test fixtures, mutation IDs, or synthetic test signatures.

---

## Category 5: Performance & Hardware Disentanglement

### Q23: What does 12.4 µs measure?
**Direct Answer**: 12.4 microseconds is the pure algorithmic mean latency of the in-memory decision engine evaluating graph correlation rules across pre-ingested, in-RAM evidence structs.

### Q24: Why isn't 12.4 µs the build latency?
**Direct Answer**: Because real-world builds involve physical storage I/O, process execution, and compiler toolchains. In-memory correlation operates in RAM, whereas physical build overhead includes filesystem interception and binary hashing.

### Q25: What does 0.24% build overhead mean?
**Direct Answer**: It is the empirical wall-clock execution tax added by ProvenanceX runtime telemetry to a standard physical Go compilation (adding ~2.4 ms to a 1,000 ms build baseline), demonstrating that telemetry capture incurs negligible build friction.

### Q26: How does graph complexity scale?
**Direct Answer**: Theoretically, Kahn's topological sort and pairwise correlation scale linearly in $O(V + E)$ where $V$ is evidence planes and $E$ is causal dependencies. Empirically, synthetic graph stress tests demonstrated 4.8 µs per node, executing a 100,000-node graph traversal in 48.2 ms without polynomial blowup.

---

## Category 6: Research Validity & Open Problems

### Q27: What is the strongest limitation?
**Direct Answer**: The dependence on observation boundaries. If an attack executes entirely in unmonitored external filesystem locations or leverages low-entropy dictionary subdomain DNS tunneling in an unprivileged user-mode CI environment, ProvenanceX cannot observe the divergence.

### Q28: What would invalidate your conclusions?
**Direct Answer**: If an attacker can demonstrate an attack variant that violates cross-layer correlation within configured observation boundaries while maintaining zero contradictions across all 12 evidence planes, or if unmonitored in-tree generated files trigger unavoidable false alarms under real-world CI workflows.

### Q29: What is genuinely contributed by ProvenanceX versus existing standards?
**Direct Answer**: Three primary contributions: (1) An independent cross-layer evidence model that breaks reliance on build-runner self-attestation; (2) A deterministic topological localization algorithm that isolates earliest broken layers ($L^*$); and (3) A rigorous empirical characterization of OS scheduler and privilege boundaries that replaces marketing claims with verifiable scientific limits.

### Q30: What would you do with a larger research budget?
**Direct Answer**: We would implement hardware-enforced trusted execution environment (TEE) attestation using AMD SEV-SNP / Intel TDX to measure and cryptographically bind the entire build runner hypervisor, deploy cross-platform eBPF sensors on Linux, and integrate formal automated policy synthesis for in-tree code generation.