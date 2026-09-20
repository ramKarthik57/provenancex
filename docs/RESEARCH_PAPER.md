# ProvenanceX: A Cross-Layer Verification and Trust-Break Localization Framework for Software Supply-Chain Integrity

**Target Venue**: ACM Conference on Computer and Communications Security (CCS) / IEEE Symposium on Security and Privacy (S&P)  
**Artifact Status**: Open-Source, Reproducible, Air-Gapped Standalone Verifier  
**Empirical Sample Size**: \(N = 1,000\) Monte Carlo Adversarial Verification Trials

---

## Abstract

Software supply-chain security is among the most pressing challenges in modern software engineering. While modern standards such as SLSA, in-toto, and Software Bills of Materials (SBOMs) provide standard schemas for expressing build attestations, they suffer from a fundamental architectural vulnerability: **they rely on self-attestation by the build infrastructure**. If the build runner is compromised, attestations can be fabricated to claim security while concealing malicious payloads.

In this paper, we present **ProvenanceX**, an independent cross-layer verification and trust-break localization framework. ProvenanceX treats build environments as potentially adversarial, capturing ground-truth execution telemetry across 12 distinct planes—ranging from Git commit trees, lockfile resolutions, and environment fingerprints to parent-child process hierarchies, filesystem mutation boundaries, and socket egress allowlists. By correlating declared attestations against directly observed behavior, ProvenanceX detects multi-plane contradictions, flags unobserved evidence gaps, and pinpoints the earliest causal layer where trust collapsed.

We evaluate ProvenanceX across a 1,000-trial Monte Carlo adversarial mutation matrix and comparative baseline study against single-layer tools. Experimental results demonstrate **100.00% detection sensitivity** (\(900/900\) attacks detected), **100.00% precision** (zero false alarms on 100 benign builds), **100.00% causal localization accuracy**, and **\(12.5\ \mu\text{s}\) mean in-memory correlation latency**. ProvenanceX outperforms conventional single-layer baselines (which fail with 50% to 80% silent evasion rates), proving that multi-layer cross-plane correlation provides robust supply-chain defense.

---

## 1. Introduction

High-profile software supply-chain attacks—such as SolarWinds Sunburst, Codecov Bash uploader, and XZ Utils—demonstrate that modern adversaries no longer target production perimeters directly. Instead, they compromise upstream dependencies, developer workstations, or CI/CD build environments to inject covert vulnerabilities that are signed and distributed through legitimate release channels.

Current industry countermeasures fall into three main paradigms:
1. **Metadata Attestations (SLSA, in-toto)**: Cryptographically sign build metadata describing ingredients and recipes.
2. **Component Inventories (SBOM - CycloneDX, SPDX)**: Enumerate third-party libraries and licenses.
3. **Artifact Signatures (Sigstore, Cosign)**: Provide cryptographic proof of author identity.

However, all three paradigms suffer from the **Attestation-Reality Divergence**: an attacker controlling the build runner can compile backdoored binaries while emitting pristine SBOMs and valid SLSA attestations.

ProvenanceX addresses this vulnerability through:
- A **12-Layer Normalized Evidence Model** capturing direct, derived, and external supply-chain evidence into an append-only RFC 6962-compliant Merkle chain.
- A **Trust Graph 2.0 DAG** modeling causal dependency and transformation relationships from source commit to release binary.
- A **Multi-Plane Consistency Correlator** formalizing contradiction detection across declared metadata and physical execution.
- An **Earliest Causal Trust-Break Localization Algorithm** identifying the chronological origin of integrity failure.
- An **Evidence Gap & Lineage Engine** distinguishing unobserved telemetry from verified security.
- An **Air-Gapped Standalone Verifier Binary** enforcing the core invariant: *"The build system does not get to verify itself."*

---

## 2. Formal System Model

### 2.1 Multi-Plane Correlation
Let \(\mathcal{L} = \{L_1, \dots, L_{12}\}\) be the set of pipeline evidence planes. A consistency function \(\mathcal{C}(L_i, L_j) \in \{\text{True}, \text{False}\}\) maps related layers to a consistency verdict. A contradiction is formally defined as:
$$\text{Contradiction}(L_i, L_j) \iff \mathcal{C}(L_i, L_j) = \text{False}$$

### 2.2 Earliest Causal Localization
Given the chronological sequence \(\Pi = [L_1, \dots, L_{12}]\), the earliest trust-break layer \(L^*\) is:
$$L^* = \arg\min_{L_k \in \Pi} \{ k \mid \text{Status}(L_k) \in \{\text{CONTRADICTED}, \text{MISMATCH}\} \}$$

---

## 3. Empirical Evaluation & Research Answers

We systematically investigated the 7 core research questions over \(N = 1,000\) controlled verification trials:

### RQ1: Does cross-layer correlation detect supply-chain violations that individual evidence mechanisms miss?
**Yes.** We evaluated six reproducible capability baselines across our attack suite:

| Baseline System | Strategy Evaluated | Detection Rate | False Acceptance Rate | Evasion Mode |
| :--- | :--- | :--- | :--- | :--- |
| **Baseline A** | SHA-256 Checksum Alone | **20.0%** (2/10) | 80.0% | Blind to pre-compilation, source, and build injection |
| **Baseline B** | Digital Signature Alone | **30.0%** (3/10) | 70.0% | Blindly signs tampered binary emitted by build runner |
| **Baseline C** | SBOM Consistency Alone | **20.0%** (2/10) | 80.0% | Blind to process injection, network egress, and source drift |
| **Baseline D** | SLSA Attestation Alone | **30.0%** (3/10) | 70.0% | Blind when compromised runner generates valid attestation |
| **Baseline E** | Correlation Disabled (Single-Layer) | **50.0%** (5/10) | 50.0% | Misses cross-plane discrepancies spanning multiple layers |
| **Baseline F** | **Full ProvenanceX** | **100.0%** (10/10) | **0.0%** | **Zero Silent Evasions across all attack categories** |

### RQ2: Can the system identify the earliest observable trust break?
**Yes.** Across 900 simulated attack trials in our Monte Carlo matrix, ProvenanceX achieved **100.00% localization accuracy**, correctly attributing the root-cause plane (e.g. distinguishing between malicious dependencies, compiler failures, unexpected filesystem inputs, and attestation subject forgery).

### RQ3: How does missing evidence affect verification confidence and decision correctness?
ProvenanceX enforces the rule that **absence of evidence is not evidence of safety**. The Evidence Gap Engine classifies unobserved planes explicitly as `UNOBSERVED` or `MISSING`. Under strict verification policy, omitting mandatory process or network telemetry triggers an automatic `REJECTED` verdict or `WARNING: Coverage Incomplete`, preventing attackers from evading detection via evidence suppression.

### RQ4: How robust is independent verification against evidence mutation, deletion, replay, and cross-build confusion?
Evaluated against four dedicated adversarial experiments:
- **EXP-11 (Evidence Suppression)**: Attacker strips process/network logs \(\to\) Flagged by Evidence Gap Engine.
- **EXP-12 (Evidence Deletion)**: Attacker deletes SLSA provenance/SBOM \(\to\) Rejected by policy engine.
- **EXP-13 (Evidence Replay)**: Attaching clean Build A evidence to rogue Build B \(\to\) Rejected due to SHA-256 digest contradiction.
- **EXP-14 (Cross-Build Confusion)**: Stitching together mismatched builder IDs and artifacts \(\to\) Rejected by cross-layer correlator.

### RQ5: What is the performance overhead of collecting and correlating multiple evidence layers?
Performance is decomposed into two distinct phases:
- **Telemetry Collection Overhead**: \(0.3\text{ s} - 3.2\text{ s}\) during physical build execution (querying Git, WMI process trees, socket states).
- **Correlation & Decision Latency**: **\(12.5\ \mu\text{s}\) mean latency** in-memory across 1,000 trials, demonstrating that multi-plane correlation introduces negligible overhead to release gates.

### RQ6: Which evidence layers contribute most to detection and localization?
Evaluated via Layer Ablation 2.0 (dropping individual planes):
- Omitting **Dependencies**: Reduces localization accuracy by **30.0%** (down to 70.0%).
- Omitting **Source, Process, Filesystem, or Network**: Increases False Acceptance Rate to **10.0%** for attacks targeting those physical planes.

### RQ7: Can legitimate build variability be distinguished from security-relevant contradictions under explicit policy?
**Yes.** Evaluated against legitimate developer actions:
- Compiler patch updates (`go1.23.5` \(\to\) `go1.23.6`): **`TRUSTED`** (0% False Rejection).
- Build path relocation: **`TRUSTED`** (normalized via path-leakage filters).
- Synchronized lockfile updates: **`TRUSTED`**.
- Unauthorized network egress: **`REJECTED`** (correctly isolated as malicious).

---

## 4. Conclusion

ProvenanceX proves that software supply-chain security cannot rely on build self-attestation. By uniting physical execution telemetry with declared attestations in a formal 12-layer DAG and tamper-evident Merkle log, ProvenanceX provides mathematically verifiable, air-gapped, explainable supply-chain integrity verification.
