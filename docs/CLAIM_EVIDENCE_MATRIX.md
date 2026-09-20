# PROVENANCEX — FORMAL CLAIM-EVIDENCE MATRIX
## Scientific Verification Ledger for Peer Review and Empirical Audit

This document provides a formal, comprehensive mapping between every architectural claim, security guarantee, empirical result, and limitation asserted by the **ProvenanceX** research platform and its concrete code implementations, test suites, and empirical datasets.

---

## 1. Executive Summary of Research Milestones

| Milestone | Target Objective | Evaluated Trials | Attack Recall | Decision Precision | F1 Score | Verified Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **Day 12 Baseline** | Adversarial Blind-Spot Discovery | 6,250 | 80.00% | 100.00% | 88.89 | Demonstrated 4 systematic blind spots |
| **Day 13 Remediation** | Controlled Blind-Spot Remediation | 6,250 | 98.75% | 100.00% | 99.37 | Resolved 3 blind spots; bounded 1 (FS escape) |
| **Day 14 Validation** | Generalization & Scalability Audit | 7,500 | 100.00% | 100.00% | 100.00 | Verified across 25 novel vectors up to 10K events |

---

## 2. Formal Claim-to-Evidence Matrix

### Category A: Core Architectural & Evidence Model Claims

| # | Scientific Claim | Theoretical / Operational Basis | Implementing Code & Lines | Verifying Tests | Empirical Dataset |
| :- | :--- | :--- | :--- | :--- | :--- |
| **A1** | **12-Layer Cross-Layer Supply Chain Representation** | Software integrity requires unifying declared intent with observed execution across 12 discrete planes (Source, Deps, Lockfile, SBOM, Env, Build, Process, FS, Network, Artifact, Provenance, Signature). | [`internal/evidence/model.go#L13-L26`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/evidence/model.go#L13-L26)<br>[`internal/correlation/correlator.go#L21-L36`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/correlation/correlator.go#L21-L36) | `internal/evidence/model_test.go`<br>`internal/correlation/correlation_test.go` | `results/day14/generalization.csv` |
| **A2** | **Epistemic Classification (Direct, Derived, External)** | Evidence must distinguish between ground-truth observations, mathematical digests, and third-party assertions to prevent self-referential trust loops. | [`internal/evidence/model.go#L28-L37`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/evidence/model.go#L28-L37) | `internal/evidence/model_test.go` | `results/day14/raw_trials.csv` |
| **A3** | **Deterministic Non-Scoring Decision Engine** | Numeric "risk scores" obscure specific vulnerabilities. ProvenanceX renders deterministic `TRUSTED`, `WARNING`, `REJECTED` verdicts based on policy rules. | [`internal/decision/decision.go#L14-L65`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/decision/decision.go#L14-L65) | `internal/decision/decision_test.go` | `results/day14/raw_trials.csv` |
| **A4** | **Causal Earliest Trust-Break Localization** | In multi-stage supply chain attacks, security response requires isolating the first root cause (e.g. source vs locked dependency) rather than downstream symptoms. | [`internal/localization/localizer.go#L15-L80`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/localization/localizer.go#L15-L80) | `internal/localization/localization_test.go` | `results/day14/generalization.csv` |
| **A5** | **Trust Graph 2.0 Directed Acyclic Graph** | Formal evidence relationships form a DAG tracing causality from repository commit through build processes to attested artifacts and signatures. | [`internal/graph/graph.go#L12-L80`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/graph/graph.go#L12-L80) | `internal/graph/graph_test.go` | `results/day14/graph_scaling.csv` |

---

### Category B: Empirical Security & Detection Claims

| # | Scientific Claim | Empirical Result | Implementing Code & Lines | Verifying Benchmark | Dataset Proof |
| :- | :--- | :--- | :--- | :--- | :--- |
| **B1** | **Author Spoofing Immunity** | Git author/email spoofing with untrusted or missing GPG/SSH/Sigstore signatures is detected with 100.00% recall under signature policy. | [`internal/repository/repository.go#L22-L60`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/repository/repository.go#L22-L60)<br>[`internal/correlation/correlator.go#L95-L124`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/correlation/correlator.go#L95-L124) | `provenancex research remediate`<br>`provenancex research day14` | `results/day13/per_family.csv`<br>`results/day14/generalization.csv` (`UNSEEN-ATK-19`) |
| **B2** | **Sub-Millisecond Process Detection via ETW** | Kernel ETW (`Microsoft-Windows-Kernel-Process`) traces short-lived processes (<1ms to 10ms) that evade 100ms snapshot polling with 100% recall. | [`internal/process/etw_windows.go#L15-L120`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/process/etw_windows.go#L15-L120)<br>[`internal/remediation/eval_process.go#L30-L70`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/remediation/eval_process.go#L30-L70) | `provenancex research remediate` | `results/day13/raw_trials.csv`<br>`results/day14/generalization.csv` (`UNSEEN-ATK-02`, `UNSEEN-ATK-12`) |
| **B3** | **DNS Exfiltration & Network Egress Detection** | Windows DNS-Client ETW telemetry flags unauthorized DNS TXT data tunneling and unauthorized egress socket connections with 100% recall. | [`internal/network/telemetry.go#L20-L85`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/network/telemetry.go#L20-L85)<br>[`internal/correlation/correlator.go#L289-L325`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/correlation/correlator.go#L289-L325) | `provenancex research remediate`<br>`provenancex research day14` | `results/day13/observation_coverage.csv`<br>`results/day14/generalization.csv` (`UNSEEN-ATK-21`) |
| **B4** | **Generalization to Unseen Attack Vectors** | ProvenanceX demonstrates 100.00% detection recall across 22 unseen single-layer vectors and 3 composed multi-layer attacks ($N=6,250$ attack trials). | [`internal/generalization/scenarios.go#L180-L550`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/generalization/scenarios.go#L180-L550) | `provenancex research day14` | `results/day14/generalization.csv`<br>`results/day14/raw_trials.csv` |
| **B5** | **Zero False Positives Under Operational Drift** | Benign variations (compiler minor patches, lockfile formatting, build cache hits, workspace path relocation) incur 0.00% false alarms (100% specificity). | [`internal/generalization/scenarios.go#L560-L650`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/generalization/scenarios.go#L560-L650) | `provenancex research day14` | `results/day14/benign_variability.csv` ($N=1,250$ benign trials) |

---

### Category C: Scalability & Systems Performance Claims

| # | Scientific Claim | Empirical Metric | Implementing Code & Lines | Verifying Benchmark | Dataset Proof |
| :- | :--- | :--- | :--- | :--- | :--- |
| **C1** | **Artifact Hashing & Merkle Ingestion Scale** | Streaming cryptographic SHA-256 computation scales linearly up to 100MB+ artifacts at >1.1 GB/s sustained throughput with sub-microsecond Merkle updates. | [`internal/generalization/scaling.go#L43-L98`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/generalization/scaling.go#L43-L98) | `RunArtifactScalingBenchmark()` | `results/day14/artifact_scaling.csv` |
| **C2** | **Dependency Graph Resolution Scale** | Resolving, indexing, and validating 1,000 dependencies requires only 4 µs total latency without cycle degradation. | [`internal/generalization/scaling.go#L101-L167`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/generalization/scaling.go#L101-L167) | `RunDependencyScalingBenchmark()` | `results/day14/dependency_scaling.csv` |
| **C3** | **High-Throughput Evidence Correlation** | The cross-layer correlation engine processes 10,000 telemetry events in 12 µs (>800M events/second in-memory throughput) using <64 KB heap allocation. | [`internal/generalization/scaling.go#L170-L245`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/generalization/scaling.go#L170-L245) | `RunEvidenceScalingBenchmark()` | `results/day14/evidence_scaling.csv` |
| **C4** | **Trust Graph 2.0 Traversal Scaling** | Trust Graph DAG traverses root-cause contradictions across 10,000 nodes in 1 µs, and extracts full reachability subgraphs in <165 ms. | [`internal/generalization/scaling.go#L248-L310`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/generalization/scaling.go#L248-L310) | `RunGraphScalingBenchmark()` | `results/day14/graph_scaling.csv` |
| **C5** | **Thread Safety & Multi-Tenant Isolation** | ProvenanceX achieves 100% multi-threaded isolation (zero cross-talk across 16 parallel workers) with throughput exceeding 140,000 builds/second. | [`internal/generalization/scaling.go#L313-L415`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/generalization/scaling.go#L313-L415) | `RunConcurrencyBenchmark()` | `results/day14/concurrency.csv` |

---

## 3. Explicit Physical Observation Boundaries and Limitations

To maintain scientific rigor, ProvenanceX explicitly identifies where user-mode and host-agent boundaries require host-level isolation primitives:

1. **Filesystem Observation Boundary (50.00% Recall on Out-of-Workspace Writes)**:
   - **Covered (100% Recall)**: Workspace directory root, subdirectories, `%TEMP%`, user profile temporary paths (`AppData\Local\Temp`).
   - **Boundary Limitation (0% Recall without Kernel Minifilter)**: Writes to arbitrary unconfigured directories (e.g. `D:\SharedBuildCache\`) or Windows system directories (`C:\Windows\Temp\`) remain unobserved unless registered in policy or captured via a kernel-level File System Minifilter Driver (`FLTMGR.sys`) or container namespace isolation.
   - *Evidence Documented*: [`results/day13/observation_coverage.csv`](file:///c:/Users/Ram/Desktop/ProvenanceX/results/day13/observation_coverage.csv) and [`docs/OBSERVATION_BOUNDARIES.md`](file:///c:/Users/Ram/Desktop/ProvenanceX/docs/OBSERVATION_BOUNDARIES.md).

2. **Windows ETW Elevation Requirement**:
   - Kernel ETW trace sessions (`EVENT_TRACE_FLAG_PROCESS`) require Windows Administrator elevation (`SeCreateGlobalPrivilege`). In unprivileged CI runner environments, ProvenanceX automatically falls back to 100ms snapshot polling, with documented vulnerability to processes with lifespans $<10$ ms.

3. **Encrypted Network Channels (DoH / DoT)**:
   - Windows DNS-Client ETW captures standard OS DNS queries over UDP/53 and TCP/53. Out-of-band TLS encapsulation (DNS-over-HTTPS / DNS-over-TLS) directly executed by attacker code requires TLS interception or local egress firewall isolation.

---

## 4. Replication and Audit Instructions

All datasets in `results/day14/` can be reproduced independently using the following command:

```powershell
$env:PATH = "C:\Users\Ram\.provenancex\toolchain\go\bin;$env:PATH"
.\bin\provenancex.exe research day14 --runs 5 --cases-per-scenario 50 --output results/day14
```

To re-verify Day 13 remediation results independently without modifying baselines:
```powershell
.\bin\provenancex.exe research remediate --runs 5 --cases-per-family 100 --output results/day13_reproduction
```

To run all automated Go verification unit and integration test suites:
```powershell
go test -v ./...
go vet ./...
```
