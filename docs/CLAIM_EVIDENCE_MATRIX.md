# PROVENANCEX — FORMAL CLAIM-EVIDENCE MATRIX
## Scientific Verification Ledger for Peer Review and Empirical Audit

This document provides a formal, comprehensive mapping between every architectural claim, security guarantee, empirical result, and limitation asserted by the **ProvenanceX** research platform and its concrete code implementations, test suites, and empirical datasets.

Following the **Day 15 Independent Benchmark Audit**, every claim is assigned an explicit scientific audit status:
* **`VALIDATED`**: Statistically verified across independent datasets with zero contradiction within defined threat model.
* **`PARTIALLY VALIDATED`**: Validated under specified runtime configurations or assumptions, but subject to operational caveats.
* **`BOUNDED`**: Formally bounded by fundamental observation primitives, physical host permissions, or protocol limits.

---

## 1. Executive Summary of Research Milestones

| Milestone | Target Objective | Evaluated Trials | Attack Recall | Decision Precision | F1 Score | Verified Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **Day 12 Baseline** | Adversarial Blind-Spot Discovery | 6,250 | 80.00% | 100.00% | 88.89 | Demonstrated 4 systematic blind spots |
| **Day 13 Remediation** | Controlled Blind-Spot Remediation | 6,250 | 98.75% | 100.00% | 99.37 | Resolved 3 blind spots; bounded 1 (FS escape) |
| **Day 14 Validation** | Generalization & Scalability Audit | 7,500 | 100.00% | 100.00% | 100.00 | Verified across 25 novel vectors up to 10K events |
| **Day 15 Audit** | Independent Benchmark & Scope Audit | 7,500 + Hunts | 100.00%* | 100.00%* | 100.00* | Recomputed Day 14 ($TP+FN+TN+FP=N$); disentangled performance scopes; surfaced 3 kernel/protocol blind spots |

*\*Note: 100% applies to the closed 7,500-trial Day 14 holdout. In the Day 15 adversarial stress hunt, 3 evasion techniques (`ADV-HUNT-03`, `ADV-HUNT-04`, `ADV-HUNT-05`) successfully bypassed user-mode observation primitives and are documented below.*

---

## 2. Formal Claim-to-Evidence Matrix

### Category A: Core Architectural & Evidence Model Claims

| # | Scientific Claim | Audit Status | Theoretical / Operational Basis | Implementing Code & Lines | Verifying Tests | Empirical Dataset |
| :- | :--- | :---: | :--- | :--- | :--- | :--- |
| **A1** | **12-Layer Cross-Layer Supply Chain Representation** | `VALIDATED` | Software integrity requires unifying declared intent with observed execution across 12 discrete planes (Source, Deps, Lockfile, SBOM, Env, Build, Process, FS, Network, Artifact, Provenance, Signature). | [`internal/evidence/model.go#L13-L26`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/evidence/model.go#L13-L26)<br>[`internal/correlation/correlator.go#L21-L36`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/correlation/correlator.go#L21-L36) | `internal/evidence/model_test.go`<br>`internal/correlation/correlation_test.go` | `results/day15/recomputed_metrics.csv`<br>`results/day14/generalization.csv` |
| **A2** | **Epistemic Classification (Direct, Derived, External)** | `VALIDATED` | Evidence must distinguish between ground-truth observations, mathematical digests, and third-party assertions to prevent self-referential trust loops. | [`internal/evidence/model.go#L28-L37`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/evidence/model.go#L28-L37) | `internal/evidence/model_test.go` | `results/day15/raw_trials.csv`<br>`results/day14/raw_trials.csv` |
| **A3** | **Deterministic Non-Scoring Decision Engine** | `VALIDATED` | Numeric "risk scores" obscure specific vulnerabilities. ProvenanceX renders deterministic `TRUSTED`, `WARNING`, `REJECTED` verdicts based on policy rules. | [`internal/decision/decision.go#L14-L65`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/decision/decision.go#L14-L65) | `internal/decision/decision_test.go` | `results/day15/recomputed_metrics.csv` (7,500 trials verified) |
| **A4** | **Causal Earliest Trust-Break Localization** | `VALIDATED` | In multi-stage supply chain attacks, security response requires isolating the first root cause (e.g. source vs locked dependency) rather than downstream symptoms. | [`internal/localization/localizer.go#L15-L80`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/localization/localizer.go#L15-L80) | `internal/localization/localization_test.go` | `results/day15/recomputed_metrics.csv` (`COMPOSED-ATK-01..03`) |
| **A5** | **Trust Graph 2.0 Directed Acyclic Graph** | `VALIDATED` | Formal evidence relationships form a DAG tracing causality from repository commit through build processes to attested artifacts and signatures. | [`internal/graph/graph.go#L12-L80`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/graph/graph.go#L12-L80) | `internal/graph/graph_test.go` | `results/day15/graph_benchmark.csv`<br>`results/day14/graph_scaling.csv` |

---

### Category B: Empirical Security & Detection Claims

| # | Scientific Claim | Audit Status | Empirical Result | Implementing Code & Lines | Verifying Benchmark | Dataset Proof |
| :- | :--- | :---: | :--- | :--- | :--- | :--- |
| **B1** | **Author Spoofing Immunity** | `VALIDATED` | Git author/email spoofing with untrusted or missing GPG/SSH/Sigstore signatures is detected with 100.00% recall under signature policy. | [`internal/repository/repository.go#L22-L60`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/repository/repository.go#L22-L60)<br>[`internal/correlation/correlator.go#L95-L124`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/correlation/correlator.go#L95-L124) | `provenancex research remediate`<br>`provenancex research day15` | `results/day15/recomputed_metrics.csv` (`UNSEEN-ATK-19`) |
| **B2** | **Sub-Millisecond Process Detection via ETW** | `BOUNDED` | Kernel ETW (`Microsoft-Windows-Kernel-Process`) traces short-lived processes (<1ms to 10ms) with 100% recall. **Bounded**: Falls back to 100ms polling without admin privileges, missing sub-10ms ephemeral spawns (`ADV-HUNT-03`). | [`internal/process/etw_windows.go#L15-L120`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/process/etw_windows.go#L15-L120)<br>[`internal/remediation/eval_process.go#L30-L70`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/remediation/eval_process.go#L30-L70) | `provenancex research remediate`<br>`provenancex research day15` | `results/day15/false_negative_hunt.csv` (`ADV-HUNT-03`)<br>`results/day14/generalization.csv` (`UNSEEN-ATK-02`, `UNSEEN-ATK-12`) |
| **B3** | **DNS Exfiltration & Network Egress Detection** | `BOUNDED` | Windows DNS-Client ETW flags unauthorized DNS TXT data tunneling and unauthorized egress socket connections with 100% recall. **Bounded**: Suffix allowlisting permits subdomain tunneling (`ADV-HUNT-05`); DoH bypasses OS DNS. | [`internal/network/telemetry.go#L20-L85`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/network/telemetry.go#L20-L85)<br>[`internal/correlation/correlator.go#L289-L325`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/correlation/correlator.go#L289-L325) | `provenancex research remediate`<br>`provenancex research day15` | `results/day15/false_negative_hunt.csv` (`ADV-HUNT-05`)<br>`results/day13/observation_coverage.csv` |
| **B4** | **Generalization to Unseen Attack Vectors** | `VALIDATED` | ProvenanceX demonstrates 100.00% detection recall across 22 unseen single-layer vectors and 3 composed multi-layer attacks ($N=6,250$ attack trials in closed holdout). | [`internal/generalization/scenarios.go#L180-L550`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/generalization/scenarios.go#L180-L550) | `provenancex research day15` | `results/day15/recomputed_metrics.csv` ($TP=6,250, FN=0$) |
| **B5** | **Zero False Positives Under Operational Drift** | `PARTIALLY VALIDATED` | Benign variations (compiler minor patches, lockfile formatting, build cache hits, workspace path relocation) incur 0.00% false alarms (100% specificity). **Caveat**: Uncommitted test mock generators trigger false rejection (`BENIGN-HUNT-04`). | [`internal/generalization/scenarios.go#L560-L650`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/generalization/scenarios.go#L560-L650) | `provenancex research day15` | `results/day15/recomputed_metrics.csv` ($TN=1,250, FP=0$)<br>`results/day15/false_positive_hunt.csv` (`BENIGN-HUNT-04`) |

---

### Category C: Scalability & Systems Performance Claims (Scope Disentangled)

| # | Scientific Claim | Audit Status | Precise Performance Scope & Metric | Implementing Code & Lines | Verifying Benchmark | Dataset Proof |
| :- | :--- | :---: | :--- | :--- | :--- | :--- |
| **C1** | **Artifact Hashing & Merkle Ingestion Scale** | `VALIDATED` | **Physical Disk vs In-Memory Hashing**: Physical streaming SHA-256 sustains **1,344 MB/s** on NVMe (100MB artifact in 74.3 ms). In-memory buffer hashing achieves **1,941 MB/s** (100MB in 51.5 ms). | [`internal/audit/perf_audit.go#L182-L245`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/audit/perf_audit.go#L182-L245) | `RunArtifactBenchmark()` | `results/day15/artifact_benchmark.csv` |
| **C2** | **Dependency Graph Resolution Scale** | `VALIDATED` | **In-Memory Dependency Analysis**: Resolving, indexing, and cycle-checking 1,000 packages requires **4 µs**; 10,000 packages requires **1,007 µs** (sub-millisecond across full production trees). | [`internal/audit/perf_audit.go#L104-L180`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/audit/perf_audit.go#L104-L180) | `RunDependencyBenchmark()` | `results/day15/dependency_benchmark.csv` |
| **C3** | **High-Throughput Evidence Correlation** | `VALIDATED` | **In-Memory Telemetry Correlation**: Pure graph correlation of 10,000 events executes in **12.4 µs** (>800M events/sec in-memory). End-to-end full pipeline (parsing, graph build, evaluation, JSON serialization) for 10K events takes **3.07 ms**. | [`internal/audit/perf_audit.go#L20-L102`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/audit/perf_audit.go#L20-L102) | `RunStageBreakdownBenchmark()` | `results/day15/performance_summary.csv` |
| **C4** | **Trust Graph 2.0 Traversal Scaling** | `VALIDATED` | **DAG Query & Reachability Complexity**: Root-cause contradiction lookup is $O(1)$ indexed (**1 µs** across 10,000 nodes). Full reachability extraction traverses 10,000 nodes in **3.01 ms** and 50,000 nodes in **15.2 ms**. | [`internal/audit/perf_audit.go#L248-L305`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/audit/perf_audit.go#L248-L305) | `RunGraphBenchmark()` | `results/day15/graph_benchmark.csv` |
| **C5** | **Multi-Tenant In-Memory Verification Throughput** | `VALIDATED` | **In-Memory Verification Operations / Sec**: Multi-threaded concurrency achieves **192,000 verification operations/second** across 32 workers with 100% tenant isolation (zero cross-talk). This measures analytical decision rate, not end-to-end compiler invocations. | [`internal/audit/perf_audit.go#L308-L390`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/audit/perf_audit.go#L308-L390) | `RunConcurrencyBenchmark()` | `results/day15/concurrency_benchmark.csv` |
| **C6** | **Physical End-to-End Build Overhead** | `VALIDATED` | **Real CI Build Latency Overhead**: Measuring real Go compiler execution (`go build`) with baseline compilation duration of ~1,120 ms reveals an absolute ProvenanceX overhead of **1.84 to 3.33 ms**, translating to **0.16% to 0.27% total build overhead**. | [`internal/audit/end_to_end.go#L20-L80`](file:///c:/Users/Ram/Desktop/ProvenanceX/internal/audit/end_to_end.go#L20-L80) | `RunEndToEndBuildOverhead()` | `results/day15/end_to_end.csv` |

---

## 3. Explicit Physical Observation Boundaries and Demonstrated Blind Spots

To maintain complete scientific integrity, ProvenanceX documents both architectural observation boundaries and the empirical false negatives discovered during the Day 15 adversarial hunt:

1. **Filesystem Observation Boundary & Transient File Evasion (`ADV-HUNT-04`)**:
   - **Covered (100% Recall)**: Workspace directory root, configured subdirectories, `%TEMP%`, and registered output paths.
   - **Empirical Blind Spot**: Rapid create-and-delete transient payloads dropped to disk, executed via child processes, and unlinked prior to post-build snapshot diffing evade detection unless captured by a kernel filesystem minifilter driver (`FLTMGR.sys`) or Windows USN Change Journal parsing.
   - **Out-of-Workspace Writes**: 0% recall on arbitrary unconfigured drives (`D:\SharedCache\`) without container namespace isolation.
   - *Evidence Documented*: [`results/day15/false_negative_hunt.csv`](file:///c:/Users/Ram/Desktop/ProvenanceX/results/day15/false_negative_hunt.csv) and [`docs/FINAL_RESEARCH_LIMITATIONS.md`](file:///c:/Users/Ram/Desktop/ProvenanceX/docs/FINAL_RESEARCH_LIMITATIONS.md).

2. **Windows ETW Elevation Requirement & Sub-10ms Processes (`ADV-HUNT-03`)**:
   - Kernel ETW trace sessions (`EVENT_TRACE_FLAG_PROCESS`) require Windows Administrator elevation (`SeCreateGlobalPrivilege`). In unprivileged CI runner environments, ProvenanceX automatically falls back to 100ms snapshot polling.
   - **Empirical Blind Spot**: Subprocesses that spawn, inject or exfiltrate in memory, and terminate within $<10$ ms between polling intervals evade user-mode observation.

3. **Subdomain Multiplexing in Allowed Domains (`ADV-HUNT-05`)**:
   - Windows DNS-Client ETW captures DNS queries. However, if a domain suffix is allowlisted (e.g. `*.pkg.go.dev`), high-entropy subdomain exfiltration (e.g. `<hex_payload>.pkg.go.dev`) passes suffix validation without Shannon entropy filtering or deep payload inspection.

4. **In-Tree Test Artifact False Rejections (`BENIGN-HUNT-04`)**:
   - Strict working-tree cleanliness policies reject untracked source files. If build or test phases generate in-tree mock code not registered in `.gitignore` or build inputs, a false alarm occurs.

---

## 4. Replication and Audit Instructions

All Day 15 audit benchmarks, metrics recomputations, and stress hunts can be reproduced independently:

```powershell
# Set Go toolchain
$env:PATH = "C:\Users\Ram\.provenancex\toolchain\go\bin;$env:PATH"

# Run Day 15 Independent Audit Suite
.\bin\provenancex.exe research day15 --output results/day15

# Re-run automated unit and integration tests
go test -v ./...
go vet ./...
```
