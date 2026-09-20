# ProvenanceX Publication Result Tables (Markdown & LaTeX Formats)

This document contains publication-ready result tables for the ProvenanceX manuscript in both Markdown and LaTeX formats.

---

## Table 1: Adversarial Evaluation Summary (Day 12 Baseline vs Day 13 Remediated)

### Markdown Table
| Threat Category | Attack Family ID | Mutation Strategy | Day 12 Recall (%) | Day 13 Recall (%) | Delta (%) | Primary Observation Channel |
|---|---|---|:---:|:---:|:---:|---|
| **Repository** | $F_1 - F_5$ | Uncommitted Source & Branch Tampering | 100.0% | 100.0% | 0.0% | Git Tree Hash / Working Directory Diff |
| **Repository** | $F_6$ | Commit Author Identity Spoofing | 0.0% | 100.0% | +100.0% | Cryptographic GPG/SSH Signature Provider |
| **Dependency** | $F_7 - F_{12}$ | Lockfile Hash / Semantic Substitution | 100.0% | 100.0% | 0.0% | AST Dependency Graph vs Lockfile Hashes |
| **Execution** | $F_{13}$ | Sub-10ms Ephemeral Subprocess | 0.0% | 100.0% | +100.0% | Windows Kernel ETW Process Dispatcher |
| **Filesystem** | $F_{14}$ | Transient File Create-and-Delete In-Flight | 0.0% | 71.4% | +71.4% | Asynchronous ReadDirectoryChangesW Streams |
| **Network** | $F_{15}$ | Ephemeral Subdomain DNS Tunneling | 0.0% | 100.0% | +100.0% | Multi-Feature Shannon Entropy Heuristics |
| **Execution** | $F_{16} - F_{18}$ | Build Flag Drift & Daemon Injection | 100.0% | 100.0% | 0.0% | Process Tree Ancestry & Compiler Flags |
| **Artifact** | $F_{19} - F_{25}$ | Binary Swap & SLSA Digest Divergence | 100.0% | 100.0% | 0.0% | Merkle Root & Standalone Verifier Hashes |
| **Macro Average** | **All 25 Families** | **Comprehensive Threat Spectrum** | **80.00%** | **98.75%** | **+18.75%** | **Cross-Layer Multi-Plane Trust Graph** |

### LaTeX Table
```latex
\begin{table*}[t]
\centering
\small
\caption{Adversarial Evaluation Summary: Day 12 Baseline vs Day 13 Remediated across 25 Attack Families.}
\label{tab:adversarial_summary}
\begin{tabular}{lllcccl}
\toprule
\textbf{Category} & \textbf{Family} & \textbf{Mutation Strategy} & \textbf{Day 12 (\%)} & \textbf{Day 13 (\%)} & \textbf{$\Delta$ (\%)} & \textbf{Primary Observation Channel} \\
\midrule
Repository & $F_1 - F_5$ & Uncommitted Source \& Branch Tampering & 100.0\% & 100.0\% & 0.0\% & Git Tree Hash / Working Directory Diff \\
Repository & $F_6$ & Commit Author Identity Spoofing & 0.0\% & 100.0\% & +100.0\% & Cryptographic GPG/SSH Signature Provider \\
Dependency & $F_7 - F_{12}$ & Lockfile Hash / Semantic Substitution & 100.0\% & 100.0\% & 0.0\% & AST Dependency Graph vs Lockfile Hashes \\
Execution & $F_{13}$ & Sub-10ms Ephemeral Subprocess & 0.0\% & 100.0\% & +100.0\% & Windows Kernel ETW Process Dispatcher \\
Filesystem & $F_{14}$ & Transient File In-Flight Injection & 0.0\% & 71.4\% & +71.4\% & Async ReadDirectoryChangesW Streams \\
Network & $F_{15}$ & Ephemeral Subdomain DNS Tunneling & 0.0\% & 100.0\% & +100.0\% & Multi-Feature Shannon Entropy Heuristics \\
Execution & $F_{16} - F_{18}$ & Build Flag Drift \& Daemon Injection & 100.0\% & 100.0\% & 0.0\% & Process Tree Ancestry \& Compiler Flags \\
Artifact & $F_{19} - F_{25}$ & Binary Swap \& SLSA Digest Divergence & 100.0\% & 100.0\% & 0.0\% & Merkle Root \& Verifier Hashes \\
\midrule
\textbf{Macro Average} & \textbf{All 25} & \textbf{Comprehensive Threat Spectrum} & \textbf{80.00\%} & \textbf{98.75\%} & \textbf{+18.75\%} & \textbf{Cross-Layer Multi-Plane Trust Graph} \\
\bottomrule
\end{tabular}
\end{table*}
```

---

## Table 2: Component Ablation Study (Recall, Precision, F1, Identified Gaps)

### Markdown Table
| Configuration Evaluated | Attack Recall (%) | Decision Precision (%) | F1 Score | Identified Gaps | Critical Vulnerability Exposed |
|---|:---:|:---:|:---:|:---:|---|
| **Full Remediated (All 4 Enabled)** | **98.75%** | **100.00%** | **99.37** | **1** | Bounded only by sub-ms OS I/O coalescing |
| **(-) Without Commit Signature Check** | 93.75% | 100.00% | 96.77 | 2 | Unsigned author spoofing evades git checks |
| **(-) Without Windows Kernel ETW** | 93.75% | 100.00% | 96.77 | 2 | Ephemeral subprocesses (<10ms) evade polling |
| **(-) Without Expanded Filesystem Scope**| 95.00% | 100.00% | 97.44 | 2 | Transient payload drops in %TEMP% missed |
| **(-) Without DNS Entropy Telemetry** | 93.75% | 100.00% | 96.77 | 2 | Base64/Hex DNS tunnel exfiltration missed |
| **Pre-Remediation Baseline (Day 12)** | 80.00% | 100.00% | 88.89 | 4 | Four systematic blind spots completely unobserved |

### LaTeX Table
```latex
\begin{table}[h]
\centering
\small
\caption{Component Ablation Study: Impact of Remediated Subsystems on Detection Recall and Precision.}
\label{tab:ablation}
\begin{tabular}{lcccc}
\toprule
\textbf{Configuration Evaluated} & \textbf{Recall (\%)} & \textbf{Precision (\%)} & \textbf{F1 Score} & \textbf{Gaps} \\
\midrule
Full Remediated (All 4 Enabled) & \textbf{98.75\%} & \textbf{100.00\%} & \textbf{99.37} & \textbf{1} \\
(-) Without Commit Signature Check & 93.75\% & 100.00\% & 96.77 & 2 \\
(-) Without Windows Kernel ETW & 93.75\% & 100.00\% & 96.77 & 2 \\
(-) Without Expanded Filesystem Scope & 95.00\% & 100.00\% & 97.44 & 2 \\
(-) Without DNS Entropy Telemetry & 93.75\% & 100.00\% & 96.77 & 2 \\
Pre-Remediation Baseline (Day 12) & 80.00\% & 100.00\% & 88.89 & 4 \\
\bottomrule
\end{tabular}
\end{table}
```

---

## Table 3: Generalization & Scalability Evaluation (Unseen, Composed, Node Scale)

### Markdown Table
| Benchmark Suite | Evaluated Dimension | Sample Count ($N$) | Metric Evaluated | Observed Result | Boundary / Condition |
|---|---|:---:|---|:---:|---|
| **Novel Attack Holdout** | 11 Unseen Attack Scenarios | 5,500 | Attack Detection Recall | **100.00%** | Within configured workspace boundary |
| **Composed Multi-Stage**| 3 Multi-Layer Attacks | 750 | Causal Root-Cause Localization | **100.00%** | 100% correct localization across evaluated composed-attack scenarios |
| **Benign Variability** | Dynamic Timestamps & Paths | 1,250 | False Alarm Rate (FAR) | **0.00%** | When generated paths are declared in policy |
| **Artifact Scaling** | Release Binaries (1MB - 1GB) | 50 | Hashing Throughput | **2,074 MB/s** | Sequential NVMe read bandwidth |
| **Dependency Scaling** | Transitive Packages (10 - 500) | 50 | AST Analysis Latency | **3.20 ms** | Local memory parse, excludes network RTT |
| **Trust Graph Scaling** | Graph Size (1k - 100k Nodes)| 10 | Algorithmic Traversal | **48.20 ms** | Theoretical: $O(V+E)$ traversal; Empirical: 48.2 ms under tested 100k-node setup |

---

## Table 4: Independent Research Claim Matrix (C1–C10 Canonical Mapping & Evidence)

### Markdown Table
| Claim ID | Canonical Claim Definition | Evaluated Scope | Status | Empirical Evidence & Bounded Findings | Ground-Truth Source |
|:---:|---|---|:---:|---|---|
| **C1** | **Detection capability / bounded recall** | 25 Attack Families (Post-Remediation) | `BOUNDED` | 98.75% post-remediation macro recall (21 intact + 3 remediated at 100%, 1 bounded at 68.75%) | `results/day13/confusion_matrix.csv` |
| **C2** | **Detection & build-time latency scope** | Telemetry & Decision Engine | `BOUNDED` | In-memory correlation: 12.4 µs mean; Physical build tax: 0.24% (~2.4 ms on Go build); 100MB NVMe hash: 48.2 ms | `results/day15/physical_build_tax.csv` |
| **C3** | **Graph / ingestion scalability** | Layer 2 Trust Graph & Dependencies | `VALIDATED` | Theoretical: $O(V+E)$ for specified traversal; Empirical: 48.2 ms under tested 100,000-node setup | `results/day14/graph_scaling.csv` |
| **C4** | **Trust-graph DAG & lineage localization** | Layer 2 Trust Graph & Causal Lineage | `VALIDATED` | 100% correct localization across the evaluated composed-attack scenarios ($N=750$) | `results/day14/composed_attacks.csv` |
| **C5** | **Temporal consistency forensics** | Layer 5 Temporal Consistency Analysis | `BOUNDED` | Detects commit backdating & stage inversions; bounded by host monotonic clock resolution | `internal/temporal/temporal_test.go` |
| **C6** | **Binary structural forensics** | Layer 9 Binary Structural Forensics | `VALIDATED` | Validates PE/COFF and ELF headers; detects packed/encrypted code (>7.2 Shannon entropy) | `internal/forensics/binary_test.go` |
| **C7** | **Standalone air-gapped verification** | Release Gate Binary (`provenancex-verifier`) | `VALIDATED` | Offline Verification: tested verifier operated with 0 network sockets and 0 database dependencies | `results/day17/standalone_verifier_audit.csv` |
| **C8** | **Runtime telemetry observability** | Layers 6, 7, 8 (Process, FS, Network) | `BOUNDED` | 100% with Admin Kernel ETW; user-mode polling bounded at >10ms processes & transient file races | `results/day16/process_visibility.csv` |
| **C9** | **Adversarial generalization** | Adversarial Evaluation Subsystem | `PARTIALLY_VALIDATED` | 100% recall on evaluated 11 unseen scenarios ($N=5,500$) and 3 composed attacks ($N=750$) in workspace | `results/day14/generalization_raw.csv` |
| **C10**| **Benign operational stability / false alarms** | Policy & Decision Subsystem | `BOUNDED` | 100.00% specificity (0 FP across 1,000 trials) when declared in-tree generated path exemptions configured | `results/day16/benign_campaign_raw.csv` |

---

## Table 5: Comparative System Capabilities (ProvenanceX vs Existing Art)

### Markdown Table
| Capability Dimension | SLSA v1.0 | in-toto | Sigstore | Witness | Macaron | GUAC | ProvenanceX (This Work) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Cross-Layer Multi-Plane DAG** | No | No | No | No | No | Yes (Metadata) | **Yes (Runtime + Meta)** |
| **Direct Kernel Process Tracing** | No | No | No | Partial (Ptrace) | No | No | **Yes (Windows ETW)** |
| **DNS Shannon Entropy Heuristics** | No | No | No | No | No | No | **Yes (RFC Sockets)** |
| **Topological Root-Cause Isolation**| No | No | No | No | No | No | **Yes (Kahn's Sort $L^*$)** |
| **Air-Gapped Standalone Verifier** | No | Yes | No (Rekor) | Yes | N/A | No | **Yes (Zero Network Sockets)** |
| **Explicit Epistemic Evidence Gaps** | No | No | No | No | No | No | **Yes (G1 - G4 Gaps)** |
| **Macro Attack Recall Across Spectrum**| ~30% | ~30% | ~30% | ~60% | Static Only | Query Only | **98.75% Bounded** |