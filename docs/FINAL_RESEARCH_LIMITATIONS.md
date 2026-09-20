# PROVENANCEX — COMPREHENSIVE RESEARCH LIMITATIONS
## Systematic Vulnerability & Boundary Ledger for Academic Scrutiny

This document details the exact boundary conditions, structural assumptions, and physical limits of the **ProvenanceX** verification platform. In adherence to research integrity, these limitations must be explicitly cited in any peer-reviewed paper or production deployment assessment.

---

## 1. Ephemeral Process Visibility & Privilege Requirements (ADV-HUNT-03)
- **Privilege Boundary**: Windows Kernel Event Tracing (ETW) via `Microsoft-Windows-Kernel-Process` requires Administrator elevation (`SeCreateGlobalPrivilege`).
- **Telemetry Breakdown Across Evaluated Modes**:
  - **Mode A (Standard 100ms Polling)**: Captures only processes with lifetimes $\ge 100\text{ ms}$ (**25.00% overall lifetime coverage**). Processes executing and exiting under 100ms disappear between polling ticks without detection.
  - **Mode B (Administrator Kernel ETW)**: Captures 100.00% of process starts and exits down to sub-millisecond execution (<1ms).
  - **Mode C (Unprivileged User-Mode High-Frequency / Job Object)**: Captures processes with lifetimes $\ge 10\text{ ms}$ (**62.50% overall lifetime coverage**).
- **Physical Boundary**: Due to Windows non-realtime OS scheduler quantization (default timer interrupt frequency ~15.6 ms), unprivileged user-mode collectors cannot guarantee capture of subprocesses executing in $<10\text{ ms}$.

## 2. Transient Filesystem Activity: Final State vs Event Streaming (ADV-HUNT-04)
- **Final State Observation Boundary**: Snapshot/delta comparison models only evaluate the *final state* of the filesystem. If an adversary drops a payload, executes it, and unlinks it prior to post-build snapshot creation, final state diffing sees **0.00% recall**, regardless of payload execution duration.
- **Event Observation Coverage**: Real-time asynchronous directory change notifications (`ReadDirectoryChangesW`) improve event-level visibility to **71.43%**, capturing create, write, and delete events for files persisting $\ge 5\text{ ms}$.
- **Remaining Limitations**:
  - **Buffer Coalescing**: Files created and deleted within $<5\text{ ms}$ can be coalesced by the Windows I/O subsystem or dropped if user-mode notification buffers overflow.
  - **Attribution Gap**: User-mode filesystem change notifications report file paths and action types, but do NOT provide the originating process PID or command line without a kernel-level File System Minifilter driver (`FLTMGR.sys`).
  - **Unconfigured Volume Escape**: Monitoring is bounded to declared directories (workspace root, `%TEMP%`). Writes to arbitrary unmonitored drives (e.g. `D:\SharedCache\`) remain invisible.

## 3. Subdomain DNS Tunneling & Lexical Heuristic Bounds (ADV-HUNT-05)
- **Suffix Allowlist Vulnerability**: Domain allowlists verifying suffixes (e.g. `*.pkg.go.dev`) permit arbitrary data exfiltration if the adversary multiplexes data inside subdomain labels.
- **Heuristic Remediation & Bounds**: ProvenanceX incorporates multi-feature heuristics (Shannon entropy $>3.65$, label length $>32$, hex/base ratio $>0.85$, label depth $>4$) achieving **80.00% standalone detection** and **100.00% detection when correlated with execution anomalies**.
- **Remaining Limitations**:
  - **Dictionary-Word Evasion**: Adversaries encoding exfiltrated data into sequences of valid English dictionary words (low Shannon entropy, normal lengths) bypass lexical heuristics in isolation.
  - **Encrypted DNS (DoH/DoT)**: Queries encapsulated in TLS and routed directly over TCP/443 bypass standard OS DNS-Client ETW and UDP/53 inspection, requiring network firewall egress isolation.

## 4. In-Tree Generated Artifacts & Policy Ambiguity (BENIGN-HUNT-04)
- **Operational Reality**: Strict working-tree cleanliness policies (`require_clean_state: true`) flag legitimate uncommitted files created during build or test execution (e.g., unit test mocks, protobuf stubs) as unauthorized tampering.
- **Remediation & Governance**: ProvenanceX provides declared intermediate path matching (`policy.Repository.DeclaredGeneratedPaths`), reducing false positives to **0.00%** across 1,000 benign trials while preserving 100% rejection on undeclared files.
- **Remaining Limitation**: Requires explicit policy declaration. Blanket wildcard ignore rules (e.g. ignoring all `.go` files created in subdirectories) create an attacker loophole and are strictly forbidden.

## 5. ETW Buffer Sizing & Event Dropping Under Extreme Load
- **Event Loss**: Under extreme kernel context switching ($>500,000$ events/second), ETW ring buffers can drop events if consumer throughput is saturated.
- **Impact**: Dropped process termination or image load events can cause temporary causal ambiguity in the process tree hierarchy.

## 6. Dependency Benchmark Scope (In-Memory vs Remote Resolvers)
- **Scope Distinction**: The $\le 4$ µs dependency scaling benchmark measures in-memory lockfile parsing, AST indexing, graph traversal, and cycle detection.
- **Exclusion**: It does NOT include physical network round-trip time (RTT) to remote registries (PyPI, npmjs, Go proxy) or remote package tarball downloads.

## 7. Evidence Volume Benchmark Scope (In-Memory vs Network I/O)
- **Scope Distinction**: The 10,000-event in-memory correlation latency (12–25 µs) measures pure cross-layer rule evaluation and state comparison on pre-ingested structs.
- **Exclusion**: It does NOT include remote syslog streaming, disk log file tailing, or external JSON deserialization overhead.

## 8. Synthetic Microbenchmarks vs Real Physical Builds
- **Disentanglement**: In-memory microbenchmarks execute in microseconds. However, an actual end-to-end Go or C++ build takes hundreds of milliseconds or seconds due to disk I/O, process compilation, and linker operations.
- **Measured Reality**: On actual compilations, ProvenanceX adds **0.16% to 0.27%** overhead (2.0–2.5 ms) to the physical build pipeline.

## 9. Test Environment & Operating System Constraints
- **Platform Specifics**: Advanced process and network telemetry implementations utilize Windows-native Win32 API and ETW sessions. On Linux, eBPF / auditd collectors provide equivalent capabilities but possess distinct kernel version dependencies (Linux kernel $\ge 5.8$ for CO-RE eBPF).

## 10. Attack-Family Boundary Conditions
- **Threat Model Scope**: ProvenanceX is designed to detect discrepancies between declared build metadata and observed execution behavior.
- **Out of Scope**: Zero-day hardware side-channels (Spectre/Meltdown), hypervisor compromise, kernel rootkits that hook ETW dispatch tables, and firmware-level supply chain modifications.

## 11. Generalization Scope (Tested vs Universal Vectors)
- **No Universal Detection**: ProvenanceX achieved high recall across evaluated attack scenarios, but this applies strictly to the tested parameter spaces and modeled layers. Novel multi-stage attacks exploiting unmonitored OS primitives can achieve evasion.

## 12. Concurrency Benchmark Semantic Definition
- **Metric Definition**: The 160,000+ operations/sec concurrency benchmark represents **in-memory cross-layer verification operations per second** across isolated goroutines, NOT full compilation and disk linking of distinct physical codebases.

## 13. Hardware Dependence of Microsecond Latencies
- **Hardware Skew**: Microsecond latencies depend heavily on CPU clock speed, L1/L2 cache locality, and OS thread scheduling. On constrained virtualized CI runners, latency percentiles (P95/P99) may experience jitter up to 50–100 µs.

## 14. Inability to Infer Adversary Attribution Solely from Evidence
- **Attribution Limit**: Cross-layer evidence identifies *what* broke, *where* it broke, and *which layer* failed first. It does NOT identify *who* initiated the attack (e.g., distinguishing state-sponsored APTs from automated credential stuffing) without external threat intelligence feeds.

## 15. Inability to Guarantee Universal Attack Prevention
- **Observation vs Enforcement**: ProvenanceX is an audit, correlation, and decision platform. While it renders deterministic `REJECTED` verdicts to halt CI/CD deployment gates, it cannot physically prevent a rogue process from executing in real time without kernel-level inline prevention hooks (EDR/AV).

## 16. User-Mode vs Kernel-Mode Telemetry Trade-Offs
- **User-Mode Safety**: Operating in user-mode avoids host blue-screens (BSODs), kernel version lock-in, and signing requirements. However, it concedes visibility into sub-10ms processes, coalesced transient file I/O, and raw packet manipulation.
- **Kernel-Mode Requirement**: Production environments demanding 100% capture of transient attacks must deploy elevated daemons utilizing Windows Kernel ETW and File System Minifilters.

## 17. Coalescing in OS Notification Buffers
- When hundreds of files are rapidly created and destroyed in quick succession within the same directory, Windows directory change notification queues can experience buffer overflow (`ERROR_NOTIFY_ENUM_DIR`), causing individual transient event drops.

## 18. Cross-Layer Causal Correlation vs Single-Layer Heuristics
- Single-layer heuristics (such as DNS Shannon entropy or process execution speed) are inherently noisy when evaluated in isolation. ProvenanceX relies on cross-layer correlation—requiring corroboration across multiple planes before issuing fatal rejection verdicts, thereby minimizing operational disruption.

---

## 19. Day 17 Audited Observability & Limitation Ledger

The complete Day 17 independent audit (`results/day17/observability_audit.csv`) confirms and formally records all 18 limitations above. In academic publications and industrial security reviews, ProvenanceX must be represented with these exact boundaries. Absolute claims of unassisted 100% detection or zero false positives across arbitrary environments are formally rejected.
