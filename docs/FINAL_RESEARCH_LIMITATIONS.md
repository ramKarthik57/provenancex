# PROVENANCEX — COMPREHENSIVE RESEARCH LIMITATIONS
## Systematic Vulnerability & Boundary Ledger for Academic Scrutiny

This document details the exact boundary conditions, structural assumptions, and physical limits of the **ProvenanceX** verification platform. In adherence to research integrity, these limitations must be explicitly cited in any peer-reviewed paper or production deployment assessment.

---

## 1. Windows Elevation & Kernel Privilege Requirements
- **Privilege Boundary**: Windows Kernel Event Tracing (ETW) via `Microsoft-Windows-Kernel-Process` requires Administrator elevation (`SeCreateGlobalPrivilege`).
- **Degradation**: In standard unprivileged CI/CD runner containers (e.g. unprivileged GitHub Actions runners or low-integrity agent tokens), ProvenanceX automatically falls back to Toolhelp32/WMI snapshot polling.
- **Empirical Impact**: Under polling fallback, short-lived subprocesses executing in $<10$ ms remain unobserved.

## 2. ETW Buffer & Event Dropping Under Heavy Load
- **Event Loss**: Under extreme kernel context switching ($>500,000$ events/second), ETW ring buffers can drop events if consumer throughput is saturated.
- **Impact**: Dropped process termination or image load events can cause temporary causal ambiguity in the process tree hierarchy.

## 3. Physical Filesystem Observation Boundaries
- **Monitored Scope**: Controlled workspace root, immediate auxiliary directories (`%TEMP%`, user temporary paths).
- **Unconfigured Path Escape**: Writes directed to arbitrary unmonitored volumes (e.g. `D:\SharedBuildCache\`) or Windows system folders (`C:\Windows\Temp\`) are missed without kernel minifilter drivers (`FLTMGR.sys`).
- **Rapid Create/Delete Race**: Payloads that drop a script into `%TEMP%`, execute it within milliseconds, and unlink it prior to boundary polling can escape snapshot-based filesystem comparison.

## 4. Encrypted Network Channels (DoH / DoT) & Domain Multiplexing
- **Encrypted DNS**: Windows DNS-Client ETW captures OS-native UDP/53 and TCP/53 resolution. If malware carries an embedded TLS-over-HTTPS client executing DoH directly to Cloudflare/Google over port 443, standard DNS ETW is bypassed.
- **Subdomain Data Tunneling**: ProvenanceX's domain allowlist evaluates domain suffixes. Data exfiltrated via base64 subdomains under an approved domain (e.g. `secret_data.pkg.go.dev`) passes suffix allowlists unless entropy or deep payload inspection is enabled.

## 5. Dependency Benchmark Scope (In-Memory vs Remote Resolvers)
- **Scope Distinction**: The $\le 4$ µs dependency scaling benchmark measures in-memory lockfile parsing, AST indexing, graph traversal, and cycle detection.
- **Exclusion**: It does NOT include physical network round-trip time (RTT) to remote registries (PyPI, npmjs, Go proxy) or remote package tarball downloads.

## 6. Evidence Volume Benchmark Scope (In-Memory vs Network I/O)
- **Scope Distinction**: The 10,000-event in-memory correlation latency (12–25 µs) measures pure cross-layer rule evaluation and state comparison on pre-ingested structs.
- **Exclusion**: It does NOT include remote syslog streaming, disk log file tailing, or external JSON deserialization overhead.

## 7. Synthetic Microbenchmarks vs Real Physical Builds
- **Disentanglement**: In-memory microbenchmarks execute in microseconds. However, an actual end-to-end Go or C++ build takes hundreds of milliseconds or seconds due to disk I/O, process compilation, and linker operations.
- **Measured Reality**: On actual compilations, ProvenanceX adds **0.16% to 0.27%** overhead (2.0–2.5 ms) to the physical build pipeline.

## 8. Test Environment & Operating System Constraints
- **Platform Specifics**: Advanced process and network telemetry implementations utilize Windows-native Win32 API and ETW sessions. On Linux, eBPF / auditd collectors provide equivalent capabilities but possess distinct kernel version dependencies (Linux kernel $\ge 5.8$ for CO-RE eBPF).

## 9. Attack-Family Boundary Conditions
- **Threat Model Scope**: ProvenanceX is designed to detect discrepancies between declared build metadata and observed execution behavior.
- **Out of Scope**: Zero-day hardware side-channels (Spectre/Meltdown), hypervisor compromise, kernel rootkits that hook ETW dispatch tables, and firmware-level supply chain modifications.

## 10. Benign In-Tree Generated Artifacts (False Alarms)
- **Operational Reality**: Strict git cleanliness policies (`require_clean_working_tree: true`) will flag legitimate uncommitted files generated during compilation (e.g. `mock_client.go`, `.pb.go`, `.tsbuildinfo`) unless explicitly exempted in `.gitignore` or declared in build inputs.

## 11. Generalization Scope (Tested vs Universal Vectors)
- **No Universal Detection**: ProvenanceX achieved 100.00% recall across the 25 evaluated attack scenarios. However, this applies strictly to the tested parameter spaces and modeled layers. Novel multi-stage attacks exploiting unmonitored OS primitives can achieve evasion.

## 12. Concurrency Benchmark Semantic Definition
- **Metric Definition**: The 140,000+ operations/sec concurrency benchmark represents **in-memory cross-layer verification operations per second** across isolated goroutines, NOT full compilation and disk linking of distinct physical codebases.

## 13. Hardware Dependence of Microsecond Latencies
- **Hardware Skew**: Microsecond latencies depend heavily on CPU clock speed, L1/L2 cache locality, and OS thread scheduling. On constrained virtualized CI runners, latency percentiles (P95/P99) may experience jitter up to 50–100 µs.

## 14. Inability to Infer Adversary Attribution Solely from Evidence
- **Attribution Limit**: Cross-layer evidence identifies *what* broke, *where* it broke, and *which layer* failed first. It does NOT identify *who* initiated the attack (e.g., distinguishing state-sponsored APTs from automated credential stuffing) without external threat intelligence feeds.

## 15. Inability to Guarantee Universal Attack Prevention
- **Observation vs Enforcement**: ProvenanceX is an audit, correlation, and decision platform. While it renders deterministic `REJECTED` verdicts to halt CI/CD deployment gates, it cannot physically prevent a rogue process from executing in real time without kernel-level inline prevention hooks (EDR/AV).
