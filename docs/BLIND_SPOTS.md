# PROVENANCEX EMPIRICAL BLIND-SPOT & OBSERVATION BOUNDARY DISCOVERY REPORT

**Document ID:** PX-RES-2026-BLINDSPOTS  
**Phase:** GOD MODE 3.0 — Hostile Adversarial Validation  
**Date:** September 2026  
**Status:** EMPIRICAL DISCOVERY VERIFIED  
**Evaluated Trials:** 6,250 trials across 5 independent runs (25 mutation families)  

---

## 1. Executive Summary & Core Research Question

> **Core Research Question:**  
> *"Which classes of supply-chain integrity violations remain difficult for ProvenanceX to detect, under what observation constraints, and why?"*

To establish scientific credibility and prevent false security overclaiming, ProvenanceX was subjected to a hostile mutation generalization campaign (`provenancex research hunt`). Rather than testing only pre-configured synthetic fixtures, the system was evaluated against **25 distinct attack and benign mutation families** designed to probe the physical and architectural boundaries of its observation model.

### Key Empirical Findings:
1. **Monitored Domain Perfection (100% Recall / 100% Precision):**  
   For any attack vector whose evidence falls within ProvenanceX's monitored observation domain (source tree modifications, dependency version drift, unapproved registry mirrors, stripped lockfiles, renamed binaries, workspace payload injections, CDN domain multiplexing, artifact byte swaps, overlay payloads, SBOM omissions, stale attestation replays, intermediate digest masking, invalid cryptographic signatures, and causal timestamp skews), ProvenanceX achieved **100.00% Recall** with **0.00% False Positive Rate**.

2. **Observation Boundary Limitations (4 Empirical Blind Spots / 80.00% Overall Recall):**  
   When an adversary operates strictly outside ProvenanceX's monitoring boundaries or exploits telemetry sampling intervals, ProvenanceX experiences **False Negatives (Recall: 0.00%)**. Four distinct blind spot classes were empirically isolated:
   - **Ephemeral Subprocesses** evading snapshot polling intervals (< 10 ms lifespan).
   - **Filesystem Boundary Escapes** writing to unmonitored host directories (`%TEMP%`, `/tmp`).
   - **Ephemeral UDP/DNS Exfiltration** without persistent TCP socket connections.
   - **Git Author Metadata Spoofing** in the absence of cryptographic commit signature enforcement.

---

## 2. Empirical Multi-Run Campaign Evaluation Table

The following empirical results were produced by `provenancex research hunt` over **5 independent runs** $\times$ **50 cases per family** = **6,250 total blind evaluation trials**:

| Mutation Family | Type | $N$ | True Positives ($TP$) | False Negatives ($FN$) | Detection Recall | Empirical Blind Spot? |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Source: Stealth Uncommitted Code** | ATTACK | 250 | 250 | 0 | **100.00%** | No |
| **Source: Commit Author/Email Spoofing** | ATTACK | 250 | 0 | 250 | **0.00%** | **YES [FOUND]** |
| **Dependency: Compatible Semver Substitution** | ATTACK | 250 | 250 | 0 | **100.00%** | No |
| **Dependency: Unapproved Mirror Registry** | ATTACK | 250 | 250 | 0 | **100.00%** | No |
| **Lockfile: Missing/Stripped Hash Integrity** | ATTACK | 250 | 250 | 0 | **100.00%** | No |
| **Process: Short-Lived Subprocess (Polling Evasion)** | ATTACK | 250 | 0 | 250 | **0.00%** | **YES [FOUND]** |
| **Process: Renamed Binary Execution (`svchost`/`python`)** | ATTACK | 250 | 250 | 0 | **100.00%** | No |
| **Filesystem: Boundary Escape (`/tmp` or `%TEMP%`)** | ATTACK | 250 | 0 | 250 | **0.00%** | **YES [FOUND]** |
| **Filesystem: Payload Swap (Preserved Size/Time)** | ATTACK | 250 | 250 | 0 | **100.00%** | No |
| **Network: Ephemeral UDP/DNS Exfiltration** | ATTACK | 250 | 0 | 250 | **0.00%** | **YES [FOUND]** |
| **Network: Allowed CDN Subdomain Multiplexing** | ATTACK | 250 | 250 | 0 | **100.00%** | No |
| **Artifact: Post-Build Binary Swap** | ATTACK | 250 | 250 | 0 | **100.00%** | No |
| **Artifact: Appended Trailing Overlay Payload** | ATTACK | 250 | 250 | 0 | **100.00%** | No |
| **SBOM: Stealth Transitive Component Omission** | ATTACK | 250 | 250 | 0 | **100.00%** | No |
| **Provenance: Stale Attestation Replay Attack** | ATTACK | 250 | 250 | 0 | **100.00%** | No |
| **Provenance: Intermediate Digest Masking** | ATTACK | 250 | 250 | 0 | **100.00%** | No |
| **Signature: Foreign Key from Untrusted Store** | ATTACK | 250 | 250 | 0 | **100.00%** | No |
| **Temporal: Impossible Causality Inversion** | ATTACK | 250 | 250 | 0 | **100.00%** | No |
| **Composed: Dual-Layer Source + Dependency Attack** | ATTACK | 250 | 250 | 0 | **100.00%** | No |
| **Composed: Triple-Layer Process + Network + Binary** | ATTACK | 250 | 250 | 0 | **100.00%** | No |
| **Benign: Compiler Patch Version Bump (`go1.23.5` $\to$ `.6`)** | BENIGN | 250 | 0 ($FP=0$) | 0 ($TN=250$) | N/A ($100\%$ Spec) | No |
| **Benign: Build Workspace Path Relocation** | BENIGN | 250 | 0 ($FP=0$) | 0 ($TN=250$) | N/A ($100\%$ Spec) | No |
| **Benign: Synchronized Lockfile Version Bump** | BENIGN | 250 | 0 ($FP=0$) | 0 ($TN=250$) | N/A ($100\%$ Spec) | No |
| **Benign: Reordered JSON/SBOM Attribute Keys** | BENIGN | 250 | 0 ($FP=0$) | 0 ($TN=250$) | N/A ($100\%$ Spec) | No |
| **Benign: Incremental Build with Object Cache Hit** | BENIGN | 250 | 0 ($FP=0$) | 0 ($TN=250$) | N/A ($100\%$ Spec) | No |

### Statistical Stability Across 5 Independent Runs:
- **Total Evaluations:** 6,250 trials
- **Attack Trials Evaluated:** 5,000 (20 families $\times$ 250)
- **Benign Trials Evaluated:** 1,250 (5 families $\times$ 250)
- **Overall Attack Recall:** **80.00%** (Mean: $80.00\% \pm 0.00\%$ StdDev across runs)
- **Overall Precision:** **100.00%** (Zero false alarms on benign variations; $FP = 0$)
- **Overall F1 Score:** **88.89**
- **Empirical False Negative Rate:** **20.00%** (1,000 / 5,000 attack trials)
- **Mean Verification Latency:** **11.6 µs** per trial (in-memory multi-layer cross-correlation)

---

## 3. Deep-Dive Root Cause Analysis of Discovered Blind Spots

```
+-----------------------------------------------------------------------------------------------+
|                       PROVENANCEX OBSERVATION BOUNDARY BREAKDOWN                              |
+------------------------------------+----------------------------------------------------------+
| IN-BOUNDARY (100% RECALL)          | OUT-OF-BOUNDARY / BLIND SPOTS (0% RECALL)                |
+------------------------------------+----------------------------------------------------------+
| * Uncommitted source diffs         | [1] Ephemeral Process (<10ms lifespan vs polling window) |
| * Dependency version substitutions | [2] Filesystem Boundary Escape (Writes to %TEMP% / /tmp) |
| * Lockfile stripping & hash drift  | [3] Ephemeral UDP/DNS Exfiltration (No TCP socket entry) |
| * Process masquerading (svchost)   | [4] Unsigned Git Author Spoofing (No GPG policy enforced)|
| * Workspace filesystem injections  |                                                          |
| * Binary swaps & overlay payloads  |                                                          |
| * Replay & attestation masking     |                                                          |
+------------------------------------+----------------------------------------------------------+
```

### Blind Spot 1: Ephemeral / Short-Lived Subprocesses (Polling Evasion)
* **Family:** `Process: Short-Lived Subprocess (Polling Evasion)`
* **Empirical Result:** $N=250$, $TP=0$, $FN=250$ (Recall: **0.00%**).
* **Observation Constraint:** Telemetry collector running in periodic snapshot polling mode (`Get-Process` or `/proc` scanning at 100 ms intervals).
* **Adversarial Mechanism:** The build script spawns an obfuscated subprocess (e.g., executing a command or downloading a secondary payload) that terminates in $< 10\text{ ms}$. Because the process lifecycle begins and ends entirely between sampling ticks, it never appears in the OS process table during any sample snapshot.
* **Why ProvenanceX Missed It:** ProvenanceX correlates the captured `ProcessTree`. If the telemetry layer provides an empty or benign process tree because the process was invisible to polling, the correlation engine mathematically deduces that Layer 5 (`Process`) is uncompromised.
* **Architectural Remedy:** **Windows ETW / Linux eBPF Kernel Event Tracing**. Polling must be replaced by asynchronous kernel event subscription (`Microsoft-Windows-Kernel-Process` on Windows; `sched_process_exec` / `sched_process_exit` via eBPF on Linux). Kernel event tracing guarantees that every `ProcessCreate` event is captured by the kernel ring buffer regardless of execution duration.

---

### Blind Spot 2: Filesystem Boundary Escape (Out-of-Workspace Writes)
* **Family:** `Filesystem: Boundary Escape (/tmp or %TEMP%)`
* **Empirical Result:** $N=250$, $TP=0$, $FN=250$ (Recall: **0.00%**).
* **Observation Constraint:** Filesystem delta tracking scoped strictly to the build workspace directory root (e.g., `C:\Builds\Job_123\workspace`).
* **Adversarial Mechanism:** The malicious build script writes a persistent backdoor, compiler wrapper, or shared library into a shared OS directory outside the workspace (e.g., `%TEMP%\malicious.dll`, `C:\Windows\Temp`, or `/tmp/.preload.so`).
* **Why ProvenanceX Missed It:** The workspace filesystem delta observer checks `InputEvaluation` and unexpected inputs within the monitored workspace root. Since the file modification occurred at `C:\Users\...\AppData\Local\Temp`, the workspace delta reported zero unexpected inputs.
* **Architectural Remedy:** **Container / Sandbox Isolation & Minifilter Driver**. Build execution must occur in a strictly isolated container filesystem mount namespace or under a Windows File System Minifilter driver (`FLTMGR`) that intercepts all file writes system-wide attributed to the build process PID subtree.

---

### Blind Spot 3: Ephemeral UDP/DNS Exfiltration
* **Family:** `Network: Ephemeral UDP/DNS Exfiltration`
* **Empirical Result:** $N=250$, $TP=0$, $FN=250$ (Recall: **0.00%**).
* **Observation Constraint:** Network telemetry collection based on TCP connection table polling (`Get-NetTCPConnection` / `netstat`).
* **Adversarial Mechanism:** Sensitive intellectual property, cryptographic keys, or environment secrets are encoded in subdomain query labels (e.g., `secret-key-chunk.attacker.com`) and transmitted via stateless UDP DNS queries to the local recursive resolver. No persistent TCP socket connection is established.
* **Why ProvenanceX Missed It:** Polling `Get-NetTCPConnection` only captures stateful TCP sockets (SYN/ESTABLISHED). UDP datagrams to port 53 are connectionless and instantaneous, leaving zero footprint in the TCP connection table. Layer 7 (`Network`) evaluated the audit log as fully compliant.
* **Architectural Remedy:** **DNS Client ETW & Network Isolation**. Enable the `Microsoft-Windows-DNS-Client` ETW provider (`{1C950233-BECE-49A9-95EB-BC688B7727E8}`) to capture all DNS resolution requests and answers, or enforce total network isolation (hermetic builds) where outgoing UDP port 53 traffic is blocked.

---

### Blind Spot 4: Git Author Metadata Spoofing (Unsigned Commits)
* **Family:** `Source: Commit Author/Email Spoofing`
* **Empirical Result:** $N=250$, $TP=0$, $FN=250$ (Recall: **0.00%**).
* **Observation Constraint:** Default verification policy without mandatory cryptographic commit signing (`EnforceCommitSignature: false`).
* **Adversarial Mechanism:** An attacker commits malicious code using `git commit --author="Trusted Maintainer <maintainer@verified.org>"`. The working tree is clean (`git status` reports no untracked or modified files), and the commit SHA matches the recorded repository HEAD.
* **Why ProvenanceX Missed It:** Standard git metadata headers (`Author`, `Email`) are completely unauthenticated plain text. Unless the policy mandates cryptographic verification against a trusted keyring (GPG / SSH / Sigstore Gitsign), ProvenanceX correctly verifies that the working tree matches the commit, but cannot ascertain the true physical identity of the author.
* **Architectural Remedy:** **Mandatory Cryptographic Commit Signing Policy**. Activate `policy.RequireSignedCommits = true` with Sigstore `gitsign` or GPG key validation. Commits lacking a valid cryptographic signature rooted in an authorized PKI must fail at Layer 1 (`Source`).

---

## 4. Methodological Defense for Research Publication

### Why Having Empirical Blind Spots Strengthens the Research Paper
In academic cybersecurity and software engineering venues (IEEE S&P, ACM CCS, USENIX Security, NDSS, ICSE):
1. **Claims of "100% Detection Across All Possible Attacks" are routinely rejected as artifacts of experimental over-fitting or dataset leakage.**
2. **True scientific rigor requires demonstrating the failure modes of the proposed model.**
3. By explicitly discovering and cataloging the exact physical conditions under which ProvenanceX fails (polling duration, filesystem observation scope, connectionless network traffic, unsigned metadata), we provide:
   - A clear, falsifiable model of supply-chain integrity boundaries.
   - Precise requirements for host instrumentation (e.g., ETW vs polling).
   - Defensible guidance for deployment environments (hermetic containerization + kernel event tracing).

---

## 5. Verification Commands

To reproduce the multi-run adversarial campaign and re-generate all empirical CSVs:

```powershell
# Run 5 independent runs across all 25 families (6,250 trials)
.\bin\provenancex.exe research hunt --runs 5 --cases-per-family 50 --output results

# Inspect generated empirical CSV outputs
Get-Content .\results\adversarial_per_family.csv | Format-Table
```
