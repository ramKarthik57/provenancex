# THEORETICAL & PHYSICAL OBSERVATION BOUNDARIES IN SUPPLY-CHAIN INTEGRITY

**Document ID:** PX-RES-2026-OBS-BOUNDARIES  
**Classification:** Academic Research Reference & Architectural Specification  
**Subject:** ProvenanceX Multi-Layer Observation Boundaries  

---

## 1. Introduction: The Incompleteness of User-Mode Build Observation

A fundamental premise of the ProvenanceX research project is that **no supply-chain security system can detect what it cannot observe**. In academic evaluations, detection claims of 100% are almost universally an artifact of evaluating attacks only within the observation domain of the sensor.

This document formally categorizes the **four primary physical observation boundaries** identified and evaluated in Days 12 and 13, contrasting user-mode heuristics against kernel-native instrumentation.

```
+---------------------------------------------------------------------------------------------------+
|                        PHYSICAL OBSERVATION LAYERS & BOUNDARY HIERARCHY                           |
+---------------------------------------------------------------------------------------------------+
| LAYER 1: IDENTITY (Source Tree)                                                                   |
| [Boundary: Unauthenticated Metadata] Plaintext Git Author Headers                                 |
| [Remediation: Cryptographic Anchor]  Mandatory GPG / SSH / Sigstore Gitsign PKI Verification       |
+---------------------------------------------------------------------------------------------------+
| LAYER 2: PROCESS (Execution Runtime)                                                              |
| [Boundary: Sampling Window]          User-mode snapshot polling (Get-Process, /proc, 100ms ticks) |
| [Remediation: Kernel Ring Buffer]    Windows ETW (Microsoft-Windows-Kernel-Process) / Linux eBPF  |
+---------------------------------------------------------------------------------------------------+
| LAYER 3: FILESYSTEM (Storage & Artifacts)                                                         |
| [Boundary: Path Scoping]             Workspace Root Directory Delta Observation                   |
| [Remediation: Isolation & Filters]   Expanded Auxiliary (%TEMP%) + Minifilter Driver / Namespaces|
+---------------------------------------------------------------------------------------------------+
| LAYER 4: NETWORK (Exfiltration & Dependencies)                                                    |
| [Boundary: State Table Sampling]     TCP Socket Table Polling (Get-NetTCPConnection)              |
| [Remediation: Event Egress Control]  DNS-Client ETW Provider + Hermetic Boundary Firewall Rules   |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Process Observation Boundary: Polling vs. Kernel Event Tracing

### The Nyquist–Shannon Sampling Problem in Process Tracking
User-mode process collectors periodically sample the OS process table at interval $T_{\text{sample}}$ (typically $100\text{ ms} \le T_{\text{sample}} \le 1000\text{ ms}$).
If an adversarial process executes with lifetime $\tau_{\text{exec}}$ such that:
$$\tau_{\text{exec}} < T_{\text{sample}}$$
the probability of capturing the process in a discrete snapshot approaches zero:
$$P(\text{Observed}) \approx \frac{\tau_{\text{exec}}}{T_{\text{sample}}}$$

For $\tau_{\text{exec}} = 4\text{ ms}$ and $T_{\text{sample}} = 100\text{ ms}$, the chance of observation is $\le 4\%$. In an uncoordinated build, it routinely yields **0.00% empirical detection**.

### Kernel-Native Event Tracing (Windows ETW / Linux eBPF)
In contrast, Event Tracing for Windows (`Microsoft-Windows-Kernel-Process`) hooks directly into the executive process creation routines (`PspCreateProcessNotifyRoutineEx`).
- Every `ProcessStart` and `ProcessStop` event is written synchronously to an in-memory kernel ring buffer.
- Events include microsecond-precision timestamps, Process ID (PID), Parent Process ID (PPID), Image File Name, Command Line, and User SID.
- Even sub-millisecond processes ($\tau_{\text{exec}} < 500\text{ µs}$) are reliably recorded and attributed to the build stage.

### Deployment Limitation:
- Creating a system trace session requires administrative privileges (`SeCreateGlobalPrivilege`).
- On unprivileged CI/CD runners (e.g. standard GitHub Actions Windows runners without elevation), ProvenanceX must fall back to snapshot polling, inherently re-opening this sub-quantum blind spot.

---

## 3. Filesystem Observation Boundary: Workspace vs. System-Wide I/O

### The Spatial Scope Vulnerability
Standard software build integrity checkers observe the directory root of the repository being built (`./` or `C:\Build\workspace`).
An adversary aware of this observation scope simply targets external host locations:
- `%TEMP%` (`C:\Users\<user>\AppData\Local\Temp`)
- Global system temp (`C:\Windows\Temp`)
- User startup directories or global pip/npm cache folders (`~/.cache`, `~/.npm`)

### The Remediation Spectrum:
1. **Workspace Only (Pre-Remediation):** 0% detection of out-of-workspace writes.
2. **Expanded Static Paths (Day 13):** Adds `%TEMP%` and user profile temp directories to the observation boundary. Detects standard script droppers, but misses writes to arbitrary unconfigured directories.
3. **Process-Attributed Minifilter (Future Hardening):** Uses Windows File System Minifilter Driver (`FLTMGR`) to intercept all `IRP_MJ_CREATE` and `IRP_MJ_WRITE` requests originating from the build process PID subtree, regardless of target path.
4. **Hermetic Container Mounts:** The only architectural mechanism that provides complete containment without requiring kernel drivers is running the build inside an isolated container filesystem namespace where host paths do not exist.

---

## 4. Network Observation Boundary: Stateful TCP vs. Stateless UDP/DNS

### The Connectionless Tunneling Blind Spot
Polling `Get-NetTCPConnection` inspects the kernel TCP state machine (`SYN_SENT`, `ESTABLISHED`, `CLOSE_WAIT`).
Adversaries exfiltrate sensitive environment variables, credentials, or source diffs through DNS queries:
```text
Build Process ---> Query: [hex-encoded-secret].c2-server.com ---> Local Resolver (Port 53)
```
Because UDP is stateless and DNS resolution typically completes in $2\text{–}10\text{ ms}$, no TCP connection is ever opened. The TCP socket table remains completely pristine, yielding a false-negative security audit.

### The Remediation Spectrum:
1. **DNS-Client ETW (`Microsoft-Windows-DNS-Client`):** Captures query events asynchronously, decoding the query name, type, and result. High-entropy subdomain queries to unauthorized domains trigger network policy contradictions.
2. **Hermetic Network Isolation:** Configures local packet filtering (Windows Filtering Platform / iptables) allowing only loopback and declared HTTP/S proxy endpoints, dropping all outbound UDP/53 traffic.

### Inherent Limitation: Encrypted DNS (DoH / DoT)
If the build tool or attacker binary sends DNS requests via DNS over HTTPS (DoH) to an external IP (e.g. `https://1.1.1.1/dns-query`), the traffic appears to the OS as standard HTTPS (TCP/443). Unless endpoint DoH client providers are instrumented or TLS interception is enabled, DoH bypasses standard DNS-Client ETW.

---

## 5. Source Identity Boundary: Metadata vs. Cryptographic Roots

### The Plaintext Git Fallacy
The Git commit object header contains:
```text
author Alice <alice@corporate.com> 1700000000 +0000
committer Bob <bob@corporate.com> 1700000000 +0000
```
Neither of these fields is cryptographically authenticated by Git by default. Any local user can execute `git commit --author="CEO <ceo@company.com>"`, producing a valid commit SHA and a completely clean working tree.

### The Remediation Boundary:
ProvenanceX resolves this by shifting Layer 1 (`Source`) trust from plaintext metadata to cryptographic signing:
1. Every commit must possess an attached digital signature (GPG, SSH, or Sigstore Gitsign).
2. The signature key must validate against an explicit policy allowlist (`trusted_signers`).
3. The cryptographic identity extracted from the signature must match the declared author.

If `repository.require_signed_commits` is disabled, author spoofing remains an inherent limitation of the Git storage model.
