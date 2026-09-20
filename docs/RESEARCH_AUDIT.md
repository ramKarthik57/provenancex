# ProvenanceX Research Audit & Empirical Claim Classification

**Audit Date**: 2026-09-20  
**Audit Scope**: Codebase (`internal/`, `cmd/`, `pkg/`), Documentation (`docs/`), Experiments (`experiments/`, `tests/`)  
**Standard**: Academic Rigor & Research Integrity (ACM CCS / IEEE S&P criteria)

---

## 1. Classification Taxonomy

Every empirical claim and research assertion across the project documentation is audited and assigned one of five formal classifications:

* **`VERIFIED`**: Confirmed by deterministic, reproducible automated test execution with raw empirical evidence.
* **`PARTIALLY VERIFIED`**: Valid under restricted/mocked experimental conditions, but subject to operational caveats or narrow test scopes.
* **`REQUIRES EXPERIMENT`**: Conceptually sound and supported by code, but lacks large-sample or adversarial statistical validation.
* **`UNVERIFIED`**: Claimed in prose or documentation, but absent automated reproducible test harness.
* **`UNSUPPORTED`**: Hyperbolic, overly broad, or scientifically unproven assertion requiring immediate correction or retraction.

---

## 2. Audit Matrix of Research Claims

| Claim ID | Claim Statement | Source Document | Classification | Empirical Audit Finding & Limitations |
| :--- | :--- | :--- | :--- | :--- |
| **CLM-01** | Detection Rate = 100.0% (10/10 attacks detected) | `docs/RESEARCH_PAPER.md`, `experiments/BENCHMARK_REPORT.md` | **`PARTIALLY VERIFIED`** | Verified on 10 controlled scenarios in `internal/experiment/scenarios.go`. However, \(N=10\) is an unacceptably small sample size for statistical significance. Vulnerable to "The 100% Trap" if generalized beyond the synthetic suite. |
| **CLM-02** | Trust-Break Localization Accuracy = 100.0% | `docs/RESEARCH_PAPER.md`, `experiments/BENCHMARK_REPORT.md` | **`PARTIALLY VERIFIED`** | Verified for single-point causal breaks. Does not evaluate simultaneous multi-layer concurrent attacks or masking attacks. |
| **CLM-03** | Mean Verification Latency < 5 ms (0.00 ms in tables) | `experiments/BENCHMARK_REPORT.md` | **`UNVERIFIED`** / **Misleading** | In-memory correlation arithmetic takes < 1 ms. However, real-world collection (Git CLI, process snapshotting via WMI) takes between 300 ms and 3.8 s. Reporting 0.00 ms reflects pre-mocked input evaluation, not full pipeline latency. |
| **CLM-04** | False Positive Rate = 0.0% | `docs/ARCHITECTURE.md` | **`REQUIRES EXPERIMENT`** | Benign variability (compiler patch differences, build path relocation, archive timestamp jitter) has not been evaluated across non-malicious corporate builds. |
| **CLM-05** | False Negative Rate = 0.0% ("Zero-Evasion Defense") | `experiments/BENCHMARK_REPORT.md` | **`UNSUPPORTED`** | In security research, "zero evasion" is an untenable theoretical claim. Attackers using evidence deletion, replay, or timing skew could evade detection unless explicitly defended. |
| **CLM-06** | Baseline Superiority: ProvenanceX (100%) vs Checksum (20%), Signature (30%), SBOM (10%) | `internal/ablation/ablation_test.go` | **`PARTIALLY VERIFIED`** | Verified against the 10 synthetic attacks under defined baseline definitions (Ablation Study 1.0). Must clearly document baseline operational constraints rather than claiming general tool inferiority. |
| **CLM-07** | Tamper-Evident Hash Chain Immutability | `internal/evidence/manifest.go` | **`VERIFIED`** | Verified in `internal/evidence/evidence_test.go`. Any modification of an item's claim or previous hash breaks verification deterministically. |
| **CLM-08** | Offline Air-Gapped Verification Invariant | `cmd/provenancex-verifier/` | **`VERIFIED`** | Binary compiles with zero database, network, or server dependencies. Validated in `internal/bundle/bundle_test.go`. |
| **CLM-09** | Windows Telemetry Resolution | `docs/ARCHITECTURE.md` | **`PARTIALLY VERIFIED`** | Current telemetry uses periodic polling (`Get-NetTCPConnection`, `Win32_Process`), which cannot observe transient microsecond-lived processes or sub-interval network bursts. Requires native ETW. |
| **CLM-10** | Reproducibility & Delta Isolation | `internal/reproducibility/` | **`VERIFIED`** | Verified in `reproducibility_test.go` for bitwise comparison, path leakage, and ZIP normalization. |

---

## 3. Required Corrective Actions (God Mode 2.0 Plan)

1. **Scale Empirical Trials to \(N \ge 1,000\)**: Replace single-run \(N=10\) benchmark with a multi-trial Monte Carlo perturbation harness measuring confidence intervals.
2. **Implement Evidence Gap & Omission Detection**: Explicitly distinguish `UNOBSERVED` / `MISSING` from `VERIFIED` to eliminate the "absence of evidence = evidence of safety" fallacy.
3. **Execute Adversarial Attacks on Evidence Itself**:
   - `EXP-11`: Evidence Suppression
   - `EXP-12`: Evidence Deletion
   - `EXP-13`: Evidence Replay
   - `EXP-14`: Cross-Build Evidence Confusion
4. **Measure Benign Build Variability**: Evaluate false positive rates across legitimate compiler updates, path drifts, and dependency version bumps.
5. **Real-World Latency Reporting**: Explicitly partition latency into *Collection Latency* (\(\approx 0.5 - 3.5\text{ s}\)) vs *Verification & Correlation Latency* (\(\approx 0.5 - 2.5\text{ ms}\)).
