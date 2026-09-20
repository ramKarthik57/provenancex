# ProvenanceX Independent Research Validation Audit

**Audit Date**: 2026-09-20  
**Branch**: `research-validation`  
**Purpose**: Rigorous adversarial evaluation of existing empirical claims under scientific peer-review standards.

---

## 1. Audit Matrix of Empirical Claims

| Claim ID | Formal Claim | Dataset Source | Sample Size | Experiment Executed | Ground Truth Source | Detector Input | Potential Leakage | Reproducibility | Validation Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **VAL-01** | Detection Sensitivity = 100.0% across 10 controlled scenarios | `internal/experiment/scenarios.go` | $N=10$ | `provenancex benchmark` | `Scenario.ExpectedVerdict` | `CorrelationInput` | Mock inputs specifically targeted the rule attributes (single-fault fixtures). | Deterministic (100% reproducible) | **`PARTIALLY VALIDATED`** (Small sample size; single-point attacks) |
| **VAL-02** | Monte Carlo Matrix: Recall = 100.0%, Precision = 100.0%, Localization = 100.0% | `internal/mutation/matrix.go`, `results/` | $N=1,000$ ($n_{\text{att}}=900$, $n_{\text{ben}}=100$) | `provenancex research run` | `TrialRecord.IsBenign`, `TrialRecord.ExpectedResult` | Mutated `CorrelationInput` | Generated mutations targeted known single layer rules; target layer alignment was calibrated to detector rule order. | Deterministic (100% reproducible) | **`PARTIALLY VALIDATED`** (Requires blind evaluation on holdout set) |
| **VAL-03** | Mean In-Memory Correlation Latency = $12.5\ \mu\text{s}$ | `results/raw.csv`, `results/summary.csv` | $N=1,000$ | `provenancex research run` | Time measurement (`time.Since(start).Microseconds()`) | `CorrelationInput` in RAM | None (computational benchmark). | High variance based on CPU scheduling ($10 - 25\ \mu\text{s}$). | **`VALIDATED`** (Accurate for RAM correlation; must separate from physical collection) |
| **VAL-04** | Physical Telemetry Acquisition Latency = $0.3\text{ s} - 3.8\text{ s}$ | Test execution logs (`TestEnvironmentCollector`, `TestRepositoryCollector`) | $N=10$ runs | Live CLI execution | Windows OS process and network queries | Physical file system, Git repo, WMI | None | Variable depending on disk I/O and process tree depth. | **`VALIDATED`** |
| **VAL-05** | Baselines A–F Superiority: ProvenanceX (100%) vs Baselines A (20%), B (30%), C (20%), D (30%), E (50%) | `internal/ablation/ablation.go` | $N=10$ scenarios | `go test ./internal/ablation/...` | Scenario ground truth | Subsets of `CorrelationInput` per baseline | Baselines are implemented as internal capability models rather than invoked external tool binaries (Cosign, Syft). | Deterministic (100% reproducible) | **`PARTIALLY VALIDATED`** (Fair operational model, but synthetic baselines) |
| **VAL-06** | False Positive Rate = 0.00% (Zero False Alarms) | `internal/mutation/matrix.go`, `internal/ablation/ablation.go` | $N=104$ benign cases | Clean base inputs, compiler update, path relocation | `isBenign = true` | Clean `CorrelationInput` | Benign cases are variants of one pristine template. Real-world repositories have uncommitted tags, build scripts, dynamic timestamps. | Deterministic | **`REQUIRES MORE DATA`** (Must test diverse real-world dirty/complex workspaces) |
| **VAL-07** | Standalone Air-Gapped Verifier Security Invariant | `cmd/provenancex-verifier/` | 3 bundle tests | `internal/bundle/bundle_test.go` | Bundle manifest and HMAC hash log | Tarball archive | None (zero external dependencies). | Deterministic | **`VALIDATED`** |
| **VAL-08** | Windows Telemetry ETW Resolution | `internal/telemetry/windows/etw.go` | 1 session test | `internal/telemetry/windows/etw_test.go` | OS token elevation check | Windows Kernel Trace Session | User-mode fallback gracefully downgrades to polling; ETW kernel capture requires administrative privileges. | Deterministic | **`PARTIALLY VALIDATED`** (Interface exists; requires Administrator privilege for live kernel session) |

---

## 2. Key Audit Findings & Directives

1. **The "100% Trap"**: The 100% sensitivity and 100% precision in `results/summary.csv` reflect synthetic single-variable mutations on a shared base template. Under multi-stage, simultaneous, or stealthy partial corruptions, detection and localization rates are expected to experience degradation.
2. **Ground Truth Leakage Prevention**: The verifier must be strictly isolated from all harness metadata. It must receive only the raw `EvidenceBundle` or `CorrelationInput` with zero scenario IDs, expected verdicts, or mutation tags.
3. **Holdout Evaluation**: A holdout dataset of unseen attack variations and benign build configurations must be constructed to test true generalization.
