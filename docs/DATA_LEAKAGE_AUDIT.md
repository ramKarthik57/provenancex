# ProvenanceX Data Leakage & Test Contamination Audit

**Audit Date**: 2026-09-20  
**Status**: COMPLETE  
**Standard**: Adversarial Scientific Validity

---

## 1. Executive Summary

Data leakage occurs when a machine learning model, rule engine, or security verification system receives information during evaluation that would not be available during real-world operational deployment, thereby artificially inflating accuracy metrics.

This audit systematically examined all evidence structures, mock fixtures, test harnesses, and correlation pipelines in ProvenanceX to detect and eliminate any potential leakage channels.

---

## 2. Leakage Vector Analysis

| Leakage Vector | Potential Threat | Codebase Inspection Finding | Risk Severity | Remediation Enacted |
| :--- | :--- | :--- | :--- | :--- |
| **Scenario Metadata Exposure** | Scenario ID (e.g. `EXP-04`) or Name passed directly to `Correlator` or `DecisionEngine`. | `CorrelationInput` struct does **NOT** contain `ScenarioID`, `ScenarioName`, or `ExpectedVerdict`. Pure behavioral structs only. | **NONE (SECURE)** | Architectural separation verified. |
| **Ground-Truth Label Leakage** | `isBenign` or `expectedVerdict` accessible within the verification pipeline. | In `internal/mutation/matrix.go`, `dec := tr.engine.Decide(corr, tr.pol)` was invoked in the same scope where `expectedVerdict` was defined. | **LOW (ISOLATED)** | Implemented strict **Blind Validation Mode**: Verifier receives only anonymized `EvidencePayload` with zero labels. |
| **Semantic String Tainting in Fixtures** | Using giveaway strings like `"backdoor.go"` or `"malicious-c2.com"` in mock inputs that could be hardcoded into rules. | `internal/correlation/correlator.go` was audited with regex. Rules do **NOT** inspect for strings like "backdoor", "exploit", or "hack". Rules check formal set differences (`!IsClean`, `Expected != Observed`, domain not in policy allowlist). | **LOW (COSMETIC)** | Cleaned synthetic inputs to use realistic production package names and anonymous domain patterns. |
| **Mutation Parameter Exposure** | Mutation category (`CategoryArtifact`, `CategorySignature`) exposed to detector. | Detector receives raw binary digests and attestation objects; mutation category is kept strictly in the experiment harness. | **NONE (SECURE)** | Verified. |
| **Fixture Topology Symmetry** | Attack fixtures always differing in exactly one field while clean builds are 100% invariant. | In early iterations, clean builds shared an identical template. Real builds exhibit natural variability (timestamps, path differences). | **MEDIUM (REALISM)** | Implemented Holdout Dataset and Benign Variability Matrix (Phase 11–13). |

---

## 3. Strict Separation Architecture (Enforced in God Mode 3.0)

```
       +-------------------------------------------------------------+
       |                  EXPERIMENT HARNESS                         |
       |  - Holds Ground Truth Labels (ATTACK / BENIGN)              |
       |  - Holds Attack Family & Mutation Parameters                |
       |  - Withholds ALL ground truth from Verifier                 |
       +-------------------------------------------------------------+
                                      │
                                      ▼ [Generates & Anonymizes]
       +-------------------------------------------------------------+
       |               ANONYMIZED EVIDENCE PAYLOAD                   |
       |  - Artifact Bytes / SHA-256                                 |
       |  - Observed Process Tree                                    |
       |  - Filesystem Mutations & Merkle Root                       |
       |  - Outbound Network Sockets                                 |
       |  - SBOM (CycloneDX / SPDX)                                  |
       |  - SLSA / in-toto Provenance Attestation                    |
       |  - Digital Signature Bytes                                  |
       +-------------------------------------------------------------+
                                      │
                                      ▼ [Blind Verification Call]
       +-------------------------------------------------------------+
       |               PROVENANCEX BLIND VERIFIER                    |
       |  - Pure function: EvidencePayload + Policy -> Verdict       |
       |  - ZERO knowledge of scenario ID or expected outcome        |
       |  - Computes cross-plane consistency matrices                |
       +-------------------------------------------------------------+
                                      │
                                      ▼ [Outputs Raw Decision]
       +-------------------------------------------------------------+
       |                  VERIFICATION DECISION                      |
       |  Verdict: [TRUSTED / WARNING / REJECTED]                    |
       |  Earliest Trust Break Layer: [e.g. DEPENDENCIES]            |
       |  Contradiction Count: [e.g. 1]                              |
       +-------------------------------------------------------------+
                                      │
                                      ▼ [Post-Verification Scoring]
       +-------------------------------------------------------------+
       |                  SCORING & METRICS ENGINE                   |
       |  - Reveals Ground Truth Label                               |
       |  - Scores TP, FP, TN, FN, Precision, Recall, Accuracy        |
       +-------------------------------------------------------------+
```

---

## 4. Verification Invariant

> **INVARIANT-LEAKAGE-01**: Under no operational or testing circumstance shall any function in `internal/correlation`, `internal/decision`, `internal/localization`, or `cmd/provenancex-verifier` import, receive, or reference scenario identifiers, mutation categories, or expected ground-truth verdicts.
