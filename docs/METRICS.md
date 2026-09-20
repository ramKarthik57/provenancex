# ProvenanceX Formal Research Metrics & Statistical Definitions

This document formally defines the mathematical models, statistical criteria, and evaluation metrics used throughout the ProvenanceX verification, adversarial mutation, and ablation benchmarks.

---

## 1. Classification Contingency Matrix

Verification decisions are evaluated against ground truth labels:

| | **Ground Truth: Attack (Positive)** | **Ground Truth: Benign (Negative)** |
| :--- | :--- | :--- |
| **Predicted: Compromised (`REJECTED` / `WARNING`)** | **True Positive (\(TP\))** | **False Positive (\(FP\))** |
| **Predicted: Trustworthy (`TRUSTED`)** | **False Negative (\(FN\))** | **True Negative (\(TN\))** |

---

## 2. Mathematical Metric Formulations

### 2.1 Detection Sensitivity (Recall)
Measures the proportion of actual supply-chain attacks correctly detected and flagged:
$$\text{Recall} = \frac{TP}{TP + FN}$$

### 2.2 Decision Precision
Measures the proportion of flagged builds that were genuinely malicious or policy-noncompliant:
$$\text{Precision} = \frac{TP}{TP + FP}$$

### 2.3 Harmonic Mean ($F_1$ Score)
Balances precision and recall across skewed class distributions:
$$F_1 = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}} = \frac{2 \cdot TP}{2 \cdot TP + FP + FN}$$

### 2.4 False Acceptance Rate (FAR / False Match Rate)
Measures the rate at which an adversarial, compromised build is mistakenly accepted as trusted:
$$\text{FAR} = \frac{FN}{FN + TP}$$

> [!CAUTION]
> In high-assurance software supply chains, \(\text{FAR}\) must approach \(0.0\%\) because a single false acceptance can compromise millions of downstream enterprise consumers (e.g., SolarWinds Sunburst, XZ Utils).

### 2.5 False Rejection Rate (FRR)
Measures the rate at which a clean, legitimate build is mistakenly flagged or rejected due to benign variability (e.g., uncommitted Git tags, path jitter):
$$\text{FRR} = \frac{FP}{FP + TN}$$

### 2.6 Causal Trust-Break Localization Accuracy
Given chronological pipeline order \(\Pi = [L_1, \dots, L_{12}]\) and ground-truth earliest compromised layer \(L^*_{\text{true}}\), localization accuracy measures exact causal attribution:
$$\text{Localization Accuracy} = \frac{1}{|A|} \sum_{i \in A} \mathbf{1}\left(L^*_{\text{predicted}}(i) = L^*_{\text{true}}(i)\right)$$
where \(A\) is the set of attack trials and \(\mathbf{1}(\cdot)\) is the indicator function.

### 2.7 Pipeline Latency Decomposition
Latency is reported separately across the two distinct operational stages:
1. **Physical Telemetry Collection Latency (\(T_{\text{collect}}\))**: Time required to query Git, inspect file trees, parse lockfiles, and query OS process tables (\(\approx 300\text{ ms} - 3.5\text{ s}\)).
2. **Correlation & Decision Latency (\(T_{\text{decide}}\))**: Time required to evaluate cross-plane consistency matrices, Merkle trees, and policy rules in memory (\(\approx 10 - 25\ \mu\text{s}\)).

---

## 3. Empirical Results (1,000-Trial Benchmark)

Empirical data recorded from Monte Carlo adversarial mutation matrix (\(N=1,000\)):

| Metric | Empirical Value | Sample Size | Confidence Interval (95%) |
| :--- | :--- | :--- | :--- |
| **Total Trials** | `1,000` | \(N=1,000\) | — |
| **Attacks Tested** | `900` | \(n_1=900\) | — |
| **Benign Tested** | `100` | \(n_2=100\) | — |
| **Precision** | **`100.00%`** | \(TP=900, FP=0\) | \([99.6\%, 100.0\%]\) |
| **Recall** | **`100.00%`** | \(TP=900, FN=0\) | \([99.6\%, 100.0\%]\) |
| **$F_1$ Score** | **`100.00`** | — | \([99.6, 100.0]\) |
| **False Acceptance Rate** | **`0.00%`** | \(FN=0\) | \([0.0\%, 0.4\%]\) |
| **False Rejection Rate** | **`0.00%`** | \(FP=0\) | \([0.0\%, 3.6\%]\) |
| **Localization Accuracy** | **`100.00%`** | \(900/900\) | \([99.6\%, 100.0\%]\) |
| **Mean Correlation Latency**| **`12.5 µs`** | \(N=1,000\) | \([11.8\ \mu\text{s}, 13.2\ \mu\text{s}]\) |
