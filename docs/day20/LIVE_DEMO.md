# ProvenanceX Viva Voce Live Interactive Demonstration Script

**Target Duration**: 7–10 Minutes  
**Audience**: Viva Voce Examination Panel & Technical Reviewers  
**Prerequisites**: Clean working tree on branch `research-validation`, Go 1.22+ toolchain.  
**Demonstration Principle**: Every step is deterministic, uses authentic existing CLI commands, and operates from local repository test fixtures.

---

## PART 1: Establish Baseline & Research State (1 Minute)

### Objective
Demonstrate that the repository is in a clean, reproducible state and display the available CLI surface.

### Terminal Commands
```powershell
# 1. Verify clean repository state
git status
git branch --show-current

# 2. Inspect the ProvenanceX primary CLI interface
$env:PATH = "C:\Users\Ram\.provenancex\toolchain\go\bin;$env:PATH"
go run ./cmd/provenancex --help
```

### Expected Output
```text
On branch research-validation
Your branch is up to date with 'origin/research-validation'.
nothing to commit, working tree clean
research-validation

Usage:
  provenancex [command]

Available Commands:
  benchmark   Execute empirical supply-chain attack benchmark and localization evaluation
  bundle      Package and verify self-contained, portable software supply chain evidence bundles
  diff        Cross-layer comparative diff between two build execution manifests or binaries
  evidence    Audit and verify supply-chain evidence completeness and gaps
  explain     Audit-grade causal root-cause analysis and 'Why?' explainability engine
  graph       ProvenanceX Trust Graph 2.0 formal evidence DAG explorer
  verify      Cross-layer software supply-chain integrity verification and trust-break localization
  ...
```

### Spoken Defense Commentary
> *"Examiners can see our repository is on branch `research-validation` with a clean working tree. The ProvenanceX CLI provides commands for multi-layer evidence verification, graph inspection, and causal explanation. We will now evaluate a benign build against organizational policy."*

---

## PART 2: Normal Build Verification — Deterministic Trust (1.5 Minutes)

### Objective
Demonstrate normal build verification where repository, dependencies, execution telemetry, and artifacts satisfy policy.

### Terminal Command
```powershell
go test -v ./internal/ablation/... -run TestBenignVariabilityEvaluation
```

### Expected Output
```text
=== RUN   TestBenignVariabilityEvaluation
    ablation_test.go:85: Benign Variability [COMPILER_PATH_UPDATE]: TRUSTED (Compiler update within allowed semantic range does not trigger false positive)
    ablation_test.go:85: Benign Variability [BUILD_PATH_RELOCATION]: TRUSTED (Normalized paths prevent path leakage false positives under reproducible flags)
    ablation_test.go:85: Benign Variability [AUTHORIZED_LOCKFILE_UPDATE]: TRUSTED (Synchronized dependency and lockfile update verified as legitimate)
    ablation_test.go:85: Benign Variability [UNAUTHORIZED_EGRESS_ENDPOINT]: REJECTED (Correctly distinguished from benign change: unapproved socket egress rejected)
--- PASS: TestBenignVariabilityEvaluation (0.00s)
PASS
ok      github.com/ramKarthik57/provenancex/internal/ablation    0.045s
```

### Spoken Defense Commentary
> *"Notice that legitimate development variations—such as compiling across relocated directories or updating compiler patch releases—evaluate to `TRUSTED`. Path normalization prevents path leakage false alarms, achieving 100% specificity across our 1,000-trial benign campaign when generated paths are declared in policy."*

---

## PART 3: Controlled Contradiction Simulation (1.5 Minutes)

### Objective
Simulate a stealth supply-chain attack: an adversary modifies dependency lockfile hashes while keeping high-level package declarations unchanged.

### Terminal Command
```powershell
go test -v ./internal/mutation/... -run TestMutationMatrix
```

### Expected Output
```text
=== RUN   TestMutationMatrix
    matrix_test.go:48: Executing Controlled Adversarial Mutation Suite across 25 Attack Families...
    matrix_test.go:92: Injected Mutation: Category [DEPENDENCY], Target Layer [L3: Lockfile Resolution]
    matrix_test.go:93: Declared package manifest matches benign configuration.
    matrix_test.go:94: Physical lockfile hash substituted: SHA-256 mismatch detected.
--- PASS: TestMutationMatrix (0.42s)
PASS
ok      github.com/ramKarthik57/provenancex/internal/mutation    0.442s
```

### Spoken Defense Commentary
> *"In this controlled scenario, an attacker altered a dependency lockfile hash to pull a compromised package. A single-layer tool inspecting only `package.json` sees a valid version string. Now let us see how the verification engine handles this contradiction."*

---

## PART 4: Detection & Policy Decision (1.5 Minutes)

### Objective
Execute the decision engine to evaluate cross-layer invariants and show deterministic rejection.

### Terminal Command
```powershell
go test -v ./internal/decision/...
```

### Expected Output
```text
=== RUN   TestDeterministicPolicyDecision
    decision_test.go:34: Evaluating Pairwise Invariant: C(L2, L3) [Declared Dependencies vs Lockfile Resolution]
    decision_test.go:38: Invariant Violation Detected: Declared dependency SHA-256 divergence.
    decision_test.go:45: Evaluating Organization Release Policy: require_strict_lockfile_match = true
    decision_test.go:52: Emitting Deterministic Categorical Verdict: REJECTED
--- PASS: TestDeterministicPolicyDecision (0.01s)
PASS
ok      github.com/ramKarthik57/provenancex/internal/decision    0.024s
```

### Spoken Defense Commentary
> *"The decision engine evaluates the pairwise invariant C(L2, L3). Rather than outputting an arbitrary numeric score like 'Risk: 65%', it deterministically emits `REJECTED`, halting the deployment gate based on an explicit policy rule."*

---

## PART 5: Causal Trust-Break Localization (2 Minutes)

### Objective
Execute the localization engine on a multi-stage attack to isolate earliest broken layer $L^*$.

### Terminal Command
```powershell
go test -v ./internal/localization/...
```

### Expected Output
```text
=== RUN   TestCausalLocalizationComposedAttack
    explain_test.go:32: Multi-Stage Attack Cascading Failures:
    explain_test.go:34: Contradicted Layers: [L7: Process, L8: Filesystem, L10: Artifact, L12: Signature]
    explain_test.go:42: Executing Kahn's Algorithm on 12-Node Evidence DAG G = (V, E)...
    explain_test.go:48: Topological Order Pi: [L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12]
    explain_test.go:56: Evaluating L* = argmin_{L_k in Pi} { k | State(L_k) = CONTRADICTED }...
    explain_test.go:62: Earliest Broken Layer Isolated: L7 (Process Hierarchy)
    explain_test.go:68: Causal Diagnostic: Unauthorized compiler helper spawned outside approved PID tree.
--- PASS: TestCausalLocalizationComposedAttack (0.01s)
PASS
ok      github.com/ramKarthik57/provenancex/internal/localization    0.018s
```

### Spoken Defense Commentary
> *"Notice the critical distinction: the downstream signature failed at Layer 12 because the binary changed at Layer 10, which was written at Layer 8. ProvenanceX traces back through the topological DAG to isolate Layer 7—the rogue process—as the earliest observable inconsistent layer. Crucially, as stated in our thesis, this is localization within the observable evidence graph, not proof of the physical attacker's external origin."*

---

## PART 6: Standalone Air-Gapped Verification (1.5 Minutes)

### Objective
Demonstrate independent release bundle verification with zero database connections and zero network sockets.

### Terminal Command
```powershell
go run ./cmd/provenancex-verifier --help
```

### Expected Output
```text
provenancex-verifier is a physically separate, independent verification tool
designed for air-gapped consumer environments, release gates, and audit pipelines.

Core Architectural Invariant: "The build system does not get to verify itself."

It has:
  - Zero database dependency
  - Zero web UI dependency
  - Zero network dependency
  - Deterministic evaluation of bundle checksums, digital signatures,
    SLSA/in-toto attestations, and RFC 6962 tamper-evident hash logs.

Usage:
  provenancex-verifier <evidence-bundle.tar.gz> [flags]

Flags:
  -h, --help   help for provenancex-verifier
      --json   Output verification result as JSON
```

### Spoken Defense Commentary
> *"In our final demonstration step, we invoke `provenancex-verifier`. In the tested configuration, this binary verifies release packages with zero network sockets and zero database connections. It performs archive integrity checks, SHA-256 artifact verification, Ed25519/ECDSA signature verification, and SLSA attestation validation entirely locally, providing a robust air-gapped verification gate."*