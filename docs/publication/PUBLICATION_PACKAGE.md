# ProvenanceX Publication & Artifact Evaluation Package

## 1. Executive Overview

This package contains the complete submission-ready research artifacts, manuscripts, experimental datasets, presentation materials, and reproducible verification harnesses for:

**ProvenanceX: A Cross-Layer Framework for Software Supply-Chain Integrity Verification and Causal Trust-Break Localization**

- **Target Venues**: IEEE S&P / ACM CCS / USENIX Security / NDSS
- **Artifact Evaluation Badges Targeted**:
  - [x] **Artifacts Available**: Publicly accessible, versioned, persistent archive.
  - [x] **Artifacts Evaluated – Functional**: Documented, consistent, complete, and exercisable.
  - [x] **Artifacts Evaluated – Reusable**: Cleanly designed, modular, and extensible.
  - [x] **Results Reproduced**: All claims C1–C10 independently verifiable in under 60 seconds.

---

## 2. Zenodo Open-Science Archival Metadata

```json
{
  "title": "ProvenanceX: Research Validation Benchmark Suite and Air-Gapped Verification Engine",
  "creators": [
    {
      "name": "Ram, Karthik",
      "affiliation": "Independent Researcher / Advanced Systems Research",
      "orcid": "0009-0000-0000-0000"
    }
  ],
  "description": "Complete experimental reproduction suite, raw benchmark campaigns (19,777 trials), immutable datasets, standalone verifier, and cross-layer trust graph algorithms for software supply-chain integrity verification.",
  "access_right": "open",
  "license": "Apache-2.0",
  "keywords": [
    "software supply chain security",
    "provenance verification",
    "causal trust graph",
    "SLSA",
    "in-toto",
    "reproducible builds",
    "empirical security evaluation"
  ],
  "communities": [
    {"identifier": "security-privacy"},
    {"identifier": "software-engineering"}
  ],
  "version": "1.0.0-publication"
}
```

---

## 3. Reviewer & Artifact Evaluation Committee Quick-Start

### System Requirements
- **OS**: Windows 11 / Windows Server 2022 (Kernel ETW) or Linux Runner (User-Mode Polling Fallback).
- **Toolchain**: Go 1.22+ (Evaluated on Go 1.23.6 windows/amd64).
- **RAM**: Minimum 8 GB (16 GB recommended).
- **Disk**: 500 MB free storage.

### 60-Second Full Invariant Verification
To execute the complete regression test and audit verification suite:

```bash
# 1. Clone or extract repository
git checkout research-validation

# 2. Execute full automated verification suite
go test -v ./cmd/... ./internal/...

# 3. Verify standalone air-gapped verifier binary
go run ./cmd/provenancex-verifier --help
```

---

## 4. Publication Package Directory Structure

```
ProvenanceX/
├── docs/
│   ├── RESEARCH_PAPER.md               # Complete academic manuscript (Sections 1-18)
│   ├── DAY17_FINAL_RESEARCH_AUDIT.md   # Independent research integrity audit report
│   ├── DAY19_PUBLICATION_READINESS.md  # Publication readiness milestone certificate
│   └── publication/
│       ├── RELATED_WORK_MATRIX.md      # 12-dimensional comparison across 10 tools
│       ├── FIGURES.md                  # Figures 1-6 (ASCII, Mermaid, TikZ)
│       ├── RESULT_TABLES.md            # Tables 1-5 (Markdown & LaTeX)
│       ├── THESIS_ARCHITECTURE.md      # 15-chapter thesis blueprint
│       ├── VIVA_SLIDES.md              # 18-slide viva defense presentation deck
│       ├── VIVA_DEMO_SCRIPT.md         # 5-command examiner live demo script
│       ├── ARTIFACT_INDEX.md           # SHA-256 cryptographic catalog
│       └── PUBLICATION_PACKAGE.md      # This meta-specification
├── cmd/
│   ├── provenancex/                    # Primary CLI build & correlation tool
│   └── provenancex-verifier/           # Air-gapped standalone release gate verifier
├── internal/
│   ├── graph/                          # RFC 6962 Merkle chain & Kahn's DAG engine
│   ├── localization/                   # Causal earliest trust-break localization (L*)
│   ├── telemetry/                      # Windows Kernel ETW & non-admin polling
│   ├── ablation/                       # Component ablation test harness
│   └── remediation/                    # 25-family empirical benchmark suite
└── results/
    ├── day12_baseline/                 # Pre-remediation 80.00% baseline (6,250 trials)
    ├── day13/                         # Targeted remediation & micro-campaigns
    ├── day14/                         # Unseen generalization (7,500 trials)
    ├── day15/                         # Physical build tax & hardware disentanglement
    ├── day16/                         # Disentangled benign & stress populations
    ├── day17/                         # Independent audit verification hashes
    └── day19/                         # Publication claim validation & checklist
```

---

## 5. Artifact Badge Self-Evaluation Form

| Badge Criteria | ProvenanceX Implementation Evidence |
|---|---|
| **Artifacts Available** | Full source code, test suites, and 7 frozen benchmark datasets available on branch `research-validation`. |
| **Artifacts Functional** | All tests pass with zero failures (`go test -v ./...`), producing deterministic terminal output matching documentation. |
| **Artifacts Reusable** | Modular Go packages with clean separation between data capture (`internal/telemetry`), graph analytics (`internal/graph`), and verification (`cmd/provenancex-verifier`). |
| **Results Reproduced** | Executing `TestRemediationCampaign` programmatically recalculates and asserts all macro-average percentages (80.00% -> 98.75%) directly from raw CSV trial files. |
