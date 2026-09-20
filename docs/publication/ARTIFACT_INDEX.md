# ProvenanceX Research Artifact Index & Cryptographic Inventory

This document catalogs all primary research artifacts, datasets, algorithms, and documentation files across the ProvenanceX repository with their corresponding SHA-256 cryptographic digests.

## 1. Cryptographic File Inventory

| Artifact Path | Type | Description | SHA-256 Digest |
|---|---|---|---|
| `docs/RESEARCH_PAPER.md` | Documentation | RESEARCH_PAPER.md | `80a0e4bd8e4da770e4a799b204948335c9a1449f103c86c80610fddb68430282` |
| `docs/DAY17_FINAL_RESEARCH_AUDIT.md` | Documentation | DAY17_FINAL_RESEARCH_AUDIT.md | `fe360c2a61473260e9b3383b5203b25543262da6ce793bbe573f02f235f8a80d` |
| `docs/DAY19_PUBLICATION_READINESS.md` | Documentation | DAY19_PUBLICATION_READINESS.md | `1d40ea81ad6cdceee4dba03b62a9272ab0fa6c282c9bbcc1236188095a7c7b2c` |
| `docs/publication/RELATED_WORK_MATRIX.md` | Documentation | RELATED_WORK_MATRIX.md | `df552b3f45b96e601ec2ea7773bb4475e7c9d760d9d683a1b7a0d4e1920684d5` |
| `docs/publication/FIGURES.md` | Documentation | FIGURES.md | `04e34101bb3bcc3d8d2299a1ce66549a8cd9dd719e951f737ab3c97afd28be7d` |
| `docs/publication/RESULT_TABLES.md` | Documentation | RESULT_TABLES.md | `cb514ae4c9b8d62c3f751d09fc1f59e94429620f4350e68417b4db4110665401` |
| `docs/publication/THESIS_ARCHITECTURE.md` | Documentation | THESIS_ARCHITECTURE.md | `b4f286923c0a09d7d99717d4786515750a62336065eca47c8aef9bee436472df` |
| `docs/publication/VIVA_SLIDES.md` | Documentation | VIVA_SLIDES.md | `f5aae80b4fb6528141065aae22938cda501ed95e148350c719202e1c65d93b39` |
| `docs/publication/VIVA_DEMO_SCRIPT.md` | Documentation | VIVA_DEMO_SCRIPT.md | `acaed8782bd55feced376a64a0b4a587a03e2f13b42948dd574ed5c8e0d0d80b` |
| `docs/publication/ARTIFACT_INDEX.md` | Documentation | ARTIFACT_INDEX.md | `777be14070335e4e74d7859da707b06e7bbe53c506a09251936aa88eda2fee4c` |
| `docs/publication/PUBLICATION_PACKAGE.md` | Documentation | PUBLICATION_PACKAGE.md | `8726e7e0b988f00db14a8ad45af388cef388c430225bed6fcc1e9d14c6f94133` |
| `cmd/provenancex-verifier/main.go` | Source Code | main.go | `e8ef9990027d4f388c9c8ac9157d88441fea3e545633f663bb11324cb9739fd5` |
| `cmd/provenancex/main.go` | Source Code | main.go | `efd65a2328376d1ebda60bd5309ae70ecf4b9afb6b33a511272468f619065df6` |
| `internal/ablation/ablation.go` | Source Code | ablation.go | `c90a9af6d042dc354404c28df6c15bd09079c3abe0f21f9a2195c24f8448a64b` |
| `internal/graph/graph.go` | Source Code | graph.go | `6a47e1a02bedcf4e40619f2a3d65243203438b42b653ee76f156efe59742648d` |
| `internal/localization/explain.go` | Source Code | explain.go | `dd521d8acabca47b1f253a6fac95344e1ab5bceb501c873d353d4d3d82e0e374` |
| `internal/telemetry/telemetry.go` | Source Code | telemetry.go | `a026ed38d2a79a349db77e6092668dfabca48f52b02050a9d19c6a55bbe9550c` |
| `results/day12_baseline/adversarial_campaign_raw.csv` | Dataset | adversarial_campaign_raw.csv | `116d9071d5325662d127b89a2c72534c35a87b95bea8c5e16d1d99e936dc876d` |
| `results/day13/confusion_matrix.csv` | Dataset | confusion_matrix.csv | `9e1e80506f878d03ad172dd7ff4cdbbbe5142eb413acd538bb80723f398e6845` |
| `results/day19/publication_claim_validation.csv` | Dataset | publication_claim_validation.csv | `e44c2a3d7d5bea34a184bbf4cf5afef22b4292893c464cf451c8d8a353e1ce8b` |
| `results/day19/reproducibility_checklist.json` | Dataset | reproducibility_checklist.json | `0e769da4c5b9f26c3646b562d2bf1301befbf1a0835f15c317ab3603d0db6862` |

## 2. Verification Instructions

To independently verify the integrity of all artifacts in this repository:
```powershell
Get-FileHash -Path (Get-ChildItem -Recurse -File -Include *.go,*.md,*.csv) -Algorithm SHA256
```

To reproduce the complete suite of tests and validation invariants:
```powershell
go test -v ./cmd/... ./internal/...
```
