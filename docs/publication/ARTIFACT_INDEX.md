# ProvenanceX Research Artifact Index & Cryptographic Inventory

This document catalogs all primary research artifacts, datasets, algorithms, and documentation files across the ProvenanceX repository with their corresponding SHA-256 cryptographic digests.

## 1. Cryptographic File Inventory

| Artifact Path | Type | Description | SHA-256 Digest |
|---|---|---|---|
| `docs/RESEARCH_PAPER.md` | Documentation | RESEARCH_PAPER.md | `729bf8158798a6c2ca6bd4f1a562779af81156bd80118b9e7046ee905c8db1cc` |
| `docs/DAY17_FINAL_RESEARCH_AUDIT.md` | Documentation | DAY17_FINAL_RESEARCH_AUDIT.md | `fe360c2a61473260e9b3383b5203b25543262da6ce793bbe573f02f235f8a80d` |
| `docs/DAY19_PUBLICATION_READINESS.md` | Documentation | DAY19_PUBLICATION_READINESS.md | `4fd5251b18d7707836dd2c3e9439ac55e331ce80e6dd1e394c36b2cc51eb6632` |
| `docs/publication/RELATED_WORK_MATRIX.md` | Documentation | RELATED_WORK_MATRIX.md | `df552b3f45b96e601ec2ea7773bb4475e7c9d760d9d683a1b7a0d4e1920684d5` |
| `docs/publication/FIGURES.md` | Documentation | FIGURES.md | `da60e7d92cb14ea453267b7e55384ee9cf523bb3a31775d7fcda357dce249e57` |
| `docs/publication/RESULT_TABLES.md` | Documentation | RESULT_TABLES.md | `c6857778e5ce8f6e01e3cdd81dbe3193323cc5125fe489c2b9f4b507ece1f614` |
| `docs/publication/THESIS_ARCHITECTURE.md` | Documentation | THESIS_ARCHITECTURE.md | `b4f286923c0a09d7d99717d4786515750a62336065eca47c8aef9bee436472df` |
| `docs/publication/VIVA_SLIDES.md` | Documentation | VIVA_SLIDES.md | `f6ddc04e7977067f7f0f9a7bba3c7e831c95da8f4a8c24647ed81c30651013fa` |
| `docs/publication/VIVA_DEMO_SCRIPT.md` | Documentation | VIVA_DEMO_SCRIPT.md | `acaed8782bd55feced376a64a0b4a587a03e2f13b42948dd574ed5c8e0d0d80b` |
| `docs/publication/ARTIFACT_INDEX.md` | Documentation | ARTIFACT_INDEX.md | `c194356fb806aa4bac4cc6dad7489e7fbe630a55757c772ed31f1030a8517dac` |
| `docs/publication/PUBLICATION_PACKAGE.md` | Documentation | PUBLICATION_PACKAGE.md | `8726e7e0b988f00db14a8ad45af388cef388c430225bed6fcc1e9d14c6f94133` |
| `cmd/provenancex-verifier/main.go` | Source Code | main.go | `e8ef9990027d4f388c9c8ac9157d88441fea3e545633f663bb11324cb9739fd5` |
| `cmd/provenancex/main.go` | Source Code | main.go | `efd65a2328376d1ebda60bd5309ae70ecf4b9afb6b33a511272468f619065df6` |
| `internal/ablation/ablation.go` | Source Code | ablation.go | `c90a9af6d042dc354404c28df6c15bd09079c3abe0f21f9a2195c24f8448a64b` |
| `internal/graph/graph.go` | Source Code | graph.go | `6a47e1a02bedcf4e40619f2a3d65243203438b42b653ee76f156efe59742648d` |
| `internal/localization/explain.go` | Source Code | explain.go | `dd521d8acabca47b1f253a6fac95344e1ab5bceb501c873d353d4d3d82e0e374` |
| `internal/telemetry/telemetry.go` | Source Code | telemetry.go | `a026ed38d2a79a349db77e6092668dfabca48f52b02050a9d19c6a55bbe9550c` |
| `results/day12_baseline/adversarial_campaign_raw.csv` | Dataset | adversarial_campaign_raw.csv | `116d9071d5325662d127b89a2c72534c35a87b95bea8c5e16d1d99e936dc876d` |
| `results/day13/confusion_matrix.csv` | Dataset | confusion_matrix.csv | `9e1e80506f878d03ad172dd7ff4cdbbbe5142eb413acd538bb80723f398e6845` |
| `results/day19/publication_claim_validation.csv` | Dataset | publication_claim_validation.csv | `62b3c1b3575796b2d386f7fb68204cccc9cd6ee4029c64c9195148a0fc78322f` |
| `results/day19/reproducibility_checklist.json` | Dataset | reproducibility_checklist.json | `a7720614e3fc023d618be2d1f2df2247a4a59a0a57453118b4b561973e39aa0d` |

## 2. Verification Instructions

To independently verify the integrity of all artifacts in this repository:
```powershell
Get-FileHash -Path (Get-ChildItem -Recurse -File -Include *.go,*.md,*.csv) -Algorithm SHA256
```

To reproduce the complete suite of tests and validation invariants:
```powershell
go test -v ./cmd/... ./internal/...
```
