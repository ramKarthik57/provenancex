# ProvenanceX Academic Research Reproducibility Package

This directory provides everything necessary to reproduce all empirical findings, baseline evaluations, and adversarial mutation experiments published in the ProvenanceX research paper.

## Directory Layout

```
research/
├── datasets/        # Serialized input attack scenarios and clean baseline inputs
├── experiments/     # Scenario simulation specifications and test configurations
├── scripts/         # Automated execution and chart generation utilities
├── configs/         # Policy profiles (strict, permissive, dev)
├── results/         # Raw CSVs from Monte Carlo 1,000-trial runs
├── figures/         # SVG/PNG confusion matrices and latency distribution plots
└── README.md        # Instructions for independent verification
```

## How to Reproduce

Execute the complete 1,000-trial Monte Carlo benchmark and baseline ablation study:

```bash
provenancex research run
```

Generate the empirical markdown and CSV summary reports:

```bash
provenancex research report
```
