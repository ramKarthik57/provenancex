# ProvenanceX Policies

This directory stores supply-chain verification policy profiles in YAML:

* `default.yaml`: Baseline policy enforcing clean repository state, mandatory lockfiles, and registry allowlists.
* `strict.yaml`: Enforces digital signatures, SLSA Level 3, strict network allowlists, and bit-for-bit rebuild reproducibility.
* `audit.yaml`: Permissive audit mode flagging discrepancies without blocking decisions.
