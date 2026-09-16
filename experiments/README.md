# Controlled Supply-Chain Experiments

This directory houses the 10 controlled, non-destructive benchmark attack scenarios:

1. `01-source-tampering`: Stealth modifications to source code prior to build.
2. `02-dependency-substitution`: Lockfile vs manifest version drift.
3. `03-dependency-hash-mismatch`: Checksum forgery in dependency lockfiles.
4. `04-build-script-modification`: In-flight build script tampering.
5. `05-environment-drift`: Compiler/runtime version discrepancies.
6. `06-unexpected-build-input`: Injection of untracked files or hidden config.
7. `07-network-policy-violation`: Egress to unauthorized external destinations.
8. `08-artifact-tampering`: Post-compilation binary modification.
9. `09-provenance-contradiction`: Fabricated or contradictory SLSA/in-toto attestations.
10. `10-reproducibility-failure`: Rebuild divergence due to timestamps or path leaks.
