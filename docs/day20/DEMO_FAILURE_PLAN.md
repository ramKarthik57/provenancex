# ProvenanceX Viva Demonstration Failure & Contingency Plan

## 1. Guiding Defense Principles
The live demonstration must never depend on improvisation. If any unexpected technical exception occurs during the examination:
1. **Explain what failed transparently** (e.g., OS privilege denial, port binding conflict, temporary file lock).
2. **Present the corresponding previously generated evidence** from our immutable, audited datasets.
3. **Continue the conceptual flow of the defense** without stalling or attempting ad-hoc fixes.
4. **Never fake a live result.**

---

## 2. Contingency Matrix Across 6 Failure Modes

### Failure Mode 1: Go Toolchain or Build Compilation Failure
- **Symptom**: `go run` or `go test` fails due to locked binary (`access is denied`) or missing toolchain environment variable.
- **Root Cause**: Windows file indexing service holding a file lock on `app.exe` or temporary antivirus lock.
- **Live Script Response**:
  > *"Examiners will note that the Windows filesystem indexer temporarily locked the output executable buffer. Rather than waiting for the OS lock to release, we refer directly to the audited build execution log recorded in `results/day15/physical_build_tax.csv`."*
- **Fallback Verification Evidence**:
  - Show immutable log: `results/day15/physical_build_tax.csv` (recording 30 independent trials with mean overhead 0.24%).

---

### Failure Mode 2: Windows Kernel ETW Privilege Error
- **Symptom**: `ETW session initialization failed: access denied (requires Administrator privileges)`.
- **Root Cause**: Demonstration terminal running under a standard user account instead of an elevated token.
- **Live Script Response**:
  > *"This warning illustrates one of our primary research findings: non-administrator CI environments lack permissions to create kernel trace sessions (`SeCreateGlobalPrivilege`). ProvenanceX automatically activates its documented non-admin user-mode polling fallback."*
- **Fallback Verification Evidence**:
  - Point to `internal/telemetry/windows/etw.go` fallback notice:  
    `NOTICE: Running without administrator privileges. Falling back to periodic process/socket polling.`
  - Point to audited comparison table in `results/day16/process_visibility.csv`.

---

### Failure Mode 3: Missing External Dependency or Path Resolution
- **Symptom**: `go: cannot find module providing package...`
- **Root Cause**: Terminal opened without setting Go toolchain path or Go proxy network timeout.
- **Live Script Response**:
  > *"Because ProvenanceX is designed to operate offline, all dependencies are vendored or cached locally in `go.mod`. We restore the local toolchain path `$env:PATH = 'C:\Users\Ram\.provenancex\toolchain\go\bin;$env:PATH'`."*
- **Fallback Verification Evidence**:
  - Point to `go.mod` and `go.sum` in repository root.

---

### Failure Mode 4: TCP Port Conflict on Server Commands
- **Symptom**: `bind: address already in use: 127.0.0.1:8080`.
- **Root Cause**: Background process occupying local HTTP port.
- **Live Script Response**:
  > *"Port 8080 is occupied by a background host service. ProvenanceX CLI supports dynamic port binding via `--port 0` or we can execute offline CLI verification directly via `provenancex-verifier` without opening HTTP sockets."*
- **Fallback Verification Evidence**:
  - Execute `go run ./cmd/provenancex-verifier --help` (requires zero ports or network bindings).

---

### Failure Mode 5: Verifier Startup or Bundle Parse Exception
- **Symptom**: `error opening bundle archive: unexpected EOF`.
- **Root Cause**: Corrupted test tarball archive during temporary extraction.
- **Live Script Response**:
  > *"The test archive suffered an incomplete read stream. We immediately execute the unit verification suite over our canonical bundle fixtures in `internal/bundle/`."*
- **Fallback Verification Evidence**:
  - Execute: `go test -v ./internal/bundle/...` (validating tarball unpacking, manifest verification, and Merkle root calculation).

---

### Failure Mode 6: Operating System Differences (Windows vs Linux CI)
- **Symptom**: Path delimiter or line ending warnings (`CRLF` vs `LF`).
- **Root Cause**: Platform divergence between Windows development workstations and Ubuntu CI runners.
- **Live Script Response**:
  > *"As documented in our Day 19 CI audit, repository-wide `.gitattributes` enforces standard LF line endings and raw UTF-8 encoding across all Go and TypeScript files, permanently preventing BOM encoding differences between Windows and Linux runners."*
- **Fallback Verification Evidence**:
  - Show `.gitattributes` in repository root.
  - Show clean `go test ./...` across all 39 internal packages.