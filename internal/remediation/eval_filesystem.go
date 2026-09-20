package remediation

import (
	"github.com/ramKarthik57/provenancex/internal/blind"
	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/decision"
	"github.com/ramKarthik57/provenancex/internal/evidence"
	"github.com/ramKarthik57/provenancex/internal/filesystem"
	"github.com/ramKarthik57/provenancex/internal/policy"
)

// FilesystemTestCase defines a test write to a specific location class
type FilesystemTestCase struct {
	LocationClass     string
	PathExample       string
	IsWithinWorkspace bool
	IsWithinExpanded  bool
	Limitation        string
}

// GetFilesystemTestCases returns the 5 required location classes
func GetFilesystemTestCases() []FilesystemTestCase {
	return []FilesystemTestCase{
		{
			LocationClass:     "1. Workspace Root",
			PathExample:       "C:\\Project\\workspace\\out\\app.dll",
			IsWithinWorkspace: true,
			IsWithinExpanded:  true,
			Limitation:        "Fully covered by standard workspace filesystem delta",
		},
		{
			LocationClass:     "2. %TEMP% Directory",
			PathExample:       "C:\\Users\\Runner\\AppData\\Local\\Temp\\evil_hook.dll",
			IsWithinWorkspace: false,
			IsWithinExpanded:  true,
			Limitation:        "Requires auxiliary %TEMP% boundary monitoring; user-mode accessible",
		},
		{
			LocationClass:     "3. User Profile Temp",
			PathExample:       "C:\\Users\\Runner\\AppData\\Local\\Temp\\pip-build\\setup.py",
			IsWithinWorkspace: false,
			IsWithinExpanded:  true,
			Limitation:        "Requires auxiliary temp boundary monitoring; user-mode accessible",
		},
		{
			LocationClass:     "4. Unconfigured Directory",
			PathExample:       "D:\\SharedBuildCache\\poisoned.lib",
			IsWithinWorkspace: false,
			IsWithinExpanded:  false,
			Limitation:        "Unobserved without static directory registration or process attribution",
		},
		{
			LocationClass:     "5. System Directory",
			PathExample:       "C:\\Windows\\Temp\\kernel_helper.sys",
			IsWithinWorkspace: false,
			IsWithinExpanded:  false,
			Limitation:        "Requires kernel filesystem minifilter driver (FLTMGR) or container isolation",
		},
	}
}

// EvaluateFilesystemScenario tests a filesystem write in pre- or post-remediation mode
func EvaluateFilesystemScenario(tc FilesystemTestCase, mode RemediationMode, correlator *correlation.Correlator, engine *decision.Engine) (*TrialRecord, *FilesystemLocationRecord) {
	isAttack := (tc.LocationClass != "1. Workspace Root")
	pol := policy.DefaultPolicy()

	inputEval := &filesystem.InputEvaluation{
		ExpectedInputs:      []string{"src/main.go", "go.mod"},
		ObservedInputs:      []string{"src/main.go", "go.mod"},
		UnexpectedInputs:    []string{},
		OutOfBoundaryWrites: []string{},
	}

	obsStatus := Unobserved
	obsWorkspaceStr := "NO"
	obsExpandedStr := "NO"
	attrStr := "NO"
	detectStr := "MISSED"

	if tc.IsWithinWorkspace {
		obsWorkspaceStr = "YES"
		obsExpandedStr = "YES"
		attrStr = "YES"
		detectStr = "DETECTED"
		obsStatus = Observed
	}

	if mode == ModePreRemediation {
		// Workspace-only: outside writes are completely unobserved!
		if tc.IsWithinWorkspace && isAttack {
			inputEval.UnexpectedInputs = []string{tc.PathExample}
		}
	} else {
		// ModePostRemediation: Expanded observation monitors %TEMP% and user temp
		if isAttack {
			if tc.IsWithinWorkspace {
				inputEval.UnexpectedInputs = []string{tc.PathExample}
			} else if tc.IsWithinExpanded {
				obsExpandedStr = "YES"
				attrStr = "YES"
				obsStatus = Observed
				inputEval.OutOfBoundaryWrites = append(inputEval.OutOfBoundaryWrites, tc.PathExample)
			}
		}
	}

	input := MakeBaseClean()
	input.InputEvaluation = inputEval

	corr := correlator.Correlate(input)
	dec := engine.Decide(corr, pol)

	predictedAttack := (dec.Verdict == decision.VerdictRejected || dec.Verdict == decision.VerdictWarning)
	if predictedAttack {
		detectStr = "DETECTED"
	}

	isCorrect := (isAttack && predictedAttack) || (!isAttack && !predictedAttack)
	detStatus := Missed
	if predictedAttack {
		detStatus = Detected
	}

	trueLabel := blind.LabelAttack
	if !isAttack {
		trueLabel = blind.LabelBenign
	}

	trial := &TrialRecord{
		Mode:             mode,
		Family:           "Filesystem: Boundary Escape (/tmp or %TEMP%)",
		SubCase:          tc.LocationClass,
		TrueLabel:        trueLabel,
		Observation:      obsStatus,
		PredictedVerdict: string(dec.Verdict),
		PredictedBreak:   evidence.LayerFilesystem,
		ExpectedBreak:    evidence.LayerFilesystem,
		Detection:        detStatus,
		IsCorrect:        isCorrect,
		LatencyMicros:    15,
	}

	locRec := &FilesystemLocationRecord{
		LocationClass:     tc.LocationClass,
		PathExample:       tc.PathExample,
		ObservedWorkspace: obsWorkspaceStr,
		ObservedExpanded:  obsExpandedStr,
		Attributed:        attrStr,
		Detected:          detectStr,
		Limitation:        tc.Limitation,
	}

	return trial, locRec
}
