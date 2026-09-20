package day16

import (
	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/decision"
	"github.com/ramKarthik57/provenancex/internal/policy"
	"github.com/ramKarthik57/provenancex/internal/remediation"
)

// PolicyEvalTestCase specifies a generated file scenario for Phase F
type PolicyEvalTestCase struct {
	ID                       string
	Description              string
	HasModifiedTrackedSource bool
	ModifiedFiles            []string
	UntrackedFiles           []string
	DeclaredPatterns         []string
	AllowDeclaredGenerated   bool
	ExpectedVerdict          string
	IsAttack                 bool
}

// GetPolicyEvalTestCases returns the 6 required generated file scenarios
func GetPolicyEvalTestCases() []PolicyEvalTestCase {
	return []PolicyEvalTestCase{
		// 1. Legitimate declared generated file (BENIGN-HUNT-04 remediation)
		{
			ID:                       "GEN-TEST-01",
			Description:              "1. Legitimate declared generated mock file created during build test phase",
			HasModifiedTrackedSource: false,
			ModifiedFiles:            []string{},
			UntrackedFiles:           []string{"pkg/client/generated_mock.go"},
			DeclaredPatterns:         []string{"pkg/client/generated_*.go"},
			AllowDeclaredGenerated:   true,
			ExpectedVerdict:          "TRUSTED",
			IsAttack:                 false,
		},

		// 2. Undeclared generated file (Attacker attempts to drop unapproved file)
		{
			ID:                       "GEN-TEST-02",
			Description:              "2. Undeclared generated file dropped in source tree without policy registration",
			HasModifiedTrackedSource: false,
			ModifiedFiles:            []string{},
			UntrackedFiles:           []string{"pkg/secret/evil_helper.go"},
			DeclaredPatterns:         []string{"pkg/client/generated_*.go"},
			AllowDeclaredGenerated:   true,
			ExpectedVerdict:          "REJECTED",
			IsAttack:                 true,
		},

		// 3. Modified tracked source file (Attacker tampers with tracked source alongside build)
		{
			ID:                       "GEN-TEST-03",
			Description:              "3. Tracked source file modified in-tree during build",
			HasModifiedTrackedSource: true,
			ModifiedFiles:            []string{"src/main.go"},
			UntrackedFiles:           []string{"pkg/client/generated_mock.go"},
			DeclaredPatterns:         []string{"pkg/client/generated_*.go"},
			AllowDeclaredGenerated:   true,
			ExpectedVerdict:          "REJECTED",
			IsAttack:                 true,
		},

		// 4. Generated file in unexpected location
		{
			ID:                       "GEN-TEST-04",
			Description:              "4. Generated file dropped outside allowed directory scope",
			HasModifiedTrackedSource: false,
			ModifiedFiles:            []string{},
			UntrackedFiles:           []string{"cmd/provenancex/backdoor.go"},
			DeclaredPatterns:         []string{"pkg/client/generated_*.go"},
			AllowDeclaredGenerated:   true,
			ExpectedVerdict:          "REJECTED",
			IsAttack:                 true,
		},

		// 5. Generated file matching declared wildcard pattern
		{
			ID:                       "GEN-TEST-05",
			Description:              "5. Legitimate mock file matching declared wildcard pattern *mock*",
			HasModifiedTrackedSource: false,
			ModifiedFiles:            []string{},
			UntrackedFiles:           []string{"tests/unit_client_mock_test.go"},
			DeclaredPatterns:         []string{"tests/*mock*.go"},
			AllowDeclaredGenerated:   true,
			ExpectedVerdict:          "TRUSTED",
			IsAttack:                 false,
		},

		// 6. Generated file containing unexpected modification (tracked code altered while claiming to be generated)
		{
			ID:                       "GEN-TEST-06",
			Description:              "6. Modified core library code claiming exemption under generated directory",
			HasModifiedTrackedSource: true,
			ModifiedFiles:            []string{"pkg/client/client.go"},
			UntrackedFiles:           []string{"pkg/client/generated_mock.go"},
			DeclaredPatterns:         []string{"pkg/client/generated_*.go"},
			AllowDeclaredGenerated:   true,
			ExpectedVerdict:          "REJECTED",
			IsAttack:                 true,
		},
	}
}

// EvaluateGeneratedFilePolicy evaluates all 6 scenarios verifying false positive remediation and security invariants
func EvaluateGeneratedFilePolicy(correlator *correlation.Correlator, engine *decision.Engine) []*GeneratedFilePolicyRecord {
	cases := GetPolicyEvalTestCases()
	var records []*GeneratedFilePolicyRecord

	for _, tc := range cases {
		pol := policy.DefaultPolicy()
		pol.Repository.RequireCleanState = true
		pol.Repository.AllowDeclaredGenerated = tc.AllowDeclaredGenerated
		pol.Repository.DeclaredGeneratedPaths = tc.DeclaredPatterns

		base := remediation.MakeBaseClean()
		base.Repository.IsClean = (len(tc.ModifiedFiles) == 0 && len(tc.UntrackedFiles) == 0)
		base.Repository.ModifiedFiles = tc.ModifiedFiles
		base.Repository.UntrackedFiles = tc.UntrackedFiles

		corr := correlator.Correlate(base)
		dec := engine.Decide(corr, pol)

		observedVerdict := string(dec.Verdict)
		isFP := !tc.IsAttack && observedVerdict == "REJECTED"
		isFN := tc.IsAttack && observedVerdict != "REJECTED"

		var explanation string
		if len(dec.Reasons) > 0 {
			explanation = dec.Reasons[0]
		} else if len(dec.Warnings) > 0 {
			explanation = dec.Warnings[0]
		} else {
			explanation = "Clean and policy compliant"
		}

		records = append(records, &GeneratedFilePolicyRecord{
			ScenarioID:               tc.ID,
			ScenarioDescription:      tc.Description,
			HasModifiedTrackedSource: tc.HasModifiedTrackedSource,
			UntrackedFilePath:        fmtList(tc.UntrackedFiles),
			DeclaredPatterns:         tc.DeclaredPatterns,
			MatchesDeclaredPattern:   !isFP && !isFN,
			CreatedDuringBuild:       true,
			ExpectedVerdict:          tc.ExpectedVerdict,
			ObservedVerdict:          observedVerdict,
			IsFalsePositive:          isFP,
			IsFalseNegative:          isFN,
			Explanation:              explanation,
		})
	}

	return records
}

func fmtList(l []string) string {
	if len(l) == 0 {
		return "none"
	}
	return l[0]
}
