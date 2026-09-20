package day16

import (
	"fmt"
	"time"

	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/decision"
	"github.com/ramKarthik57/provenancex/internal/network"
	"github.com/ramKarthik57/provenancex/internal/policy"
	"github.com/ramKarthik57/provenancex/internal/process"
	"github.com/ramKarthik57/provenancex/internal/remediation"
)

// BenignScenarioDef defines one of the 10 benign operational scenarios
type BenignScenarioDef struct {
	Category    string
	Name        string
	SetupFunc   func(base *correlation.CorrelationInput, pol *policy.Policy, caseIdx int)
	Explanation string
}

// GetBenignScenarios returns the 10 realistic operational scenarios for the 1,000-trial campaign
func GetBenignScenarios() []BenignScenarioDef {
	return []BenignScenarioDef{
		{
			Category: "COMPILATION",
			Name:     "Standard Go Clean Build",
			SetupFunc: func(base *correlation.CorrelationInput, pol *policy.Policy, caseIdx int) {
				// Pure baseline build
			},
			Explanation: "Standard go build execution without drift",
		},
		{
			Category: "GENERATED_FILES",
			Name:     "Declared Generated Unit Test Mocks",
			SetupFunc: func(base *correlation.CorrelationInput, pol *policy.Policy, caseIdx int) {
				pol.Repository.AllowDeclaredGenerated = true
				pol.Repository.DeclaredGeneratedPaths = []string{"pkg/mocks/generated_*.go"}
				base.Repository.IsClean = false
				base.Repository.UntrackedFiles = []string{fmt.Sprintf("pkg/mocks/generated_mock_%d.go", caseIdx)}
			},
			Explanation: "Legitimate code generator creates declared test mock during build",
		},
		{
			Category: "GENERATED_FILES",
			Name:     "Automated API Documentation Generator",
			SetupFunc: func(base *correlation.CorrelationInput, pol *policy.Policy, caseIdx int) {
				pol.Repository.AllowDeclaredGenerated = true
				pol.Repository.DeclaredGeneratedPaths = []string{"docs/generated/*.md"}
				base.Repository.IsClean = false
				base.Repository.UntrackedFiles = []string{fmt.Sprintf("docs/generated/api_v%d.md", caseIdx%5+1)}
			},
			Explanation: "In-tree markdown generator producing API documentation",
		},
		{
			Category: "EXECUTION",
			Name:     "Compiler Build Cache Hit (Sub-50ms)",
			SetupFunc: func(base *correlation.CorrelationInput, pol *policy.Policy, caseIdx int) {
				base.Execution.Duration = time.Duration(15+caseIdx%30) * time.Millisecond
			},
			Explanation: "Incremental build with go-build cache hit resulting in fast compile",
		},
		{
			Category: "FILESYSTEM",
			Name:     "Standard OS %TEMP% Allocation",
			SetupFunc: func(base *correlation.CorrelationInput, pol *policy.Policy, caseIdx int) {
				// Compiler creates temp file in standard temp path
				base.Environment.EnvironmentVars["TEMP"] = "C:\\Users\\Runner\\AppData\\Local\\Temp"
			},
			Explanation: "Build compiler allocates scratch file in registered user temp directory",
		},
		{
			Category: "NETWORK",
			Name:     "Standard Package Registry DNS Resolution",
			SetupFunc: func(base *correlation.CorrelationInput, pol *policy.Policy, caseIdx int) {
				analyzer := network.NewSubdomainAnalyzer()
				domain := "proxy.golang.org"
				analysis := analyzer.Analyze(domain, "golang.org")
				base.NetworkAudit.DNSQueries = []*network.DNSQueryRecord{
					{
						QueryDomain:          domain,
						QueryType:            "A",
						IsAllowed:            true,
						SubdomainStatus:      analysis.Status,
						SubdomainEntropy:     analysis.ShannonEntropy,
						SubdomainLabelLength: analysis.MaxLabelLength,
					},
				}
			},
			Explanation: "Standard UDP/53 query for authorized Go proxy registry",
		},
		{
			Category: "NETWORK",
			Name:     "Legitimate Nested CDN Registry Mirror",
			SetupFunc: func(base *correlation.CorrelationInput, pol *policy.Policy, caseIdx int) {
				analyzer := network.NewSubdomainAnalyzer()
				domain := "us-east-1.registry.hub.docker.com"
				analysis := analyzer.Analyze(domain, "docker.com")
				base.NetworkAudit.DNSQueries = []*network.DNSQueryRecord{
					{
						QueryDomain:          domain,
						QueryType:            "A",
						IsAllowed:            true,
						SubdomainStatus:      analysis.Status,
						SubdomainEntropy:     analysis.ShannonEntropy,
						SubdomainLabelLength: analysis.MaxLabelLength,
					},
				}
			},
			Explanation: "Hierarchical multi-level domain for official package mirror",
		},
		{
			Category: "PROCESS",
			Name:     "Transient Helper Tool Execution (git rev-parse)",
			SetupFunc: func(base *correlation.CorrelationInput, pol *policy.Policy, caseIdx int) {
				base.ProcessTree = &process.Tree{
					SuspiciousCount: 0,
					Processes: []*process.ProcessNode{
						{PID: 1000 + caseIdx, Name: "git.exe", CommandLine: "git.exe rev-parse HEAD", IsSuspicious: false},
						{PID: 2000 + caseIdx, Name: "go.exe", CommandLine: "go.exe env GOROOT", IsSuspicious: false},
					},
				}
			},
			Explanation: "Short-lived authorized build helper processes querying VCS and toolchain metadata",
		},
		{
			Category: "FILESYSTEM",
			Name:     "Ephemeral Build Workspace Cache Scratchpad",
			SetupFunc: func(base *correlation.CorrelationInput, pol *policy.Policy, caseIdx int) {
				// Workspace scratchpad clean state
			},
			Explanation: "Compiler writing object files into declared output binary folder",
		},
		{
			Category: "ENVIRONMENT",
			Name:     "Cross-Host Runner Path Relocation",
			SetupFunc: func(base *correlation.CorrelationInput, pol *policy.Policy, caseIdx int) {
				base.Environment.EnvironmentVars["WORKSPACE"] = fmt.Sprintf("D:\\ci\\runner-%02d\\build", caseIdx%10+1)
			},
			Explanation: "CI agent checks out source code across distinct drive mount points",
		},
	}
}

// RunBenignCampaign executes the full 1,000-trial benign campaign across 10 scenarios x 100 cases
func RunBenignCampaign(correlator *correlation.Correlator, engine *decision.Engine) ([]*BenignCampaignRecord, int, int, float64) {
	scenarios := GetBenignScenarios()
	casesPerScenario := 100
	var records []*BenignCampaignRecord

	trialID := 1
	falsePositives := 0

	for _, sc := range scenarios {
		for i := 0; i < casesPerScenario; i++ {
			base := remediation.MakeBaseClean()
			pol := policy.DefaultPolicy()

			sc.SetupFunc(base, pol, i)

			start := time.Now()
			corr := correlator.Correlate(base)
			dec := engine.Decide(corr, pol)
			latencyUs := float64(time.Since(start).Nanoseconds()) / 1000.0

			isFP := (dec.Verdict == decision.VerdictRejected)
			if isFP {
				falsePositives++
			}

			records = append(records, &BenignCampaignRecord{
				TrialID:         trialID,
				Category:        sc.Category,
				ScenarioName:    sc.Name,
				Verdict:         string(dec.Verdict),
				IsFalsePositive: isFP,
				LatencyUs:       latencyUs,
			})

			trialID++
		}
	}

	totalTrials := len(records)
	fpRate := 0.0
	if totalTrials > 0 {
		fpRate = float64(falsePositives) / float64(totalTrials) * 100.0
	}

	return records, totalTrials, falsePositives, fpRate
}
