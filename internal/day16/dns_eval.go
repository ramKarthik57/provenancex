package day16

import (
	"fmt"

	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/decision"
	"github.com/ramKarthik57/provenancex/internal/network"
	"github.com/ramKarthik57/provenancex/internal/policy"
	"github.com/ramKarthik57/provenancex/internal/process"
	"github.com/ramKarthik57/provenancex/internal/remediation"
)

// DNSEvalTestCase defines a DNS subdomain test scenario
type DNSEvalTestCase struct {
	Domain              string
	AllowedSuffix       string
	IsTunnelingAttack   bool
	HasExecutionAnomaly bool
	ExpectedVerdict     string
	Description         string
}

// GetDNSEvalTestCases returns a diverse suite of normal, CDN, and tunneling DNS queries
func GetDNSEvalTestCases() []DNSEvalTestCase {
	return []DNSEvalTestCase{
		// 1. Legitimate official subdomains
		{Domain: "proxy.golang.org", AllowedSuffix: "golang.org", IsTunnelingAttack: false, HasExecutionAnomaly: false, ExpectedVerdict: "TRUSTED", Description: "Standard Go proxy registry"},
		{Domain: "sum.golang.org", AllowedSuffix: "golang.org", IsTunnelingAttack: false, HasExecutionAnomaly: false, ExpectedVerdict: "TRUSTED", Description: "Go checksum database"},
		{Domain: "pkg.go.dev", AllowedSuffix: "pkg.go.dev", IsTunnelingAttack: false, HasExecutionAnomaly: false, ExpectedVerdict: "TRUSTED", Description: "Go package documentation root"},
		{Domain: "api.github.com", AllowedSuffix: "github.com", IsTunnelingAttack: false, HasExecutionAnomaly: false, ExpectedVerdict: "TRUSTED", Description: "GitHub REST API endpoint"},
		{Domain: "cdn.jsdelivr.net", AllowedSuffix: "jsdelivr.net", IsTunnelingAttack: false, HasExecutionAnomaly: false, ExpectedVerdict: "TRUSTED", Description: "Public package CDN"},

		// 2. Legitimate nested / CDN subdomains
		{Domain: "us-east-1.registry.hub.docker.com", AllowedSuffix: "docker.com", IsTunnelingAttack: false, HasExecutionAnomaly: false, ExpectedVerdict: "TRUSTED", Description: "Multi-level Docker registry mirror"},
		{Domain: "production.cloudflare.docker.com", AllowedSuffix: "docker.com", IsTunnelingAttack: false, HasExecutionAnomaly: false, ExpectedVerdict: "TRUSTED", Description: "Cloudflare CDN frontend for Docker"},

		// 3. Evasive Subdomain Tunneling Attacks (under allowed suffix "pkg.go.dev" and "github.com")
		{Domain: "c2VjcmV0LWtleS1kYXRhLWV4Zmls.pkg.go.dev", AllowedSuffix: "pkg.go.dev", IsTunnelingAttack: true, HasExecutionAnomaly: true, ExpectedVerdict: "REJECTED", Description: "High-entropy base64 secret exfiltration via allowed Go domain"},
		{Domain: "7365637265745f746f6b656e5f686578.pkg.go.dev", AllowedSuffix: "pkg.go.dev", IsTunnelingAttack: true, HasExecutionAnomaly: true, ExpectedVerdict: "REJECTED", Description: "High-entropy hex-encoded token exfiltration via allowed domain"},
		{Domain: "this-is-an-abnormally-long-chunk-of-exfiltrated-payload-data.github.com", AllowedSuffix: "github.com", IsTunnelingAttack: true, HasExecutionAnomaly: true, ExpectedVerdict: "REJECTED", Description: "Excessively long label payload exfiltration"},
		{Domain: "chunk1.chunk2.chunk3.chunk4.chunk5.chunk6.pkg.go.dev", AllowedSuffix: "pkg.go.dev", IsTunnelingAttack: true, HasExecutionAnomaly: true, ExpectedVerdict: "REJECTED", Description: "Excessive label nesting depth fragmentation attack"},

		// 4. Standalone suspicious query (without execution anomaly) -> produces WARNING, not REJECTED (avoids false alarm)
		{Domain: "strange-high-entropy-x98f21bc90a.pkg.go.dev", AllowedSuffix: "pkg.go.dev", IsTunnelingAttack: false, HasExecutionAnomaly: false, ExpectedVerdict: "WARNING", Description: "Anomalous subdomain without execution anomaly renders WARNING, not REJECTED"},

		// 5. Low-entropy dictionary evasion attack (attempts to bypass entropy heuristic with plain dictionary words)
		// Documented boundary: single low-entropy word without anomaly remains bounded
		{Domain: "leak.pkg.go.dev", AllowedSuffix: "pkg.go.dev", IsTunnelingAttack: true, HasExecutionAnomaly: false, ExpectedVerdict: "TRUSTED", Description: "Adversarial evasion: low-entropy dictionary word bypasses heuristic without execution anomaly (Documented Bound)"},
	}
}

// EvaluateDNSTunneling evaluates subdomain tunneling heuristics and cross-layer correlation
func EvaluateDNSTunneling(correlator *correlation.Correlator, engine *decision.Engine) []*DNSTunnelingRecord {
	cases := GetDNSEvalTestCases()
	analyzer := network.NewSubdomainAnalyzer()
	pol := policy.DefaultPolicy()

	var records []*DNSTunnelingRecord

	for _, tc := range cases {
		analysis := analyzer.Analyze(tc.Domain, tc.AllowedSuffix)

		base := remediation.MakeBaseClean()
		dnsRec := &network.DNSQueryRecord{
			QueryDomain:          tc.Domain,
			QueryType:            "TXT",
			IsAllowed:            true, // Suffix matches allowlist!
			SubdomainStatus:      analysis.Status,
			SubdomainEntropy:     analysis.ShannonEntropy,
			SubdomainLabelLength: analysis.MaxLabelLength,
			AlertReason:          analysis.Reason,
		}

		base.NetworkAudit = &network.Evaluation{
			TotalConnections:  1,
			AllowedCount:      1,
			ViolationCount:    0,
			IsPolicyCompliant: true,
			DNSQueries:        []*network.DNSQueryRecord{dnsRec},
		}

		if tc.HasExecutionAnomaly {
			base.ProcessTree = &process.Tree{
				SuspiciousCount: 1,
				Processes: []*process.ProcessNode{
					{
						PID:          9001,
						Name:         "cmd.exe",
						CommandLine:  fmt.Sprintf("cmd.exe /c nslookup %s", tc.Domain),
						IsSuspicious: true,
						AlertReason:  "Suspicious background process invoking DNS resolution during build",
					},
				},
			}
		}

		corr := correlator.Correlate(base)
		dec := engine.Decide(corr, pol)

		observedVerdict := string(dec.Verdict)
		isCorrect := observedVerdict == tc.ExpectedVerdict

		records = append(records, &DNSTunnelingRecord{
			QueryDomain:         tc.Domain,
			AllowedSuffix:       tc.AllowedSuffix,
			SubdomainPrefix:     analysis.SubdomainPrefix,
			ShannonEntropy:      analysis.ShannonEntropy,
			MaxLabelLength:      analysis.MaxLabelLength,
			LabelNesting:        analysis.LabelCount,
			HexRatio:            analysis.HexRatio,
			HeuristicStatus:     string(analysis.Status),
			IsCorrelatedAttack:  tc.IsTunnelingAttack,
			HasExecutionAnomaly: tc.HasExecutionAnomaly,
			ObservedVerdict:     observedVerdict,
			ExpectedVerdict:     tc.ExpectedVerdict,
			IsCorrect:           isCorrect,
			Reason:              analysis.Reason,
		})
	}

	return records
}
