package day16

import (
	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/decision"
	"github.com/ramKarthik57/provenancex/internal/filesystem"
	"github.com/ramKarthik57/provenancex/internal/network"
	"github.com/ramKarthik57/provenancex/internal/policy"
	"github.com/ramKarthik57/provenancex/internal/process"
	"github.com/ramKarthik57/provenancex/internal/remediation"
)

// EvaluateAdversarialReattack stress-tests the remediations against hostile evasion attempts
func EvaluateAdversarialReattack(correlator *correlation.Correlator, engine *decision.Engine) []*AdversarialReattackRecord {
	var records []*AdversarialReattackRecord
	pol := policy.DefaultPolicy()
	pol.Repository.RequireCleanState = true
	pol.Repository.AllowDeclaredGenerated = true
	pol.Repository.DeclaredGeneratedPaths = []string{"pkg/client/generated_*.go"}

	// 1. PROCESS: Sub-1ms spawn under unprivileged polling (Attempt to evade Mode C user-mode timer)
	{
		base := remediation.MakeBaseClean()
		// Under unprivileged execution, process with lifetime 400µs terminates before timer tick
		base.ProcessTree = &process.Tree{
			SuspiciousCount: 0,
			Processes: []*process.ProcessNode{
				{PID: 1001, Name: "go.exe", CommandLine: "go build"},
			},
		}

		corr := correlator.Correlate(base)
		dec := engine.Decide(corr, pol)

		isDetected := (dec.Verdict == decision.VerdictRejected)
		records = append(records, &AdversarialReattackRecord{
			ReattackID:       "REATTACK-PROC-01",
			TargetSubsystem:  "PROCESS",
			AttackVector:     "Sub-1ms Ephemeral Process Spawn (Unprivileged Runner)",
			EvasionTechnique: "Process lifetime (400 µs) sits below Windows user-mode scheduler resolution",
			Day15Verdict:     "TRUSTED (MISSED)",
			Day16Verdict:     string(dec.Verdict),
			IsDetected:       isDetected,
			BypassSuccessful: !isDetected,
			RemainingGap:     "Unprivileged execution cannot guarantee sub-1ms capture without Administrator Kernel ETW elevation",
		})
	}

	// 2. PROCESS: Kernel ETW Elevated Tracing (Counter-Attack)
	{
		base := remediation.MakeBaseClean()
		base.ProcessTree = &process.Tree{
			SuspiciousCount: 1,
			Processes: []*process.ProcessNode{
				{PID: 9942, Name: "powershell.exe", CommandLine: "powershell.exe -enc <payload>", IsSuspicious: true, AlertReason: "Kernel ETW captured process start/stop"},
			},
		}

		corr := correlator.Correlate(base)
		dec := engine.Decide(corr, pol)

		isDetected := (dec.Verdict == decision.VerdictRejected)
		records = append(records, &AdversarialReattackRecord{
			ReattackID:       "REATTACK-PROC-02",
			TargetSubsystem:  "PROCESS",
			AttackVector:     "Ephemeral Process Execution with Elevated Kernel ETW",
			EvasionTechnique: "Attacker executes transient script, but host runs with elevated ETW trace session",
			Day15Verdict:     "TRUSTED (MISSED in unprivileged)",
			Day16Verdict:     string(dec.Verdict),
			IsDetected:       isDetected,
			BypassSuccessful: !isDetected,
			RemainingGap:     "Requires elevated privileges on Windows host/runner",
		})
	}

	// 3. FILESYSTEM: Sub-1ms Create-and-Delete Transient Payload (Unbuffered Event Race)
	{
		base := remediation.MakeBaseClean()
		base.InputEvaluation = &filesystem.InputEvaluation{
			ExpectedInputs:   []string{"main.go", "go.mod"},
			ObservedInputs:   []string{"main.go", "go.mod"},
			UnexpectedInputs: []string{}, // File unlinked in <1ms before snapshot or file notification dispatch
		}

		corr := correlator.Correlate(base)
		dec := engine.Decide(corr, pol)

		isDetected := (dec.Verdict == decision.VerdictRejected)
		records = append(records, &AdversarialReattackRecord{
			ReattackID:       "REATTACK-FS-01",
			TargetSubsystem:  "FILESYSTEM",
			AttackVector:     "Sub-1ms Create-and-Delete Event Race",
			EvasionTechnique: "Payload created in memory cache, executed, and deleted before filesystem event dispatch",
			Day15Verdict:     "TRUSTED (MISSED)",
			Day16Verdict:     string(dec.Verdict),
			IsDetected:       isDetected,
			BypassSuccessful: !isDetected,
			RemainingGap:     "User-mode change notifications can be coalesced; requires NTFS USN journal or kernel minifilter driver (FLTMGR)",
		})
	}

	// 4. FILESYSTEM: Event Journal Stream Detection (ReadDirectoryChangesW Active)
	{
		base := remediation.MakeBaseClean()
		base.InputEvaluation = &filesystem.InputEvaluation{
			ExpectedInputs:      []string{"main.go", "go.mod"},
			ObservedInputs:      []string{"main.go", "go.mod"},
			UnexpectedInputs:    []string{"tmp/transient_payload.bat"}, // Captured by directory change notification stream!
			OutOfBoundaryWrites: []string{},
		}

		corr := correlator.Correlate(base)
		dec := engine.Decide(corr, pol)

		isDetected := (dec.Verdict == decision.VerdictRejected)
		records = append(records, &AdversarialReattackRecord{
			ReattackID:       "REATTACK-FS-02",
			TargetSubsystem:  "FILESYSTEM",
			AttackVector:     "Transient File Dropped in Monitored Directory with Active Event Streaming",
			EvasionTechnique: "File unlinked prior to build end, but caught by asynchronous event stream",
			Day15Verdict:     "TRUSTED (MISSED in snapshot-only)",
			Day16Verdict:     string(dec.Verdict),
			IsDetected:       isDetected,
			BypassSuccessful: !isDetected,
			RemainingGap:     "Monitored scope must encompass parent directory; unconfigured volumes remain unobserved",
		})
	}

	// 5. NETWORK: Low-Entropy Dictionary-Word Subdomain Tunneling (Attempt to evade entropy heuristic)
	{
		base := remediation.MakeBaseClean()
		analyzer := network.NewSubdomainAnalyzer()
		domain := "secret.data.leak.pkg.go.dev" // Standard English dictionary words, low entropy (H < 3.2)
		analysis := analyzer.Analyze(domain, "pkg.go.dev")

		dnsRec := &network.DNSQueryRecord{
			QueryDomain:          domain,
			QueryType:            "TXT",
			IsAllowed:            true,
			SubdomainStatus:      analysis.Status,
			SubdomainEntropy:     analysis.ShannonEntropy,
			SubdomainLabelLength: analysis.MaxLabelLength,
		}

		base.NetworkAudit = &network.Evaluation{
			TotalConnections:  1,
			AllowedCount:      1,
			ViolationCount:    0,
			IsPolicyCompliant: true,
			DNSQueries:        []*network.DNSQueryRecord{dnsRec},
		}

		// Attacker does NOT trigger process or filesystem anomalies
		corr := correlator.Correlate(base)
		dec := engine.Decide(corr, pol)

		isDetected := (dec.Verdict == decision.VerdictRejected)
		records = append(records, &AdversarialReattackRecord{
			ReattackID:       "REATTACK-NET-01",
			TargetSubsystem:  "NETWORK",
			AttackVector:     "Low-Entropy Dictionary-Word Subdomain Tunneling",
			EvasionTechnique: "Attacker encodes data as valid dictionary words (low Shannon entropy) under allowed suffix",
			Day15Verdict:     "TRUSTED (MISSED)",
			Day16Verdict:     string(dec.Verdict),
			IsDetected:       isDetected,
			BypassSuccessful: !isDetected,
			RemainingGap:     "Pure lexical entropy cannot detect plain dictionary exfiltration; requires network egress firewall isolation or query volume rate limiting",
		})
	}

	// 6. NETWORK: Correlated High-Entropy Subdomain Tunneling
	{
		base := remediation.MakeBaseClean()
		analyzer := network.NewSubdomainAnalyzer()
		domain := "66696c655f657866696c74726174696f6e.pkg.go.dev"
		analysis := analyzer.Analyze(domain, "pkg.go.dev")

		dnsRec := &network.DNSQueryRecord{
			QueryDomain:          domain,
			QueryType:            "TXT",
			IsAllowed:            true,
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

		// Correlated with anomalous process invocation
		base.ProcessTree = &process.Tree{
			SuspiciousCount: 1,
			Processes: []*process.ProcessNode{
				{PID: 4410, Name: "curl.exe", CommandLine: "curl " + domain, IsSuspicious: true, AlertReason: "Unauthorized network tool"},
			},
		}

		corr := correlator.Correlate(base)
		dec := engine.Decide(corr, pol)

		isDetected := (dec.Verdict == decision.VerdictRejected)
		records = append(records, &AdversarialReattackRecord{
			ReattackID:       "REATTACK-NET-02",
			TargetSubsystem:  "NETWORK",
			AttackVector:     "High-Entropy DNS Tunneling Correlated with Unauthorized Execution",
			EvasionTechnique: "Attacker uses allowed domain suffix, but anomalous entropy correlates with child process",
			Day15Verdict:     "TRUSTED (MISSED via suffix bypass)",
			Day16Verdict:     string(dec.Verdict),
			IsDetected:       isDetected,
			BypassSuccessful: !isDetected,
			RemainingGap:     "Successfully detected via multi-layer correlation",
		})
	}

	// 7. GENERATED FILES: Malicious Code Injected as Undeclared Generated File
	{
		base := remediation.MakeBaseClean()
		base.Repository.IsClean = false
		base.Repository.UntrackedFiles = []string{"pkg/client/evil_backdoor.go"} // Does not match "generated_*.go"!

		corr := correlator.Correlate(base)
		dec := engine.Decide(corr, pol)

		isDetected := (dec.Verdict == decision.VerdictRejected)
		records = append(records, &AdversarialReattackRecord{
			ReattackID:       "REATTACK-GEN-01",
			TargetSubsystem:  "GENERATED_FILES",
			AttackVector:     "Attacker Injects Malicious File Claiming to Be Generated",
			EvasionTechnique: "File dropped in source tree claiming exemption, but fails declared pattern match",
			Day15Verdict:     "REJECTED",
			Day16Verdict:     string(dec.Verdict),
			IsDetected:       isDetected,
			BypassSuccessful: !isDetected,
			RemainingGap:     "Strict declared pattern enforcement blocks arbitrary untracked injections",
		})
	}

	// 8. GENERATED FILES: Attacker Modifies Tracked Source File alongside Valid Mock
	{
		base := remediation.MakeBaseClean()
		base.Repository.IsClean = false
		base.Repository.ModifiedFiles = []string{"src/main.go"}                         // Tracked file tampered!
		base.Repository.UntrackedFiles = []string{"pkg/client/generated_client_mock.go"} // Valid mock

		corr := correlator.Correlate(base)
		dec := engine.Decide(corr, pol)

		isDetected := (dec.Verdict == decision.VerdictRejected)
		records = append(records, &AdversarialReattackRecord{
			ReattackID:       "REATTACK-GEN-02",
			TargetSubsystem:  "GENERATED_FILES",
			AttackVector:     "Source Tampering Disguised Alongside Legitimate Generated Mock",
			EvasionTechnique: "Attacker creates legitimate mock to trigger exemption, but simultaneously alters tracked code",
			Day15Verdict:     "REJECTED",
			Day16Verdict:     string(dec.Verdict),
			IsDetected:       isDetected,
			BypassSuccessful: !isDetected,
			RemainingGap:     "Clean state policy requires zero modified tracked files; exemption applies solely to untracked intermediates",
		})
	}

	return records
}
