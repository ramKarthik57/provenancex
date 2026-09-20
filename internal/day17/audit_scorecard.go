package day17

// BuildFinalScorecard constructs the Day 17 audit scorecard evaluating publication readiness
func BuildFinalScorecard() []*ScorecardRow {
	return []*ScorecardRow{
		{
			Category:                  "Detection Capability & Recall",
			TargetSubsystem:           "Cross-Layer Decision Engine (All 12 Layers)",
			AuditResult:               "PASS_WITH_LIMITATION",
			KeyLimitationIdentified:   "98.75% recall post-remediation (vs 80.00% Day 12 baseline). Four empirical blind spots documented (ADV-HUNT-01 out-of-boundary paths, ADV-HUNT-03 user-mode sub-10ms processes, ADV-HUNT-04 transient races, ADV-HUNT-05 dictionary tunneling).",
			PublicationRecommendation: "PUBLISH_AS_BOUNDED_EMPIRICAL_EVALUATION. Eliminate all claims of unconditional 100% detection.",
		},
		{
			Category:                  "In-Memory Correlation Latency",
			TargetSubsystem:           "Correlation Engine (internal/correlation)",
			AuditResult:               "PASS",
			KeyLimitationIdentified:   "12.4 µs mean latency accurately reflects pure algorithmic reconciliation of in-memory evidence structs. Does not include disk streaming or compilation overhead.",
			PublicationRecommendation: "PUBLISH_WITH_DISENTANGLED_SCOPE. Clearly label as in-memory algorithmic speed, not total build pipeline latency.",
		},
		{
			Category:                  "End-to-End Build Overhead",
			TargetSubsystem:           "Telemetry Layer + Wrapper CLI",
			AuditResult:               "PASS",
			KeyLimitationIdentified:   "0.24% relative overhead (~2.4 ms) on physical Go builds. Disk streaming hash verification on release binaries >100MB requires up to 48.2 ms.",
			PublicationRecommendation: "PUBLISH_AS_DEMONSTRATED_LOW_OVERHEAD. Validate as practically non-disruptive to CI/CD workflows.",
		},
		{
			Category:                  "Trust Graph DAG & Lineage",
			TargetSubsystem:           "Layer 2 Trust Graph (internal/graph)",
			AuditResult:               "PASS",
			KeyLimitationIdentified:   "100% acyclic DAG verification and deterministic topological break localization validated across all test campaigns.",
			PublicationRecommendation: "PUBLISH_AS_FORMAL_SYSTEM_FOUNDATION. Core formal property is rigorously supported.",
		},
		{
			Category:                  "Temporal Consistency Forensics",
			TargetSubsystem:           "Layer 5 Temporal Analyzer (internal/temporal)",
			AuditResult:               "PASS_WITH_LIMITATION",
			KeyLimitationIdentified:   "Causal ordering and retroactive timestamp modifications reliably detected. Sub-millisecond drift between distributed uncoordinated runners cannot be detected without PTP.",
			PublicationRecommendation: "PUBLISH_WITH_CLOCK_SKEW_BOUNDARY. Note host monotonic clock dependency.",
		},
		{
			Category:                  "Binary Structural Forensics",
			TargetSubsystem:           "Layer 9 Binary Forensics (internal/forensics)",
			AuditResult:               "PASS",
			KeyLimitationIdentified:   "Header structure, high-entropy section injection (>7.2 Shannon), and authenticode signature stripping verified. Low-entropy payload injection requires dynamic analysis.",
			PublicationRecommendation: "PUBLISH_AS_STRUCTURAL_FORENSIC_LAYER. Multi-tier complement to runtime telemetry.",
		},
		{
			Category:                  "Standalone Air-Gapped Verifier",
			TargetSubsystem:           "cmd/provenancex-verifier (Air-Gapped Binary)",
			AuditResult:               "PASS",
			KeyLimitationIdentified:   "100% tamper detection across bit-flips, signature corruption, and provenance mismatches with 0 network socket calls. Out-of-band trust root key distribution required.",
			PublicationRecommendation: "PUBLISH_AS_INDEPENDENT_VERIFIER. 'Build system does not verify itself' invariant verified.",
		},
		{
			Category:                  "Telemetry Observability Boundary",
			TargetSubsystem:           "Layers 6, 7, 8 (Process, Filesystem, Network)",
			AuditResult:               "PASS_WITH_LIMITATION",
			KeyLimitationIdentified:   "Complete observability requires Administrator Kernel ETW. Non-admin user-mode fallback exhibits documented sub-10ms process and transient file race blind spots.",
			PublicationRecommendation: "PUBLISH_WITH_THREE_TIER_THREAT_MODEL. Document kernel vs user-mode capabilities explicitly.",
		},
		{
			Category:                  "Adversarial Generalization",
			TargetSubsystem:           "Mutation Engine (internal/mutation, internal/generalization)",
			AuditResult:               "PASS_WITH_LIMITATION",
			KeyLimitationIdentified:   "100% detection across 11 unseen scenarios and 3 composed attack scenarios on evaluated fixtures. Out-of-boundary file activity evades detection.",
			PublicationRecommendation: "PUBLISH_WITH_EXPLICIT_BOUNDARY. Highlight multi-layer synergy while acknowledging spatial boundary limits.",
		},
		{
			Category:                  "Benign Operational Stability",
			TargetSubsystem:           "Policy Engine (internal/policy)",
			AuditResult:               "PASS",
			KeyLimitationIdentified:   "0 false alarms across 1,000 trials with declared in-tree generated path policy. Undeclared in-tree generated files trigger false positives.",
			PublicationRecommendation: "PUBLISH_AS_HIGH_SPECIFICITY_ENGINE. Emphasize importance of generated file policy declarations.",
		},
	}
}
