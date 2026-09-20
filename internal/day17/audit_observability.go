package day17

// BuildObservabilityAudit constructs the audited privilege and observability records
func BuildObservabilityAudit() []*ObservabilityAuditRow {
	return []*ObservabilityAuditRow{
		{
			TelemetrySubsystem:          "Process Lifecycle Telemetry (Kernel ETW)",
			Mechanism:                   "Microsoft-Windows-Kernel-Process (TraceEventSession)",
			ExecutionPrivilege:          "Administrator (Elevated)",
			EphemeralThresholdMs:        0.01,
			CatchRateTestedPct:          100.0,
			LimitationDiscovered:        "Requires elevated Windows administrative tokens; cannot run in rootless/unprivileged container runners.",
			RemediationOrResidualStatus: "VERIFIED_ELEVATED_CAPABILITY",
		},
		{
			TelemetrySubsystem:          "Process Lifecycle Telemetry (User-Mode Polling)",
			Mechanism:                   "CreateToolhelp32Snapshot / EnumProcesses Polling (10ms-100ms intervals)",
			ExecutionPrivilege:          "Non-Administrator (User-Mode CI)",
			EphemeralThresholdMs:        10.0,
			CatchRateTestedPct:          62.5,
			LimitationDiscovered:        "ADV-HUNT-03: Sub-10ms ephemeral processes spawned by compiler scripts complete and exit between polling ticks undetected.",
			RemediationOrResidualStatus: "DOCUMENTED_RESIDUAL_LIMITATION",
		},
		{
			TelemetrySubsystem:          "Filesystem Event Stream (Kernel ETW)",
			Mechanism:                   "Microsoft-Windows-Kernel-File (Kernel Driver Callbacks)",
			ExecutionPrivilege:          "Administrator (Elevated)",
			EphemeralThresholdMs:        0.01,
			CatchRateTestedPct:          100.0,
			LimitationDiscovered:        "Requires administrative privilege; high event volume under compilation requires high-capacity ring buffers.",
			RemediationOrResidualStatus: "VERIFIED_ELEVATED_CAPABILITY",
		},
		{
			TelemetrySubsystem:          "Filesystem Diff & Change Notification",
			Mechanism:                   "ReadDirectoryChangesW + Pre/Post Build Working Tree Snapshot Comparison",
			ExecutionPrivilege:          "Non-Administrator (User-Mode CI)",
			EphemeralThresholdMs:        1.0,
			CatchRateTestedPct:          85.7,
			LimitationDiscovered:        "ADV-HUNT-04: Rapid create-and-delete operations occurring entirely within the build window leave identical final filesystem state.",
			RemediationOrResidualStatus: "DOCUMENTED_RESIDUAL_LIMITATION",
		},
		{
			TelemetrySubsystem:          "Filesystem Boundary Enforcement",
			Mechanism:                   "Path Canonicalization & Workspace Root Prefix Containment",
			ExecutionPrivilege:          "Any Privilege Tier",
			EphemeralThresholdMs:        0.0,
			CatchRateTestedPct:          90.0,
			LimitationDiscovered:        "ADV-HUNT-01: Build-time activity writing outside configured root directories (e.g. system temp or global cache) is unobserved unless configured.",
			RemediationOrResidualStatus: "BOUNDED_BY_CONFIGURATION",
		},
		{
			TelemetrySubsystem:          "Network Telemetry & DNS Exfiltration",
			Mechanism:                   "Multi-Feature Heuristic (Shannon Entropy >3.8, Label Length >32, Hex Ratio >0.6)",
			ExecutionPrivilege:          "User-Mode Socket Monitor / DNS Client",
			EphemeralThresholdMs:        0.0,
			CatchRateTestedPct:          92.3,
			LimitationDiscovered:        "ADV-HUNT-05: Low-entropy single dictionary-word subdomains (e.g. leak.pkg.go.dev) mimic legitimate traffic and evade entropy thresholds.",
			RemediationOrResidualStatus: "PARTIALLY_REMEDIATED_HEURISTIC",
		},
		{
			TelemetrySubsystem:          "Repository Cleanliness & In-Tree Generated Files",
			Mechanism:                   "Declared In-Tree Generated Path Patterns (mock_*.go, *_gen.go)",
			ExecutionPrivilege:          "Any Privilege Tier",
			EphemeralThresholdMs:        0.0,
			CatchRateTestedPct:          100.0,
			LimitationDiscovered:        "BENIGN-HUNT-04: Legitimate in-tree generated files not explicitly declared in project policy trigger false positive build failures.",
			RemediationOrResidualStatus: "REMEDIATED_WITH_DECLARED_POLICY",
		},
	}
}
