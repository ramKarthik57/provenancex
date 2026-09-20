package day16

import "time"

// ProcessLifetimeRecord captures ephemeral process observation under various privileges and modes
type ProcessLifetimeRecord struct {
	LifetimeRange    string  `json:"lifetimeRange"`
	DurationUs       int64   `json:"durationUs"`
	Privilege        string  `json:"privilege"`     // "Administrator" vs "Non-Administrator"
	TelemetryMode    string  `json:"telemetryMode"` // "Mode A: 100ms Polling", "Mode B: Kernel ETW", "Mode C: User-Mode High-Freq"
	ProcessObserved  bool    `json:"processObserved"`
	StartObserved    bool    `json:"startObserved"`
	StopObserved     bool    `json:"stopObserved"`
	ParentAttributed bool    `json:"parentAttributed"`
	Detected         bool    `json:"detected"`
	LatencyUs        float64 `json:"latencyUs"`
	EventLossPct     float64 `json:"eventLossPct"`
}

// FilesystemLifetimeRecord captures transient file event visibility vs final state observation
type FilesystemLifetimeRecord struct {
	LifetimeRange      string  `json:"lifetimeRange"`
	DurationUs         int64   `json:"durationUs"`
	TelemetryMode      string  `json:"telemetryMode"` // "Mode A: Snapshot/Delta", "Mode B: Change Notifications", "Mode C: USN Journal"
	CreateObserved     bool    `json:"createObserved"`
	WriteObserved      bool    `json:"writeObserved"`
	ModifyObserved     bool    `json:"modifyObserved"`
	DeleteObserved     bool    `json:"deleteObserved"`
	ProcessAttributed  bool    `json:"processAttributed"`
	Detected           bool    `json:"detected"`
	LatencyUs          float64 `json:"latencyUs"`
	FinalStateObserved bool    `json:"finalStateObserved"`
	EventObserved      bool    `json:"eventObserved"`
}

// DNSTunnelingRecord evaluates subdomain tunneling heuristics and cross-layer correlation
type DNSTunnelingRecord struct {
	QueryDomain         string  `json:"queryDomain"`
	AllowedSuffix       string  `json:"allowedSuffix"`
	SubdomainPrefix     string  `json:"subdomainPrefix"`
	ShannonEntropy      float64 `json:"shannonEntropy"`
	MaxLabelLength      int     `json:"maxLabelLength"`
	LabelNesting        int     `json:"labelNesting"`
	HexRatio            float64 `json:"hexRatio"`
	HeuristicStatus     string  `json:"heuristicStatus"` // "NORMAL", "SUSPICIOUS", "UNOBSERVED"
	IsCorrelatedAttack  bool    `json:"isCorrelatedAttack"`
	HasExecutionAnomaly bool    `json:"hasExecutionAnomaly"`
	ObservedVerdict     string  `json:"observedVerdict"`
	ExpectedVerdict     string  `json:"expectedVerdict"`
	IsCorrect           bool    `json:"isCorrect"`
	Reason              string  `json:"reason"`
}

// GeneratedFilePolicyRecord tests in-tree generated files policy and provenance handling
type GeneratedFilePolicyRecord struct {
	ScenarioID               string   `json:"scenarioId"`
	ScenarioDescription      string   `json:"scenarioDescription"`
	HasModifiedTrackedSource bool     `json:"hasModifiedTrackedSource"`
	UntrackedFilePath        string   `json:"untrackedFilePath"`
	DeclaredPatterns         []string `json:"declaredPatterns"`
	MatchesDeclaredPattern   bool     `json:"matchesDeclaredPattern"`
	CreatedDuringBuild       bool     `json:"createdDuringBuild"`
	ExpectedVerdict          string   `json:"expectedVerdict"`
	ObservedVerdict          string   `json:"observedVerdict"`
	IsFalsePositive          bool     `json:"isFalsePositive"`
	IsFalseNegative          bool     `json:"isFalseNegative"`
	Explanation              string   `json:"explanation"`
}

// AdversarialReattackRecord documents hostile evasion attempts against the remediations
type AdversarialReattackRecord struct {
	ReattackID       string `json:"reattackId"`
	TargetSubsystem  string `json:"targetSubsystem"` // "PROCESS", "FILESYSTEM", "NETWORK", "GENERATED_FILES"
	AttackVector     string `json:"attackVector"`
	EvasionTechnique string `json:"evasionTechnique"`
	Day15Verdict     string `json:"day15Verdict"`
	Day16Verdict     string `json:"day16Verdict"`
	IsDetected       bool   `json:"isDetected"`
	BypassSuccessful bool   `json:"bypassSuccessful"`
	RemainingGap     string `json:"remainingGap"`
}

// BenignCampaignRecord captures individual trials from the 1,000+ benign campaign
type BenignCampaignRecord struct {
	TrialID         int     `json:"trialId"`
	Category        string  `json:"category"`
	ScenarioName    string  `json:"scenarioName"`
	Verdict         string  `json:"verdict"`
	IsFalsePositive bool    `json:"isFalsePositive"`
	LatencyUs       float64 `json:"latencyUs"`
}

// BlindSpotMatrixRecord tracks the formal blind spot status
type BlindSpotMatrixRecord struct {
	ID                   string  `json:"id"`
	BlindSpot            string  `json:"blindSpot"`
	Day15Recall          float64 `json:"day15Recall"`
	Remediation          string  `json:"remediation"`
	Day16Recall          float64 `json:"day16Recall"`
	ObservationBoundary  string  `json:"observationBoundary"`
	PrivilegeRequirement string  `json:"privilegeRequirement"`
	FalsePositiveImpact  string  `json:"falsePositiveImpact"`
	RemainingLimitation  string  `json:"remainingLimitation"`
	Status               string  `json:"status"` // REMEDIATED, PARTIALLY REMEDIATED, UNOBSERVABLE UNDER CURRENT ARCHITECTURE
}

// BeforeAfterRecord compares Day 15 pre-remediation vs Day 16 post-remediation
type BeforeAfterRecord struct {
	BlindSpotID    string  `json:"blindSpotId"`
	TotalTrials    int     `json:"totalTrials"`
	Day15_TP       int     `json:"day15Tp"`
	Day15_FN       int     `json:"day15Fn"`
	Day15_TN       int     `json:"day15Tn"`
	Day15_FP       int     `json:"day15Fp"`
	Day15_Recall   float64 `json:"day15Recall"`
	Day15_Prec     float64 `json:"day15Prec"`
	Day16_TP       int     `json:"day16Tp"`
	Day16_FN       int     `json:"day16Fn"`
	Day16_TN       int     `json:"day16Tn"`
	Day16_FP       int     `json:"day16Fp"`
	Day16_Recall   float64 `json:"day16Recall"`
	Day16_Prec     float64 `json:"day16Prec"`
	Day16_F1       float64 `json:"day16F1"`
	MeanLatencyUs  float64 `json:"meanLatencyUs"`
	P95LatencyUs   float64 `json:"p95LatencyUs"`
	P99LatencyUs   float64 `json:"p99LatencyUs"`
}

// PerformanceComparisonRecord documents system overhead impact
type PerformanceComparisonRecord struct {
	Subsystem       string  `json:"subsystem"`
	MetricName      string  `json:"metricName"`
	Day15Baseline   float64 `json:"day15Baseline"`
	Day16Remediated float64 `json:"day16Remediated"`
	DeltaAbsolute   float64 `json:"deltaAbsolute"`
	DeltaPercent    string  `json:"deltaPercent"`
	Unit            string  `json:"unit"`
	EngineeringCost string  `json:"engineeringCost"`
}

// ExperimentManifest captures complete metadata for reproducibility
type ExperimentManifest struct {
	Timestamp      time.Time `json:"timestamp"`
	Campaign       string    `json:"campaign"`
	GitCommit      string    `json:"gitCommit"`
	Branch         string    `json:"branch"`
	HostOS         string    `json:"hostOs"`
	GoVersion      string    `json:"goVersion"`
	TotalTrials    int       `json:"totalTrials"`
	BenignTrials   int       `json:"benignTrials"`
	AttackTrials   int       `json:"attackTrials"`
	ExecutionTimeS float64   `json:"executionTimeS"`
}
