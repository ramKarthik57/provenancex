package graph

import (
	
	"strings"
	"time"

	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/evidence"
)

// NodeType represents the entity plane in the Trust Graph DAG
type NodeType string

const (
	NodeRepository         NodeType = "Repository"
	NodeCommit             NodeType = "Commit"
	NodeSourceTree         NodeType = "SourceTree"
	NodeDependencies       NodeType = "Dependencies"
	NodeBuildConfig        NodeType = "BuildConfig"
	NodeLockfile           NodeType = "Lockfile"
	NodeBuildEnvironment   NodeType = "BuildEnvironment"
	NodeBuildProcess       NodeType = "BuildProcess"
	NodeProcessTelemetry   NodeType = "ProcessTelemetry"
	NodeFilesystemTelemetry NodeType = "FilesystemTelemetry"
	NodeNetworkTelemetry   NodeType = "NetworkTelemetry"
	NodeArtifact           NodeType = "Artifact"
	NodeSBOM               NodeType = "SBOM"
	NodeProvenance         NodeType = "Provenance"
	NodeSignature          NodeType = "Signature"
	NodeReproducibility    NodeType = "Reproducibility"
	NodeVerification       NodeType = "Verification"
)

// Node represents a verified entity within the supply-chain DAG
type Node struct {
	ID                string                 `json:"id"`
	Type              NodeType               `json:"type"`
	Timestamp         time.Time              `json:"timestamp"`
	Hash              string                 `json:"hash"`
	Source            string                 `json:"source"`
	Classification    string                 `json:"classification"`
	VerificationState string                 `json:"verificationState"` // VERIFIED, CONTRADICTED, MISSING, UNOBSERVED
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

// Edge represents a directional causality or attestation relationship
type Edge struct {
	From              string    `json:"from"`
	To                string    `json:"to"`
	Relationship      string    `json:"relationship"` // generates, depends_on, executes, attests_to, signs, observes, verifies
	EvidenceID        string    `json:"evidenceId"`
	Timestamp         time.Time `json:"timestamp"`
	VerificationState string    `json:"verificationState"`
}

// TrustGraph represents the formal DAG of supply chain evidence
type TrustGraph struct {
	Nodes    map[string]*Node `json:"nodes"`
	Edges    []*Edge          `json:"edges"`
	RootID   string           `json:"rootId"`
	TargetID string           `json:"targetId"`
}

// NewTrustGraph initializes an empty evidence DAG
func NewTrustGraph() *TrustGraph {
	return &TrustGraph{
		Nodes: make(map[string]*Node),
		Edges: make([]*Edge, 0),
	}
}

// AddNode inserts a node into the graph
func (g *TrustGraph) AddNode(n *Node) {
	g.Nodes[n.ID] = n
}

// AddEdge inserts a directed edge into the graph
func (g *TrustGraph) AddEdge(e *Edge) {
	g.Edges = append(g.Edges, e)
}

// BuildFromCorrelation constructs the formal Trust Graph 2.0 DAG from correlation inputs
func BuildFromCorrelation(in *correlation.CorrelationInput, res *correlation.Result) *TrustGraph {
	g := NewTrustGraph()
	now := time.Now().UTC()

	// Helper to get status string
	getStatus := func(layer evidence.Layer) string {
		if res == nil || res.LayerStatuses == nil {
			return "UNVERIFIED"
		}
		st, ok := res.LayerStatuses[layer]
		if !ok {
			return "UNOBSERVED"
		}
		return string(st)
	}

	// 1. Repository & Commit
	repoID := "node-repo"
	commitID := "node-commit"
	repoHash := "unknown"
	commitHash := "unknown"
	if in.Repository != nil {
		repoHash = in.Repository.TreeSHA
		commitHash = in.Repository.CommitSHA
	}
	g.AddNode(&Node{
		ID:                repoID,
		Type:              NodeRepository,
		Timestamp:         now,
		Hash:              repoHash,
		Source:            "git-repository",
		Classification:    "source",
		VerificationState: getStatus(evidence.LayerSource),
	})
	g.AddNode(&Node{
		ID:                commitID,
		Type:              NodeCommit,
		Timestamp:         now,
		Hash:              commitHash,
		Source:            "git-commit",
		Classification:    "source",
		VerificationState: getStatus(evidence.LayerSource),
	})
	g.AddEdge(&Edge{
		From:         repoID,
		To:           commitID,
		Relationship: "contains_commit",
		EvidenceID:   "EV-REPO-01",
		Timestamp:    now,
	})
	g.RootID = repoID

	// 2. Source Tree
	srcTreeID := "node-sourcetree"
	g.AddNode(&Node{
		ID:                srcTreeID,
		Type:              NodeSourceTree,
		Timestamp:         now,
		Hash:              commitHash,
		Source:            "working-tree",
		Classification:    "source",
		VerificationState: getStatus(evidence.LayerSource),
	})
	g.AddEdge(&Edge{
		From:         commitID,
		To:           srcTreeID,
		Relationship: "resolves_tree",
		EvidenceID:   "EV-SRC-01",
		Timestamp:    now,
	})

	// 3. Dependencies & Lockfile
	depID := "node-dependencies"
	lockID := "node-lockfile"
	g.AddNode(&Node{
		ID:                depID,
		Type:              NodeDependencies,
		Timestamp:         now,
		Source:            "dependency-manifest",
		Classification:    "dependency",
		VerificationState: getStatus(evidence.LayerDependencies),
	})
	g.AddNode(&Node{
		ID:                lockID,
		Type:              NodeLockfile,
		Timestamp:         now,
		Source:            "lockfile",
		Classification:    "dependency",
		VerificationState: getStatus(evidence.LayerLockfile),
	})
	g.AddEdge(&Edge{From: srcTreeID, To: depID, Relationship: "declares_dependencies", Timestamp: now})
	g.AddEdge(&Edge{From: depID, To: lockID, Relationship: "locks_to", Timestamp: now})

	// 4. Build Config & Environment
	cfgID := "node-buildconfig"
	envID := "node-environment"
	envHash := "default-env"
	if in.Environment != nil {
		envHash = in.Environment.FingerprintHash
	}
	g.AddNode(&Node{
		ID:                cfgID,
		Type:              NodeBuildConfig,
		Timestamp:         now,
		Source:            "build-script",
		Classification:    "build",
		VerificationState: getStatus(evidence.LayerBuild),
	})
	g.AddNode(&Node{
		ID:                envID,
		Type:              NodeBuildEnvironment,
		Timestamp:         now,
		Hash:              envHash,
		Source:            "environment-collector",
		Classification:    "environment",
		VerificationState: getStatus(evidence.LayerEnvironment),
	})
	g.AddEdge(&Edge{From: srcTreeID, To: cfgID, Relationship: "defines_build_recipe", Timestamp: now})
	g.AddEdge(&Edge{From: cfgID, To: envID, Relationship: "requires_environment", Timestamp: now})

	// 5. Build Process
	procID := "node-buildprocess"
	g.AddNode(&Node{
		ID:                procID,
		Type:              NodeBuildProcess,
		Timestamp:         now,
		Source:            "execution-engine",
		Classification:    "execution",
		VerificationState: getStatus(evidence.LayerBuild),
	})
	g.AddEdge(&Edge{From: lockID, To: procID, Relationship: "feeds_input", Timestamp: now})
	g.AddEdge(&Edge{From: envID, To: procID, Relationship: "executes_in", Timestamp: now})

	// 6. Runtime Telemetry (Process, Filesystem, Network)
	teleProcID := "node-telemetry-proc"
	teleFileID := "node-telemetry-file"
	teleNetID := "node-telemetry-net"

	g.AddNode(&Node{
		ID:                teleProcID,
		Type:              NodeProcessTelemetry,
		Timestamp:         now,
		Source:            "process-collector",
		Classification:    "telemetry",
		VerificationState: getStatus(evidence.LayerProcess),
	})
	g.AddNode(&Node{
		ID:                teleFileID,
		Type:              NodeFilesystemTelemetry,
		Timestamp:         now,
		Source:            "filesystem-collector",
		Classification:    "telemetry",
		VerificationState: getStatus(evidence.LayerFilesystem),
	})
	g.AddNode(&Node{
		ID:                teleNetID,
		Type:              NodeNetworkTelemetry,
		Timestamp:         now,
		Source:            "network-collector",
		Classification:    "telemetry",
		VerificationState: getStatus(evidence.LayerNetwork),
	})

	g.AddEdge(&Edge{From: procID, To: teleProcID, Relationship: "spawns_subprocesses", Timestamp: now})
	g.AddEdge(&Edge{From: procID, To: teleFileID, Relationship: "mutates_filesystem", Timestamp: now})
	g.AddEdge(&Edge{From: procID, To: teleNetID, Relationship: "opens_sockets", Timestamp: now})

	// 7. Artifact
	artID := "node-artifact"
	artHash := "unknown"
	if in.Artifact != nil {
		artHash = in.Artifact.SHA256
	}
	g.AddNode(&Node{
		ID:                artID,
		Type:              NodeArtifact,
		Timestamp:         now,
		Hash:              artHash,
		Source:            "compiler-output",
		Classification:    "artifact",
		VerificationState: getStatus(evidence.LayerArtifact),
	})
	g.TargetID = artID

	g.AddEdge(&Edge{From: teleProcID, To: artID, Relationship: "produces", Timestamp: now})
	g.AddEdge(&Edge{From: teleFileID, To: artID, Relationship: "writes_bytes", Timestamp: now})
	g.AddEdge(&Edge{From: teleNetID, To: artID, Relationship: "influences", Timestamp: now})

	// 8. SBOM & Provenance
	sbomID := "node-sbom"
	provID := "node-provenance"
	g.AddNode(&Node{
		ID:                sbomID,
		Type:              NodeSBOM,
		Timestamp:         now,
		Source:            "sbom-generator",
		Classification:    "attestation",
		VerificationState: getStatus(evidence.LayerSBOM),
	})
	g.AddNode(&Node{
		ID:                provID,
		Type:              NodeProvenance,
		Timestamp:         now,
		Source:            "slsa-attestation",
		Classification:    "attestation",
		VerificationState: getStatus(evidence.LayerProvenance),
	})
	g.AddEdge(&Edge{From: artID, To: sbomID, Relationship: "enumerated_by", Timestamp: now})
	g.AddEdge(&Edge{From: artID, To: provID, Relationship: "attested_by", Timestamp: now})

	// 9. Digital Signature
	sigID := "node-signature"
	g.AddNode(&Node{
		ID:                sigID,
		Type:              NodeSignature,
		Timestamp:         now,
		Source:            "cryptographic-signature",
		Classification:    "signature",
		VerificationState: getStatus(evidence.LayerSignature),
	})
	g.AddEdge(&Edge{From: sbomID, To: sigID, Relationship: "envelops", Timestamp: now})
	g.AddEdge(&Edge{From: provID, To: sigID, Relationship: "signs_attestation", Timestamp: now})

	// 10. Verification Verdict Node
	verifID := "node-verification"
	verdictState := "VERIFIED"
	if res != nil && (!res.IsConsistent || len(res.Contradictions) > 0) {
		verdictState = "CONTRADICTED"
	}
	g.AddNode(&Node{
		ID:                verifID,
		Type:              NodeVerification,
		Timestamp:         now,
		Source:            "decision-engine",
		Classification:    "decision",
		VerificationState: verdictState,
	})
	g.AddEdge(&Edge{From: sigID, To: verifID, Relationship: "evaluated_by", Timestamp: now})

	return g
}

// FindPath traces the causal chain from root node to target node
func (g *TrustGraph) FindPath(startID, endID string) []*Node {
	path := make([]*Node, 0)
	curr := startID
	visited := make(map[string]bool)

	for curr != "" && !visited[curr] {
		visited[curr] = true
		if node, exists := g.Nodes[curr]; exists {
			path = append(path, node)
		}
		if curr == endID {
			break
		}

		next := ""
		for _, edge := range g.Edges {
			if edge.From == curr && !visited[edge.To] {
				next = edge.To
				break
			}
		}
		curr = next
	}

	return path
}

// GetContradictionNodes returns all graph nodes in a contradicted or failing state
func (g *TrustGraph) GetContradictionNodes() []*Node {
	contradictions := make([]*Node, 0)
	for _, node := range g.Nodes {
		if node.VerificationState == "CONTRADICTED" || node.VerificationState == "MISMATCH" || node.VerificationState == "FAILED" {
			contradictions = append(contradictions, node)
		}
	}
	return contradictions
}

// RenderASCII returns an ASCII visualization of the Trust Graph DAG
func (g *TrustGraph) RenderASCII() string {
	var sb strings.Builder
	sb.WriteString("================================================================================\n")
	sb.WriteString("                        PROVENANCEX TRUST GRAPH 2.0 (DAG)                       \n")
	sb.WriteString("================================================================================\n")
	sb.WriteString("Repository [" + g.safeState("node-repo") + "]\n")
	sb.WriteString("    ↓ (contains_commit)\n")
	sb.WriteString("Commit [" + g.safeState("node-commit") + "]\n")
	sb.WriteString("    ↓ (resolves_tree)\n")
	sb.WriteString("Source Tree [" + g.safeState("node-sourcetree") + "]\n")
	sb.WriteString("    ├── Dependencies [" + g.safeState("node-dependencies") + "]  ──> Lockfile [" + g.safeState("node-lockfile") + "]\n")
	sb.WriteString("    └── Build Config [" + g.safeState("node-buildconfig") + "]  ──> Environment [" + g.safeState("node-environment") + "]\n")
	sb.WriteString("                 ↘                    ↙\n")
	sb.WriteString("              Build Process [" + g.safeState("node-buildprocess") + "]\n")
	sb.WriteString("              /           |           \\\n")
	sb.WriteString("     Process [" + g.safeState("node-telemetry-proc") + "]   Files [" + g.safeState("node-telemetry-file") + "]   Network [" + g.safeState("node-telemetry-net") + "]\n")
	sb.WriteString("              \\           |           /\n")
	sb.WriteString("               Artifact Binary [" + g.safeState("node-artifact") + "]\n")
	sb.WriteString("                /             \\\n")
	sb.WriteString("          SBOM [" + g.safeState("node-sbom") + "]     Provenance [" + g.safeState("node-provenance") + "]\n")
	sb.WriteString("                \\             /\n")
	sb.WriteString("             Digital Signature [" + g.safeState("node-signature") + "]\n")
	sb.WriteString("                      ↓\n")
	sb.WriteString("             Final Verification Decision [" + g.safeState("node-verification") + "]\n")
	sb.WriteString("================================================================================\n")
	return sb.String()
}

func (g *TrustGraph) safeState(id string) string {
	if n, ok := g.Nodes[id]; ok {
		return string(n.VerificationState)
	}
	return "UNOBSERVED"
}
