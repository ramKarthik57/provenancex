package server

import (
		"encoding/json"
	"fmt"
		"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ramKarthik57/provenancex/internal/artifact"
	"github.com/ramKarthik57/provenancex/internal/bundle"
	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/decision"
	"github.com/ramKarthik57/provenancex/internal/delta"
	"github.com/ramKarthik57/provenancex/internal/evidence"
	"github.com/ramKarthik57/provenancex/internal/experiment"
	"github.com/ramKarthik57/provenancex/internal/policy"
	"github.com/ramKarthik57/provenancex/pkg/version"
)

// Config configures the HTTP API and dashboard server
type Config struct {
	Port       int
	WebDir     string
	PolicyPath string
}

// Server handles REST API requests and serves the web frontend
type Server struct {
	cfg        Config
	runner     *experiment.Runner
	correlator *correlation.Correlator
	engine     *decision.Engine
	policy     *policy.Policy
}

// NewServer constructs an HTTP dashboard server
func NewServer(cfg Config) (*Server, error) {
	var pol *policy.Policy
	if cfg.PolicyPath != "" {
		var err error
		pol, err = policy.LoadPolicy(cfg.PolicyPath)
		if err != nil {
			return nil, fmt.Errorf("failed loading policy: %w", err)
		}
	} else {
		pol = policy.DefaultPolicy()
	}

	return &Server{
		cfg:        cfg,
		runner:     experiment.NewRunner(pol),
		correlator: correlation.NewCorrelator(),
		engine:     decision.NewEngine(),
		policy:     pol,
	}, nil
}

// Start registers routes and begins listening for HTTP requests
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// API Routes
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/version", s.handleVersion)
	mux.HandleFunc("GET /api/v1/scenarios", s.handleListScenarios)
	mux.HandleFunc("POST /api/v1/scenarios/{id}/run", s.handleRunScenario)
	mux.HandleFunc("GET /api/v1/benchmark", s.handleBenchmark)
	mux.HandleFunc("POST /api/v1/verify", s.handleVerify)
	mux.HandleFunc("POST /api/v1/delta", s.handleDelta)

	// Static Web Frontend File Server
	webDir := s.cfg.WebDir
	if webDir == "" {
		webDir = "web/dist"
	}

	if absDir, err := filepath.Abs(webDir); err == nil {
		if _, err := os.Stat(absDir); err == nil {
			fs := http.FileServer(http.Dir(absDir))
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				// Fallback to index.html for SPA routing if file does not exist
				fPath := filepath.Join(absDir, filepath.Clean(r.URL.Path))
				if info, err := os.Stat(fPath); err != nil || info.IsDir() {
					http.ServeFile(w, r, filepath.Join(absDir, "index.html"))
					return
				}
				fs.ServeHTTP(w, r)
			})
		} else {
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{
					"status":  "ProvenanceX API active",
					"webDir":  webDir,
					"message": "Web UI not yet built or located. Run 'npm run build' in web/ directory.",
				})
			})
		}
	}

	addr := fmt.Sprintf(":%d", s.cfg.Port)
	fmt.Printf("=== ProvenanceX Security Server listening on http://localhost%s ===\n", addr)
	fmt.Printf("Serving static frontend from: %s\n", webDir)
	return http.ListenAndServe(addr, enableCORS(mux))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, version.Get())
}

func (s *Server) handleListScenarios(w http.ResponseWriter, r *http.Request) {
	scenarios := experiment.DefaultScenarios()
	type ScenarioSummary struct {
		ID                 string         `json:"id"`
		Name               string         `json:"name"`
		Category           string         `json:"category"`
		Description        string         `json:"description"`
		TargetLayer        evidence.Layer `json:"targetLayer"`
		ExpectedVerdict    string         `json:"expectedVerdict"`
		ExpectedBreakLayer evidence.Layer `json:"expectedBreakLayer"`
	}

	var list []ScenarioSummary
	for _, sc := range scenarios {
		list = append(list, ScenarioSummary{
			ID:                 sc.ID,
			Name:               sc.Name,
			Category:           sc.Category,
			Description:        sc.Description,
			TargetLayer:        sc.TargetLayer,
			ExpectedVerdict:    sc.ExpectedVerdict,
			ExpectedBreakLayer: sc.ExpectedBreakLayer,
		})
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleRunScenario(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	scenarios := experiment.DefaultScenarios()

	var target *experiment.Scenario
	for _, sc := range scenarios {
		if strings.EqualFold(sc.ID, id) {
			target = &sc
			break
		}
	}

	if target == nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("scenario %q not found", id))
		return
	}

	res, err := s.runner.RunScenario(r.Context(), *target)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleBenchmark(w http.ResponseWriter, r *http.Request) {
	report, err := s.runner.RunAll(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

type VerifyRequest struct {
	ArtifactPath string `json:"artifactPath"`
	IsBundle     bool   `json:"isBundle"`
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.ArtifactPath == "" {
		writeError(w, http.StatusBadRequest, "artifactPath is required")
		return
	}

	// If bundle verification requested
	if req.IsBundle || strings.HasSuffix(req.ArtifactPath, ".tar.gz") {
		bundleRes, err := bundle.VerifyOffline(req.ArtifactPath)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("bundle verification error: %v", err))
			return
		}
		writeJSON(w, http.StatusOK, bundleRes)
		return
	}

	// Normal artifact verification
	meta, err := artifact.Inspect(req.ArtifactPath, "")
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("artifact inspect error: %v", err))
		return
	}

	corrInput := &correlation.CorrelationInput{
		Artifact: meta,
	}

	corrRes := s.correlator.Correlate(corrInput)
	dec := s.engine.Decide(corrRes, s.policy)

	resp := map[string]any{
		"artifact":    meta,
		"correlation": corrRes,
		"decision":    dec,
	}
	writeJSON(w, http.StatusOK, resp)
}

type DeltaRequest struct {
	Manifest1Path string `json:"manifest1Path"`
	Manifest2Path string `json:"manifest2Path"`
}

func (s *Server) handleDelta(w http.ResponseWriter, r *http.Request) {
	var req DeltaRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	m1, err := evidence.LoadManifest(req.Manifest1Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("failed loading manifest 1: %v", err))
		return
	}
	m2, err := evidence.LoadManifest(req.Manifest2Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("failed loading manifest 2: %v", err))
		return
	}

	report := delta.CompareManifests(m1, m2)
	writeJSON(w, http.StatusOK, report)
}

func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{
		"error":     msg,
		"code":      code,
		"timestamp": time.Now().UTC(),
	})
}


