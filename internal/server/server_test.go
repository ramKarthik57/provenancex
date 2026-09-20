package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ramKarthik57/provenancex/internal/experiment"
)

func TestServerHealthAndVersion(t *testing.T) {
	srv, err := NewServer(Config{Port: 8080})
	if err != nil {
		t.Fatalf("failed creating server: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	srv.handleHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var h map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&h); err != nil || h["status"] != "healthy" {
		t.Errorf("unexpected health response: %v", h)
	}

	reqV := httptest.NewRequest("GET", "/api/v1/version", nil)
	recV := httptest.NewRecorder()
	srv.handleVersion(recV, reqV)

	if recV.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", recV.Code)
	}
}

func TestServerScenariosAndBenchmark(t *testing.T) {
	srv, err := NewServer(Config{Port: 8080})
	if err != nil {
		t.Fatalf("failed creating server: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/scenarios", nil)
	rec := httptest.NewRecorder()
	srv.handleListScenarios(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var list []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil || len(list) != 10 {
		t.Errorf("expected 10 scenarios in API, got %d", len(list))
	}

	reqB := httptest.NewRequest("GET", "/api/v1/benchmark", nil)
	recB := httptest.NewRecorder()
	srv.handleBenchmark(recB, reqB)

	if recB.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", recB.Code)
	}

	var rep experiment.BenchmarkReport
	if err := json.NewDecoder(recB.Body).Decode(&rep); err != nil || rep.TotalScenarios != 10 {
		t.Errorf("expected valid benchmark report, got %v", rep)
	}
	if rep.DetectionRatePercent < 100.0 {
		t.Errorf("expected 100%% detection rate in API benchmark, got %.1f%%", rep.DetectionRatePercent)
	}
}
