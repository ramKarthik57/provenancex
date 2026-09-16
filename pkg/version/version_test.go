package version

import (
	"strings"
	"testing"
)

func TestGetVersion(t *testing.T) {
	info := Get()
	if info.Version == "" {
		t.Errorf("expected non-empty Version")
	}
	if !strings.HasPrefix(info.GoVersion, "go") {
		t.Errorf("expected GoVersion starting with 'go', got %s", info.GoVersion)
	}
	str := info.String()
	if !strings.Contains(str, "ProvenanceX") {
		t.Errorf("expected String() to contain 'ProvenanceX', got %s", str)
	}
}
