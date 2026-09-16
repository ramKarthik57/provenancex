package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the current ProvenanceX release version
	Version = "0.1.0-dev"
	// GitCommit is set at link time
	GitCommit = "unknown"
	// BuildDate is set at link time
	BuildDate = "unknown"
)

// Info returns structured version details
type Info struct {
	Version   string `json:"version"`
	GitCommit string `json:"gitCommit"`
	BuildDate string `json:"buildDate"`
	GoVersion string `json:"goVersion"`
	Compiler  string `json:"compiler"`
	Platform  string `json:"platform"`
}

// Get returns the Info struct populated with current build metadata
func Get() Info {
	return Info{
		Version:   Version,
		GitCommit: GitCommit,
		BuildDate: BuildDate,
		GoVersion: runtime.Version(),
		Compiler:  runtime.Compiler,
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

// String formats the version info as a human-readable string
func (i Info) String() string {
	return fmt.Sprintf("ProvenanceX v%s (commit: %s, built: %s, %s, %s)",
		i.Version, i.GitCommit, i.BuildDate, i.GoVersion, i.Platform)
}
