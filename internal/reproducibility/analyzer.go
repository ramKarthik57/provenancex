package reproducibility

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"debug/pe"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"time"

	"github.com/ramKarthik57/provenancex/internal/artifact"
)

var (
	// regexes for detecting embedded host build paths
	unixPathRegex = regexp.MustCompile(`/(?:home|Users|root|tmp|var/tmp|workspace)/[a-zA-Z0-9_.-]+`)
	winPathRegex  = regexp.MustCompile(`[a-zA-Z]:\\(?:Users|AppData|temp|workspace)\\[a-zA-Z0-9_.\\]+`)
	// regex for timestamp strings (e.g. 2026-09-20, 2026-09-20T...)
	dateRegex = regexp.MustCompile(`\b20\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])(?:[T\s]\d{2}:\d{2}:\d{2})?\b`)
)

// CompareArtifacts evaluates bitwise identity and diagnoses divergence causes between two artifacts
func CompareArtifacts(path1, path2 string) (*Report, error) {
	start := time.Now()

	art1, err := artifact.Inspect(path1, "")
	if err != nil {
		return nil, fmt.Errorf("failed to inspect artifact 1: %w", err)
	}

	art2, err := artifact.Inspect(path2, "")
	if err != nil {
		return nil, fmt.Errorf("failed to inspect artifact 2: %w", err)
	}

	report := &Report{
		Artifact1:        *art1,
		Artifact2:        *art2,
		ByteDifference:   art2.Size - art1.Size,
		DivergenceCauses: make([]DivergenceCause, 0),
		Recommendations:  make([]string, 0),
		EvaluatedAt:      start,
	}

	if art1.SHA256 == art2.SHA256 {
		report.Status = StatusReproducible
		report.BitwiseMatch = true
		report.DurationMs = time.Since(start).Milliseconds()
		return report, nil
	}

	report.Status = StatusDivergent
	report.BitwiseMatch = false

	// Read both files for deep diagnostic inspection
	bytes1, err := os.ReadFile(path1)
	if err != nil {
		return nil, fmt.Errorf("failed to read artifact 1: %w", err)
	}

	bytes2, err := os.ReadFile(path2)
	if err != nil {
		return nil, fmt.Errorf("failed to read artifact 2: %w", err)
	}

	// 1. Archive-specific analysis (Zip / Tar)
	isZip1 := isZip(bytes1)
	isZip2 := isZip(bytes2)
	if isZip1 && isZip2 {
		diagnoseZipDivergence(bytes1, bytes2, report)
	}

	isTar1 := isTar(bytes1)
	isTar2 := isTar(bytes2)
	if isTar1 && isTar2 {
		diagnoseTarDivergence(bytes1, bytes2, report)
	}

	// 2. Binary executable analysis (PE headers on Windows / general)
	diagnosePEHeaders(path1, path2, report)

	// 3. Embedded path leakage analysis
	diagnosePathLeakage(bytes1, bytes2, report)

	// 4. Embedded date/timestamp string analysis
	diagnoseEmbeddedTimestamps(bytes1, bytes2, report)

	// 5. General divergence fallback if no specific root cause was discovered
	if len(report.DivergenceCauses) == 0 {
		report.DivergenceCauses = append(report.DivergenceCauses, DivergenceCause{
			Category:       CategoryCodeModification,
			Severity:       "HIGH",
			Description:    "Bitwise mismatch detected without identifiable timestamp or path leakage patterns.",
			Evidence:       fmt.Sprintf("Artifact 1 size: %d bytes, Artifact 2 size: %d bytes. SHA-256 digests differ.", art1.Size, art2.Size),
			Recommendation: "Check for non-deterministic compiler optimizations, randomized symbols, or code modifications between builds.",
		})
		report.Recommendations = append(report.Recommendations, "Ensure build dependencies, compiler flags, and source code are strictly identical.")
	}

	// Deduplicate recommendations
	report.Recommendations = uniqueStrings(report.Recommendations)
	report.DurationMs = time.Since(start).Milliseconds()

	return report, nil
}

// ControlledRebuilder executes a build twice in clean temporary workspaces and compares results
func ControlledRebuilder(opts RebuildOptions) (*Report, error) {
	if opts.BuildCmd == "" {
		return nil, fmt.Errorf("build command is required for controlled rebuild")
	}

	tmpDir, err := os.MkdirTemp("", "provx-rebuild-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary rebuild directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	runDir1 := filepath.Join(tmpDir, "run1")
	runDir2 := filepath.Join(tmpDir, "run2")

	if err := copyDirectory(opts.BuildDir, runDir1); err != nil {
		return nil, fmt.Errorf("failed to prepare run 1 workspace: %w", err)
	}
	if err := copyDirectory(opts.BuildDir, runDir2); err != nil {
		return nil, fmt.Errorf("failed to prepare run 2 workspace: %w", err)
	}

	env1 := buildEnv(opts.Environment, opts.SourceEpoch, opts.CleanEnv)
	env2 := buildEnv(opts.Environment, opts.SourceEpoch, opts.CleanEnv)

	if err := executeBuild(opts.BuildCmd, runDir1, env1); err != nil {
		return nil, fmt.Errorf("controlled build run 1 failed: %w", err)
	}

	if err := executeBuild(opts.BuildCmd, runDir2, env2); err != nil {
		return nil, fmt.Errorf("controlled build run 2 failed: %w", err)
	}

	artifact1Path := filepath.Join(runDir1, opts.ArtifactRel)
	artifact2Path := filepath.Join(runDir2, opts.ArtifactRel)

	if _, err := os.Stat(artifact1Path); err != nil {
		return nil, fmt.Errorf("artifact not produced in run 1: %s", opts.ArtifactRel)
	}
	if _, err := os.Stat(artifact2Path); err != nil {
		return nil, fmt.Errorf("artifact not produced in run 2: %s", opts.ArtifactRel)
	}

	return CompareArtifacts(artifact1Path, artifact2Path)
}

func isZip(data []byte) bool {
	return len(data) >= 4 && bytes.HasPrefix(data, []byte("PK\x03\x04"))
}

func isTar(data []byte) bool {
	return len(data) >= 512 && bytes.Equal(data[257:262], []byte("ustar"))
}

func diagnoseZipDivergence(data1, data2 []byte, report *Report) {
	r1, err1 := zip.NewReader(bytes.NewReader(data1), int64(len(data1)))
	r2, err2 := zip.NewReader(bytes.NewReader(data2), int64(len(data2)))
	if err1 != nil || err2 != nil {
		return
	}

	files1 := make(map[string]*zip.File)
	var order1 []string
	for _, f := range r1.File {
		files1[f.Name] = f
		order1 = append(order1, f.Name)
	}

	files2 := make(map[string]*zip.File)
	var order2 []string
	for _, f := range r2.File {
		files2[f.Name] = f
		order2 = append(order2, f.Name)
	}

	// Check order difference
	if len(order1) == len(order2) && len(order1) > 1 {
		differOrder := false
		for i := range order1 {
			if order1[i] != order2[i] {
				differOrder = true
				break
			}
		}
		if differOrder {
			report.DivergenceCauses = append(report.DivergenceCauses, DivergenceCause{
				Category:       CategoryArchiveOrdering,
				Severity:       "WARNING",
				Description:    "Archive entry ordering is non-deterministic between builds.",
				Evidence:       fmt.Sprintf("Run 1 first entry: %s, Run 2 first entry: %s", order1[0], order2[0]),
				Recommendation: "Sort files alphabetically before archiving or pass deterministic sorting flags.",
			})
			report.Recommendations = append(report.Recommendations, "Use deterministic archive tools (e.g. zip with sorted file lists or tar --sort=name).")
		}
	}

	// Check timestamp differences inside zip
	timeDiffs := 0
	for name, f1 := range files1 {
		if f2, ok := files2[name]; ok {
			if !f1.Modified.Equal(f2.Modified) && f1.CRC32 == f2.CRC32 {
				timeDiffs++
			}
		}
	}

	if timeDiffs > 0 {
		report.DivergenceCauses = append(report.DivergenceCauses, DivergenceCause{
			Category:       CategoryTimestamp,
			Severity:       "WARNING",
			Description:    fmt.Sprintf("%d file(s) inside the zip archive have identical content CRC32 but different timestamps.", timeDiffs),
			Evidence:       "Archive entries retain local file modification timestamps instead of normalized build epochs.",
			Recommendation: "Clamp archive timestamps using SOURCE_DATE_EPOCH or pass -X/--no-extra to zip.",
		})
		report.Recommendations = append(report.Recommendations, "Set SOURCE_DATE_EPOCH environment variable to normalize archive member timestamps.")
	}
}

func diagnoseTarDivergence(data1, data2 []byte, report *Report) {
	tr1 := tar.NewReader(bytes.NewReader(data1))
	tr2 := tar.NewReader(bytes.NewReader(data2))

	var headers1, headers2 []*tar.Header
	for {
		hdr, err := tr1.Next()
		if err != nil {
			break
		}
		headers1 = append(headers1, hdr)
	}
	for {
		hdr, err := tr2.Next()
		if err != nil {
			break
		}
		headers2 = append(headers2, hdr)
	}

	if len(headers1) == len(headers2) && len(headers1) > 0 {
		diffTime := false
		for i := range headers1 {
			if !headers1[i].ModTime.Equal(headers2[i].ModTime) {
				diffTime = true
				break
			}
		}
		if diffTime {
			report.DivergenceCauses = append(report.DivergenceCauses, DivergenceCause{
				Category:       CategoryTimestamp,
				Severity:       "WARNING",
				Description:    "Tar archive headers contain differing modification timestamps (ModTime).",
				Evidence:       "Archive creation recorded host file modification times instead of a fixed epoch.",
				Recommendation: "Use `tar --mtime=@${SOURCE_DATE_EPOCH} --clamp-mtime` to normalize timestamps.",
			})
			report.Recommendations = append(report.Recommendations, "Use tar --mtime and --clamp-mtime with SOURCE_DATE_EPOCH.")
		}
	}
}

func diagnosePEHeaders(path1, path2 string, report *Report) {
	f1, err1 := pe.Open(path1)
	if err1 != nil {
		return
	}
	defer f1.Close()

	f2, err2 := pe.Open(path2)
	if err2 != nil {
		return
	}
	defer f2.Close()

	if f1.FileHeader.TimeDateStamp != f2.FileHeader.TimeDateStamp {
		t1 := time.Unix(int64(f1.FileHeader.TimeDateStamp), 0).UTC()
		t2 := time.Unix(int64(f2.FileHeader.TimeDateStamp), 0).UTC()

		report.DivergenceCauses = append(report.DivergenceCauses, DivergenceCause{
			Category:       CategoryTimestamp,
			Severity:       "WARNING",
			Description:    "Portable Executable (PE) header TimeDateStamp values differ between build runs.",
			Evidence:       fmt.Sprintf("Run 1 PE TimeDateStamp: %s (%d), Run 2: %s (%d)", t1.Format(time.RFC3339), f1.FileHeader.TimeDateStamp, t2.Format(time.RFC3339), f2.FileHeader.TimeDateStamp),
			Recommendation: "Use linker flags to zero out or fix PE TimeDateStamp (e.g. ld flag or reproducible toolchain).",
		})
		report.Recommendations = append(report.Recommendations, "Configure linker flags to fix or suppress PE header TimeDateStamps.")
	}
}

func diagnosePathLeakage(bytes1, bytes2 []byte, report *Report) {
	paths1 := extractPaths(bytes1)
	paths2 := extractPaths(bytes2)

	if len(paths1) > 0 || len(paths2) > 0 {
		diffs := 0
		var sampleDiff string
		for p1 := range paths1 {
			if !paths2[p1] {
				diffs++
				if sampleDiff == "" {
					sampleDiff = p1
				}
			}
		}

		if diffs > 0 {
			report.DivergenceCauses = append(report.DivergenceCauses, DivergenceCause{
				Category:       CategoryPathLeakage,
				Severity:       "HIGH",
				Description:    fmt.Sprintf("Host build filesystem paths leaked into the compiled binary (%d unique path variances).", diffs),
				Evidence:       fmt.Sprintf("Sample leaked path found in Run 1 but not Run 2: %s", sampleDiff),
				Recommendation: "Enable build path trimming (e.g. `go build -trimpath` in Go, or `-fdebug-prefix-map` / `-ffile-prefix-map` in C/C++).",
			})
			report.Recommendations = append(report.Recommendations, "Add compiler flags to strip host paths (e.g. `go build -trimpath`).")
		}
	}
}

func diagnoseEmbeddedTimestamps(bytes1, bytes2 []byte, report *Report) {
	dates1 := dateRegex.FindAll(bytes1, 20)
	dates2 := dateRegex.FindAll(bytes2, 20)

	set1 := make(map[string]bool)
	for _, d := range dates1 {
		set1[string(d)] = true
	}
	set2 := make(map[string]bool)
	for _, d := range dates2 {
		set2[string(d)] = true
	}

	diffs := 0
	var sample string
	for d := range set1 {
		if !set2[d] {
			diffs++
			if sample == "" {
				sample = d
			}
		}
	}

	if diffs > 0 {
		report.DivergenceCauses = append(report.DivergenceCauses, DivergenceCause{
			Category:       CategoryTimestamp,
			Severity:       "WARNING",
			Description:    fmt.Sprintf("Detected %d date/timestamp strings embedded in binary data that vary between builds.", diffs),
			Evidence:       fmt.Sprintf("Varying date string detected: %s", sample),
			Recommendation: "Avoid embedding `time.Now()` or `date` in code/version strings during compilation; use git commit timestamp instead.",
		})
		report.Recommendations = append(report.Recommendations, "Replace dynamic build timestamps with git commit dates or fixed release version tags.")
	}
}

func extractPaths(data []byte) map[string]bool {
	paths := make(map[string]bool)
	for _, m := range unixPathRegex.FindAll(data, 50) {
		paths[string(m)] = true
	}
	for _, m := range winPathRegex.FindAll(data, 50) {
		paths[string(m)] = true
	}
	return paths
}

func buildEnv(customEnv map[string]string, sourceEpoch int64, cleanEnv bool) []string {
	var env []string
	if !cleanEnv {
		env = os.Environ()
	}

	if sourceEpoch > 0 {
		env = append(env, fmt.Sprintf("SOURCE_DATE_EPOCH=%d", sourceEpoch))
	}

	for k, v := range customEnv {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	return env
}

func executeBuild(cmdStr, workDir string, env []string) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd.exe", "/c", cmdStr)
	} else {
		cmd = exec.Command("sh", "-c", cmdStr)
	}

	cmd.Dir = workDir
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command execution error: %w (output: %s)", err, string(output))
	}
	return nil
}

func copyDirectory(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range in {
		if !seen[s] && s != "" {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
