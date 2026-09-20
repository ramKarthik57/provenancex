package repository

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrNotAGitRepository is returned when the target directory is not a git repository
	ErrNotAGitRepository = errors.New("not a git repository")
	// ErrGitNotFound is returned when the git executable is not available
	ErrGitNotFound = errors.New("git executable not found in PATH")
)

// CommitSignatureStatus classifies the cryptographic status of a commit
type CommitSignatureStatus string

const (
	CommitSignatureSignedAndValid   CommitSignatureStatus = "SIGNED_AND_VALID"
	CommitSignatureSignedUntrusted  CommitSignatureStatus = "SIGNED_BUT_UNTRUSTED"
	CommitSignatureInvalid          CommitSignatureStatus = "SIGNATURE_INVALID"
	CommitSignatureUnsigned         CommitSignatureStatus = "UNSIGNED"
	CommitSignatureIdentityMismatch CommitSignatureStatus = "IDENTITY_MISMATCH"
	CommitSignatureUnverified       CommitSignatureStatus = "UNVERIFIED"
)

// CommitSignatureInfo encapsulates cryptographic signature evidence for a commit
type CommitSignatureInfo struct {
	Status         CommitSignatureStatus `json:"status"`
	SignerKeyID    string                `json:"signerKeyId,omitempty"`
	SignerIdentity string                `json:"signerIdentity,omitempty"`
	Committer      string                `json:"committer,omitempty"`
	CommitterEmail string                `json:"committerEmail,omitempty"`
	Error          string                `json:"error,omitempty"`
}

// State represents the integrity status of a Git source repository
type State struct {
	RepoURL         string               `json:"repoUrl,omitempty"`
	Branch          string               `json:"branch"`
	CommitSHA       string               `json:"commitSha"`
	ParentCommitSHA string               `json:"parentCommitSha,omitempty"`
	TreeSHA         string               `json:"treeSha"`
	Author          string               `json:"author"`
	AuthorEmail     string               `json:"authorEmail"`
	CommitTimestamp time.Time            `json:"commitTimestamp"`
	IsClean         bool                 `json:"isClean"`
	ModifiedFiles   []string             `json:"modifiedFiles"`
	UntrackedFiles  []string             `json:"untrackedFiles"`
	StagedFiles     []string             `json:"stagedFiles"`
	Submodules      []string             `json:"submodules,omitempty"`
	SignatureInfo   *CommitSignatureInfo `json:"signatureInfo,omitempty"`
}

// Collector inspects Git repository state
type Collector struct {
	gitPath string
}

// NewCollector constructs a repository state collector
func NewCollector() (*Collector, error) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGitNotFound, err)
	}
	return &Collector{gitPath: gitPath}, nil
}

// Collect inspects the git repository at targetDir
func (c *Collector) Collect(ctx context.Context, targetDir string) (*State, error) {
	absDir, err := filepath.Abs(targetDir)
	if err != nil {
		return nil, fmt.Errorf("failed resolving directory path: %w", err)
	}

	// Verify it's a git repo
	if _, err := c.runGit(ctx, absDir, "rev-parse", "--is-inside-work-tree"); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrNotAGitRepository, absDir)
	}

	state := &State{
		ModifiedFiles:  []string{},
		UntrackedFiles: []string{},
		StagedFiles:    []string{},
		Submodules:     []string{},
	}

	// Branch
	branch, _ := c.runGit(ctx, absDir, "rev-parse", "--abbrev-ref", "HEAD")
	state.Branch = strings.TrimSpace(branch)

	// Remote URL if available
	remoteURL, _ := c.runGit(ctx, absDir, "config", "--get", "remote.origin.url")
	state.RepoURL = strings.TrimSpace(remoteURL)

	// Commit SHA
	commitSHA, err := c.runGit(ctx, absDir, "rev-parse", "HEAD")
	if err == nil {
		state.CommitSHA = strings.TrimSpace(commitSHA)
	}

	// Tree SHA
	treeSHA, err := c.runGit(ctx, absDir, "rev-parse", "HEAD^{tree}")
	if err == nil {
		state.TreeSHA = strings.TrimSpace(treeSHA)
	}

	// Parent Commit SHA
	parentSHA, _ := c.runGit(ctx, absDir, "rev-parse", "HEAD^")
	state.ParentCommitSHA = strings.TrimSpace(parentSHA)

	// Author & Timestamp
	if state.CommitSHA != "" {
		author, _ := c.runGit(ctx, absDir, "log", "-1", "--format=%an")
		state.Author = strings.TrimSpace(author)

		email, _ := c.runGit(ctx, absDir, "log", "-1", "--format=%ae")
		state.AuthorEmail = strings.TrimSpace(email)

		timestampStr, err := c.runGit(ctx, absDir, "log", "-1", "--format=%ct")
		if err == nil {
			if ts, parseErr := strconv.ParseInt(strings.TrimSpace(timestampStr), 10, 64); parseErr == nil {
				state.CommitTimestamp = time.Unix(ts, 0).UTC()
			}
		}

		// Cryptographic commit signature verification
		sigCode, _ := c.runGit(ctx, absDir, "log", "-1", "--format=%G?")
		sigCode = strings.TrimSpace(sigCode)
		signerName, _ := c.runGit(ctx, absDir, "log", "-1", "--format=%GS")
		signerKey, _ := c.runGit(ctx, absDir, "log", "-1", "--format=%GK")
		committer, _ := c.runGit(ctx, absDir, "log", "-1", "--format=%cn")
		committerEmail, _ := c.runGit(ctx, absDir, "log", "-1", "--format=%ce")

		sigStatus := CommitSignatureUnverified
		switch sigCode {
		case "G":
			sigStatus = CommitSignatureSignedAndValid
		case "B":
			sigStatus = CommitSignatureInvalid
		case "U":
			sigStatus = CommitSignatureSignedUntrusted
		case "N", "":
			sigStatus = CommitSignatureUnsigned
		default:
			sigStatus = CommitSignatureInvalid
		}

		state.SignatureInfo = &CommitSignatureInfo{
			Status:         sigStatus,
			SignerKeyID:    strings.TrimSpace(signerKey),
			SignerIdentity: strings.TrimSpace(signerName),
			Committer:      strings.TrimSpace(committer),
			CommitterEmail: strings.TrimSpace(committerEmail),
		}
	}

	// Status (Clean / Dirty, Modified, Untracked, Staged)
	statusOut, err := c.runGit(ctx, absDir, "status", "--porcelain")
	if err == nil {
		lines := strings.Split(statusOut, "\n")
		for _, line := range lines {
			line = strings.TrimRight(line, "\r")
			if len(line) < 3 {
				continue
			}
			statusCode := line[:2]
			fileName := strings.TrimSpace(line[3:])

			// Index staged
			if statusCode[0] != ' ' && statusCode[0] != '?' {
				state.StagedFiles = append(state.StagedFiles, fileName)
			}
			// Worktree modified
			if statusCode[1] == 'M' || statusCode[1] == 'D' {
				state.ModifiedFiles = append(state.ModifiedFiles, fileName)
			}
			// Untracked
			if statusCode == "??" {
				state.UntrackedFiles = append(state.UntrackedFiles, fileName)
			}
		}
	}

	state.IsClean = len(state.ModifiedFiles) == 0 && len(state.UntrackedFiles) == 0 && len(state.StagedFiles) == 0

	return state, nil
}

func (c *Collector) runGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, c.gitPath, args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, stderr.String())
	}
	return stdout.String(), nil
}
