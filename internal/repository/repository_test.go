package repository

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func setupTestGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v, output: %s", args, err, string(out))
		}
	}

	run("init", "-b", "main")
	run("config", "user.name", "Test Committer")
	run("config", "user.email", "committer@example.com")
	run("config", "commit.gpgsign", "false")

	testFile := filepath.Join(dir, "README.md")
	if err := os.WriteFile(testFile, []byte("# Test Repository"), 0644); err != nil {
		t.Fatalf("failed writing test file: %v", err)
	}

	run("add", "README.md")
	run("commit", "-m", "initial test commit")

	return dir
}

func TestRepositoryCollectorClean(t *testing.T) {
	repoDir := setupTestGitRepo(t)
	collector, err := NewCollector()
	if err != nil {
		t.Fatalf("failed to create collector: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	state, err := collector.Collect(ctx, repoDir)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if state.Branch != "main" {
		t.Errorf("expected branch 'main', got '%s'", state.Branch)
	}
	if state.CommitSHA == "" {
		t.Errorf("expected non-empty commit SHA")
	}
	if state.TreeSHA == "" {
		t.Errorf("expected non-empty tree SHA")
	}
	if state.Author != "Test Committer" {
		t.Errorf("expected author 'Test Committer', got '%s'", state.Author)
	}
	if !state.IsClean {
		t.Errorf("expected clean repository state, got dirty")
	}
	if len(state.ModifiedFiles) != 0 || len(state.UntrackedFiles) != 0 {
		t.Errorf("expected zero modified/untracked files")
	}
}

func TestRepositoryCollectorDirtyAndUntracked(t *testing.T) {
	repoDir := setupTestGitRepo(t)
	collector, err := NewCollector()
	if err != nil {
		t.Fatalf("failed to create collector: %v", err)
	}

	// Create an untracked file
	untrackedFile := filepath.Join(repoDir, "malicious-injection.py")
	if err := os.WriteFile(untrackedFile, []byte("import os"), 0644); err != nil {
		t.Fatalf("failed writing untracked file: %v", err)
	}

	// Modify an existing tracked file
	trackedFile := filepath.Join(repoDir, "README.md")
	if err := os.WriteFile(trackedFile, []byte("# Modified README"), 0644); err != nil {
		t.Fatalf("failed modifying tracked file: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	state, err := collector.Collect(ctx, repoDir)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if state.IsClean {
		t.Errorf("expected dirty repository state, got clean")
	}
	if len(state.UntrackedFiles) == 0 {
		t.Errorf("expected untracked files to be detected")
	}
	if len(state.ModifiedFiles) == 0 {
		t.Errorf("expected modified files to be detected")
	}
}

func TestRepositoryCollectorNonGitDir(t *testing.T) {
	emptyDir := t.TempDir()
	collector, err := NewCollector()
	if err != nil {
		t.Fatalf("failed to create collector: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = collector.Collect(ctx, emptyDir)
	if err == nil {
		t.Errorf("expected error when collecting from non-git directory, got nil")
	}
}
