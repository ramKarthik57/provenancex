package policy

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Policy defines the configurable rules governing supply-chain trust decisions
type Policy struct {
	Version         string                `yaml:"version" json:"version"`
	Name            string                `yaml:"name" json:"name"`
	Description     string                `yaml:"description" json:"description"`
	Repository      RepositoryPolicy      `yaml:"repository" json:"repository"`
	Dependencies    DependenciesPolicy    `yaml:"dependencies" json:"dependencies"`
	Provenance      ProvenancePolicy      `yaml:"provenance" json:"provenance"`
	Signature       SignaturePolicy       `yaml:"signature" json:"signature"`
	Network         NetworkPolicy         `yaml:"network" json:"network"`
	Telemetry       TelemetryPolicy       `yaml:"telemetry" json:"telemetry"`
	Reproducibility ReproducibilityPolicy `yaml:"reproducibility" json:"reproducibility"`
}

type RepositoryPolicy struct {
	RequireCleanState      bool     `yaml:"require_clean_state" json:"require_clean_state"`
	AllowedBranches        []string `yaml:"allowed_branches" json:"allowed_branches"`
	RequireSignedCommits   bool     `yaml:"require_signed_commits" json:"require_signed_commits"`
	TrustedSigners         []string `yaml:"trusted_signers" json:"trusted_signers"`
	EnforceAuthorMatch     bool     `yaml:"enforce_author_match" json:"enforce_author_match"`
	DeclaredGeneratedPaths []string `yaml:"declared_generated_paths,omitempty" json:"declared_generated_paths,omitempty"`
	AllowDeclaredGenerated bool     `yaml:"allow_declared_generated,omitempty" json:"allow_declared_generated,omitempty"`
}

type DependenciesPolicy struct {
	RequireLockfile   bool     `yaml:"require_lockfile" json:"require_lockfile"`
	DisallowWildcards bool     `yaml:"disallow_wildcards" json:"disallow_wildcards"`
	AllowedRegistries []string `yaml:"allowed_registries" json:"allowed_registries"`
}

type ProvenancePolicy struct {
	Required         bool `yaml:"required" json:"required"`
	EnforceSLSALevel int  `yaml:"enforce_slsa_level" json:"enforce_slsa_level"`
}

type SignaturePolicy struct {
	Required bool `yaml:"required" json:"required"`
}

type NetworkPolicy struct {
	EnforceAllowlist    bool     `yaml:"enforce_allowlist" json:"enforce_allowlist"`
	AllowedDestinations []string `yaml:"allowed_destinations" json:"allowed_destinations"`
}

type TelemetryPolicy struct {
	RequireProcessTelemetry bool `yaml:"require_process_telemetry" json:"require_process_telemetry"`
	RequireNetworkTelemetry bool `yaml:"require_network_telemetry" json:"require_network_telemetry"`
}

type ReproducibilityPolicy struct {
	Required bool `yaml:"required" json:"required"`
}

// LoadPolicy parses a YAML policy file
func LoadPolicy(filePath string) (*Policy, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var pol Policy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return nil, err
	}
	return &pol, nil
}

// DefaultPolicy returns a baseline policy profile
func DefaultPolicy() *Policy {
	return &Policy{
		Version:     "1.0",
		Name:        "default-policy",
		Description: "Baseline supply-chain integrity policy",
		Repository: RepositoryPolicy{
			RequireCleanState:    true,
			AllowedBranches:      []string{"main", "master"},
			RequireSignedCommits: false,
			TrustedSigners:       []string{},
			EnforceAuthorMatch:   false,
		},
		Dependencies: DependenciesPolicy{
			RequireLockfile:   true,
			DisallowWildcards: true,
		},
		Provenance: ProvenancePolicy{
			Required: false,
		},
		Signature: SignaturePolicy{
			Required: false,
		},
		Network: NetworkPolicy{
			EnforceAllowlist: true,
		},
		Telemetry: TelemetryPolicy{
			RequireProcessTelemetry: false,
			RequireNetworkTelemetry: false,
		},
	}
}
