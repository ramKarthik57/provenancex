package network

import (
	"math"
	"strings"
	"unicode"
)

// SubdomainAnalysisResult holds detailed heuristic metrics for an evaluated domain
type SubdomainAnalysisResult struct {
	Domain           string          `json:"domain"`
	MatchedSuffix    string          `json:"matchedSuffix"`
	SubdomainPrefix  string          `json:"subdomainPrefix"`
	Status           SubdomainStatus `json:"status"`
	ShannonEntropy   float64         `json:"shannonEntropy"`
	MaxLabelLength   int             `json:"maxLabelLength"`
	TotalLength      int             `json:"totalLength"`
	LabelCount       int             `json:"labelCount"`
	DigitRatio       float64         `json:"digitRatio"`
	HexRatio         float64         `json:"hexRatio"`
	IsSuspicious     bool            `json:"isSuspicious"`
	Reason           string          `json:"reason"`
}

// SubdomainAnalyzer assesses domain prefixes under authorized suffixes for exfiltration characteristics
type SubdomainAnalyzer struct {
	MaxAllowedLabelLen int
	MaxAllowedEntropy  float64
	MaxAllowedNesting  int
}

// NewSubdomainAnalyzer creates a standard heuristic subdomain analyzer
func NewSubdomainAnalyzer() *SubdomainAnalyzer {
	return &SubdomainAnalyzer{
		MaxAllowedLabelLen: 32,
		MaxAllowedEntropy:  3.65, // Natural English/lexical domains typically have H < 3.2; random hex/base32/base64 has H > 3.7
		MaxAllowedNesting:  4,
	}
}

// ComputeShannonEntropy calculates the Shannon entropy in bits for a given string: H = -sum(p * log2(p))
func ComputeShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}

	length := float64(len(s))
	var entropy float64
	for _, count := range counts {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// Analyze evaluates whether a domain query under an authorized suffix exhibits tunneling characteristics
func (sa *SubdomainAnalyzer) Analyze(domain string, allowedSuffix string) *SubdomainAnalysisResult {
	cleanDomain := strings.ToLower(strings.TrimSpace(domain))
	cleanSuffix := strings.ToLower(strings.TrimSpace(allowedSuffix))

	res := &SubdomainAnalysisResult{
		Domain:         cleanDomain,
		MatchedSuffix:  cleanSuffix,
		Status:         SubdomainNormal,
		TotalLength:    len(cleanDomain),
		ShannonEntropy: 0.0,
	}

	if cleanDomain == cleanSuffix {
		res.Status = SubdomainNormal
		res.Reason = "Exact match on authorized root domain"
		return res
	}

	// Extract prefix (e.g., "exfil-secret-c2" from "exfil-secret-c2.pkg.go.dev")
	dotSuffix := "." + cleanSuffix
	if !strings.HasSuffix(cleanDomain, dotSuffix) {
		res.Status = SubdomainNormal
		res.Reason = "Not a subdomain of specified suffix"
		return res
	}

	prefix := strings.TrimSuffix(cleanDomain, dotSuffix)
	res.SubdomainPrefix = prefix

	labels := strings.Split(prefix, ".")
	res.LabelCount = len(labels)

	var maxLen int
	var maxEntropy float64
	var totalDigits int
	var totalHex int
	var totalChars int

	for _, label := range labels {
		if len(label) > maxLen {
			maxLen = len(label)
		}

		ent := ComputeShannonEntropy(label)
		if ent > maxEntropy {
			maxEntropy = ent
		}

		for _, ch := range label {
			totalChars++
			if unicode.IsDigit(ch) {
				totalDigits++
			}
			if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') {
				totalHex++
			}
		}
	}

	res.MaxLabelLength = maxLen
	res.ShannonEntropy = maxEntropy
	if totalChars > 0 {
		res.DigitRatio = float64(totalDigits) / float64(totalChars)
		res.HexRatio = float64(totalHex) / float64(totalChars)
	}

	// Multi-feature heuristic evaluation:
	// Do NOT rely on entropy alone. We require at least TWO distinct anomalous features:
	// 1. High entropy (>3.65)
	// 2. High label length (>32 chars)
	// 3. Excessive label nesting (>4 levels)
	// 4. Dominated by hex/digits (>85% hex with len > 16)
	anomalies := 0
	var anomalyReasons []string

	if maxEntropy > sa.MaxAllowedEntropy {
		anomalies++
		anomalyReasons = append(anomalyReasons, "high Shannon entropy (randomness)")
	}

	if maxLen > sa.MaxAllowedLabelLen {
		anomalies++
		anomalyReasons = append(anomalyReasons, "abnormally long label length")
	}

	if len(labels) > sa.MaxAllowedNesting {
		anomalies++
		anomalyReasons = append(anomalyReasons, "excessive label nesting depth")
	}

	if res.HexRatio > 0.85 && maxLen > 16 {
		anomalies++
		anomalyReasons = append(anomalyReasons, "encoded hex/base-like character distribution")
	}

	// A single anomaly warrants attention; 2 or more flags as SUSPICIOUS
	if anomalies >= 2 || (maxEntropy > 4.0 && maxLen > 24) {
		res.Status = SubdomainSuspicious
		res.IsSuspicious = true
		res.Reason = "Abnormal subdomain characteristics detected: " + strings.Join(anomalyReasons, ", ")
	} else {
		res.Status = SubdomainNormal
		res.Reason = "Standard lexical/hierarchical subdomain"
	}

	return res
}
