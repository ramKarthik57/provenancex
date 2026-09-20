package audit

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// RecomputeMetricsFromRawTrials reads raw_trials.csv and independently recalculates all metrics
func RecomputeMetricsFromRawTrials(rawTrialsPath string) ([]*RecomputedMetricRecord, error) {
	f, err := os.Open(rawTrialsPath)
	if err != nil {
		return nil, fmt.Errorf("failed opening raw trials file %s: %w", rawTrialsPath, err)
	}
	defer f.Close()

	reader := csv.NewReader(f)
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed reading CSV header: %w", err)
	}

	// Map headers
	colMap := make(map[string]int)
	for idx, h := range header {
		colMap[strings.TrimSpace(h)] = idx
	}

	type rawRecord struct {
		scenarioID  string
		category    string
		subCategory string
		isAttack    bool
		verdict     string
		detection   string
		latency     int64
	}

	var records []rawRecord

	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading row: %w", err)
		}

		scID := row[colMap["ScenarioID"]]
		cat := row[colMap["Category"]]
		subCat := row[colMap["SubCategory"]]
		isAtkStr := strings.ToLower(row[colMap["IsAttack"]])
		isAtk := isAtkStr == "true" || isAtkStr == "1"
		verdict := strings.ToUpper(row[colMap["PredictedVerdict"]])
		detection := strings.ToUpper(row[colMap["Detection"]])
		lat, _ := strconv.ParseInt(row[colMap["LatencyMicros"]], 10, 64)

		records = append(records, rawRecord{
			scenarioID:  scID,
			category:    cat,
			subCategory: subCat,
			isAttack:    isAtk,
			verdict:     verdict,
			detection:   detection,
			latency:     lat,
		})
	}

	// Helper to accumulate metrics
	type acc struct {
		partition    string
		scenarioID   string
		category     string
		subCategory  string
		total        int
		tp, fn       int
		tn, fp       int
		totalLatency int64
	}

	makeRecord := func(a *acc) *RecomputedMetricRecord {
		sumCheck := a.tp + a.fn + a.tn + a.fp
		isValid := (sumCheck == a.total)

		recall := 0.0
		if a.tp+a.fn > 0 {
			recall = float64(a.tp) / float64(a.tp+a.fn) * 100.0
		} else {
			recall = 100.0 // benign
		}

		precision := 100.0
		if a.tp+a.fp > 0 {
			precision = float64(a.tp) / float64(a.tp+a.fp) * 100.0
		} else if a.fp > 0 {
			precision = 0.0
		}

		f1 := 0.0
		if recall+precision > 0 {
			f1 = 2 * (recall * precision) / (recall + precision)
		}

		far := 0.0
		if a.fp+a.tn > 0 {
			far = float64(a.fp) / float64(a.fp+a.tn) * 100.0
		}

		frr := 0.0
		if a.fn+a.tp > 0 {
			frr = float64(a.fn) / float64(a.fn+a.tp) * 100.0
		}

		specificity := 100.0
		if a.tn+a.fp > 0 {
			specificity = float64(a.tn) / float64(a.tn+a.fp) * 100.0
		}

		accuracy := 0.0
		if a.total > 0 {
			accuracy = float64(a.tp+a.tn) / float64(a.total) * 100.0
		}

		meanLatency := 0.0
		if a.total > 0 {
			meanLatency = float64(a.totalLatency) / float64(a.total)
		}

		return &RecomputedMetricRecord{
			Partition:           a.partition,
			ScenarioID:          a.scenarioID,
			Category:            a.category,
			SubCategory:         a.subCategory,
			TotalTrials:         a.total,
			TruePositives:       a.tp,
			FalseNegatives:      a.fn,
			TrueNegatives:       a.tn,
			FalsePositives:      a.fp,
			SumCheck:            sumCheck,
			IsSumValid:          isValid,
			RecallPct:           recall,
			PrecisionPct:        precision,
			F1Score:             f1,
			FalseAcceptanceRate: far,
			FalseRejectionRate:  frr,
			SpecificityPct:      specificity,
			AccuracyPct:         accuracy,
			MeanLatencyMicros:   meanLatency,
		}
	}

	macroAll := &acc{partition: "GLOBAL_MACRO", scenarioID: "ALL_30_SCENARIOS", category: "OVERALL", subCategory: "All 7,500 Evaluated Trials"}
	macroAttacks := &acc{partition: "ATTACKS_MACRO", scenarioID: "ALL_25_ATTACK_SCENARIOS", category: "ATTACK_TOTAL", subCategory: "22 Unseen + 3 Composed Attacks"}
	macroBenign := &acc{partition: "BENIGN_MACRO", scenarioID: "ALL_5_BENIGN_SCENARIOS", category: "BENIGN_TOTAL", subCategory: "5 Benign Operational Variations"}

	byCategory := make(map[string]*acc)
	byScenario := make(map[string]*acc)
	scenarioOrder := make([]string, 0)

	for _, r := range records {
		// Update global macros
		macroAll.total++
		macroAll.totalLatency += r.latency

		if r.isAttack {
			macroAttacks.total++
			macroAttacks.totalLatency += r.latency
			if r.verdict == "REJECTED" {
				macroAll.tp++
				macroAttacks.tp++
			} else {
				macroAll.fn++
				macroAttacks.fn++
			}
		} else {
			macroBenign.total++
			macroBenign.totalLatency += r.latency
			if r.verdict == "TRUSTED" {
				macroAll.tn++
				macroBenign.tn++
			} else {
				macroAll.fp++
				macroBenign.fp++
			}
		}

		// Update category
		cAcc, exists := byCategory[r.category]
		if !exists {
			cAcc = &acc{partition: "CATEGORY", scenarioID: r.category, category: r.category, subCategory: r.category}
			byCategory[r.category] = cAcc
		}
		cAcc.total++
		cAcc.totalLatency += r.latency
		if r.isAttack {
			if r.verdict == "REJECTED" {
				cAcc.tp++
			} else {
				cAcc.fn++
			}
		} else {
			if r.verdict == "TRUSTED" {
				cAcc.tn++
			} else {
				cAcc.fp++
			}
		}

		// Update scenario
		sAcc, exists := byScenario[r.scenarioID]
		if !exists {
			sAcc = &acc{partition: "SCENARIO", scenarioID: r.scenarioID, category: r.category, subCategory: r.subCategory}
			byScenario[r.scenarioID] = sAcc
			scenarioOrder = append(scenarioOrder, r.scenarioID)
		}
		sAcc.total++
		sAcc.totalLatency += r.latency
		if r.isAttack {
			if r.verdict == "REJECTED" {
				sAcc.tp++
			} else {
				sAcc.fn++
			}
		} else {
			if r.verdict == "TRUSTED" {
				sAcc.tn++
			} else {
				sAcc.fp++
			}
		}
	}

	var results []*RecomputedMetricRecord

	// 1. Global Macro
	results = append(results, makeRecord(macroAll))
	results = append(results, makeRecord(macroAttacks))
	results = append(results, makeRecord(macroBenign))

	// 2. Categories (Unseen, Composed, Benign)
	categories := []string{"UNSEEN_ATTACK", "COMPOSED_ATTACK", "BENIGN_VARIABILITY"}
	for _, c := range categories {
		if cAcc, ok := byCategory[c]; ok {
			results = append(results, makeRecord(cAcc))
		}
	}

	// 3. Per Scenario
	for _, scID := range scenarioOrder {
		results = append(results, makeRecord(byScenario[scID]))
	}

	return results, nil
}

// ExportRecomputedMetricsCSV writes recomputed metrics to a CSV file
func ExportRecomputedMetricsCSV(records []*RecomputedMetricRecord, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	_ = w.Write([]string{
		"Partition", "ScenarioID", "Category", "SubCategory", "TotalTrials",
		"TruePositives", "FalseNegatives", "TrueNegatives", "FalsePositives",
		"SumCheck_TP_FN_TN_FP", "IsSumValid", "RecallPct", "PrecisionPct",
		"F1Score", "FalseAcceptanceRatePct", "FalseRejectionRatePct",
		"SpecificityPct", "AccuracyPct", "MeanLatencyMicros",
	})

	for _, r := range records {
		_ = w.Write([]string{
			r.Partition,
			r.ScenarioID,
			r.Category,
			r.SubCategory,
			fmt.Sprintf("%d", r.TotalTrials),
			fmt.Sprintf("%d", r.TruePositives),
			fmt.Sprintf("%d", r.FalseNegatives),
			fmt.Sprintf("%d", r.TrueNegatives),
			fmt.Sprintf("%d", r.FalsePositives),
			fmt.Sprintf("%d", r.SumCheck),
			fmt.Sprintf("%t", r.IsSumValid),
			fmt.Sprintf("%.2f", r.RecallPct),
			fmt.Sprintf("%.2f", r.PrecisionPct),
			fmt.Sprintf("%.2f", r.F1Score),
			fmt.Sprintf("%.2f", r.FalseAcceptanceRate),
			fmt.Sprintf("%.2f", r.FalseRejectionRate),
			fmt.Sprintf("%.2f", r.SpecificityPct),
			fmt.Sprintf("%.2f", r.AccuracyPct),
			fmt.Sprintf("%.1f", r.MeanLatencyMicros),
		})
	}

	return nil
}
