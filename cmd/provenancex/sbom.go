package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ramKarthik57/provenancex/internal/dependency"
	"github.com/ramKarthik57/provenancex/internal/sbom"
	"github.com/spf13/cobra"
)

var (
	sbomFormat     string
	sbomOutputJSON bool
	sbomOutputFile string
	sbomValidateFile string
)

var sbomCmd = &cobra.Command{
	Use:   "sbom [path]",
	Short: "Generate, inspect, or validate CycloneDX and SPDX SBOMs",
	Long: `Inspects or generates Software Bill of Materials (SBOM) conforming to
CycloneDX v1.5 or SPDX 2.3 standards. Cross-references SBOM components against
resolved build dependencies to detect undeclared packages or version drift.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		targetPath := "."
		if len(args) > 0 {
			targetPath = args[0]
		}

		// Validation mode: compare given SBOM against target directory dependencies
		if sbomValidateFile != "" {
			doc, err := parseSBOMFile(sbomValidateFile)
			if err != nil {
				return fmt.Errorf("failed parsing SBOM file %s: %w", sbomValidateFile, err)
			}

			analyzer := dependency.NewAnalyzer(nil)
			report, err := analyzer.Analyze(targetPath)
			if err != nil {
				return fmt.Errorf("failed analyzing dependencies: %w", err)
			}

			validator := sbom.NewValidator()
			valResult := validator.Validate(doc, report)

			if sbomOutputJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(valResult)
			}

			fmt.Println("=== ProvenanceX SBOM Validation Report ===")
			fmt.Printf("SBOM Format:     %s (Spec: %s)\n", valResult.Format, valResult.SpecVersion)
			fmt.Printf("Components:      %d\n", valResult.ComponentCount)
			if valResult.Valid {
				fmt.Println("Integrity:       VALID & CONSISTENT (✓)")
			} else {
				fmt.Println("Integrity:       DISCREPANCIES DETECTED (✗)")
				fmt.Printf("\n[Discrepancies (%d)]\n", len(valResult.Discrepancies))
				for _, d := range valResult.Discrepancies {
					fmt.Printf("  - [%s] %s\n", d.Type, d.Component)
					fmt.Printf("    SBOM:     %s\n", d.SBOMValue)
					fmt.Printf("    Observed: %s\n", d.ActualValue)
					fmt.Printf("    Details:  %s\n", d.Description)
				}
			}
			return nil
		}

		info, err := os.Stat(targetPath)
		if err != nil {
			return err
		}

		// If pointing to a file, inspect it as an SBOM
		if !info.IsDir() {
			doc, err := parseSBOMFile(targetPath)
			if err != nil {
				return err
			}

			if sbomOutputJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(doc)
			}

			fmt.Println("=== ProvenanceX SBOM Inspection Report ===")
			fmt.Printf("Format:      %s\n", doc.Format)
			fmt.Printf("Spec:        %s\n", doc.SpecVersion)
			fmt.Printf("Name:        %s\n", doc.Name)
			fmt.Printf("Timestamp:   %s\n", doc.Timestamp.Format("2006-01-02 15:04:05 UTC"))
			fmt.Printf("Components:  %d\n\n", len(doc.Components))
			for i, c := range doc.Components {
				if i >= 15 {
					fmt.Printf("  ... and %d more components\n", len(doc.Components)-15)
					break
				}
				fmt.Printf("  - %s@%s (%s)\n", c.Name, c.Version, c.PURL)
			}
			return nil
		}

		// Otherwise, generate an SBOM from workspace dependencies
		analyzer := dependency.NewAnalyzer(nil)
		report, err := analyzer.Analyze(targetPath)
		if err != nil {
			return fmt.Errorf("dependency analysis failed: %w", err)
		}

		projectName := filepath.Base(targetPath)
		if projectName == "." || projectName == "/" || projectName == "\\" {
			projectName = "app"
		}

		var outputBytes []byte
		switch strings.ToLower(sbomFormat) {
		case "spdx":
			outputBytes, err = sbom.GenerateSPDX(projectName, "1.0.0", report)
		default:
			outputBytes, err = sbom.GenerateCycloneDX(projectName, "1.0.0", report)
		}
		if err != nil {
			return fmt.Errorf("failed generating SBOM: %w", err)
		}

		if sbomOutputFile != "" {
			if err := os.WriteFile(sbomOutputFile, outputBytes, 0644); err != nil {
				return fmt.Errorf("failed writing SBOM to %s: %w", sbomOutputFile, err)
			}
			fmt.Printf("SBOM (%s) successfully generated and saved to: %s\n", sbomFormat, sbomOutputFile)
			return nil
		}

		fmt.Println(string(outputBytes))
		return nil
	},
}

func parseSBOMFile(filePath string) (*sbom.Document, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	content := string(data)
	if strings.Contains(content, "bomFormat") || strings.Contains(content, "CycloneDX") {
		return sbom.ParseCycloneDX(filePath)
	}
	if strings.Contains(content, "spdxVersion") || strings.Contains(content, "SPDX") {
		return sbom.ParseSPDX(filePath)
	}
	return nil, fmt.Errorf("unable to determine SBOM format (supported: CycloneDX, SPDX)")
}

func init() {
	sbomCmd.Flags().StringVar(&sbomFormat, "format", "cyclonedx", "Output format: cyclonedx or spdx")
	sbomCmd.Flags().StringVarP(&sbomOutputFile, "output", "o", "", "File path to save generated SBOM")
	sbomCmd.Flags().StringVar(&sbomValidateFile, "validate", "", "Path to existing SBOM file to validate against directory dependencies")
	sbomCmd.Flags().BoolVar(&sbomOutputJSON, "json", false, "Output results as formatted JSON")
	rootCmd.AddCommand(sbomCmd)
}
