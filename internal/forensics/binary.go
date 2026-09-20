package forensics

import (
	"archive/zip"
	"debug/elf"
	"debug/pe"
	"fmt"
	"os"
	"strings"
)

// StructuralDivergence models non-judgmental structural differences between two compiled binaries
type StructuralDivergence struct {
	Format          string   `json:"format"` // PE, ELF, ZIP, BINARY
	DivergenceType  string   `json:"divergenceType"` // "STRUCTURAL_DIVERGENCE"
	SectionsAdded   []string `json:"sectionsAdded"`
	SectionsRemoved []string `json:"sectionsRemoved"`
	SectionsChanged []string `json:"sectionsChanged"`
	ImportsAdded    []string `json:"importsAdded"`
	ImportsRemoved  []string `json:"importsRemoved"`
	StringsAdded    []string `json:"stringsAdded"`
	MetadataChanges []string `json:"metadataChanges"`
	Summary         string   `json:"summary"`
}

// BinaryComparator performs structural binary comparisons
type BinaryComparator struct{}

// NewBinaryComparator constructs a binary forensics comparator
func NewBinaryComparator() *BinaryComparator {
	return &BinaryComparator{}
}

// Compare analyzes two binary paths and returns structural divergence
func (bc *BinaryComparator) Compare(pathA, pathB string) (*StructuralDivergence, error) {
	div := &StructuralDivergence{
		DivergenceType:  "STRUCTURAL_DIVERGENCE",
		SectionsAdded:   make([]string, 0),
		SectionsRemoved: make([]string, 0),
		SectionsChanged: make([]string, 0),
		ImportsAdded:    make([]string, 0),
		ImportsRemoved:  make([]string, 0),
		StringsAdded:    make([]string, 0),
		MetadataChanges: make([]string, 0),
	}

	infoA, err := os.Stat(pathA)
	if err != nil {
		return nil, fmt.Errorf("failed accessing pathA %s: %w", pathA, err)
	}
	infoB, err := os.Stat(pathB)
	if err != nil {
		return nil, fmt.Errorf("failed accessing pathB %s: %w", pathB, err)
	}

	if infoA.Size() != infoB.Size() {
		div.MetadataChanges = append(div.MetadataChanges,
			fmt.Sprintf("Size divergence: %d bytes vs %d bytes (delta %d bytes)", infoA.Size(), infoB.Size(), infoB.Size()-infoA.Size()))
	}

	// 1. Try PE comparison (Windows binaries)
	peA, errA := pe.Open(pathA)
	peB, errB := pe.Open(pathB)
	if errA == nil && errB == nil {
		defer peA.Close()
		defer peB.Close()
		div.Format = "PE (Portable Executable)"
		comparePE(peA, peB, div)
		div.Summary = fmt.Sprintf("PE structural comparison complete (%d section/import changes)",
			len(div.SectionsChanged)+len(div.ImportsAdded))
		return div, nil
	}

	// 2. Try ELF comparison (Linux binaries)
	elfA, errA := elf.Open(pathA)
	elfB, errB := elf.Open(pathB)
	if errA == nil && errB == nil {
		defer elfA.Close()
		defer elfB.Close()
		div.Format = "ELF (Executable and Linkable Format)"
		compareELF(elfA, elfB, div)
		div.Summary = fmt.Sprintf("ELF structural comparison complete (%d section changes)", len(div.SectionsChanged))
		return div, nil
	}

	// 3. Try ZIP / JAR comparison
	zipA, errA := zip.OpenReader(pathA)
	zipB, errB := zip.OpenReader(pathB)
	if errA == nil && errB == nil {
		defer zipA.Close()
		defer zipB.Close()
		div.Format = "ZIP/JAR Archive"
		compareZIP(zipA, zipB, div)
		div.Summary = fmt.Sprintf("Archive member comparison complete (%d member divergences)", len(div.SectionsChanged))
		return div, nil
	}

	// 4. Fallback Generic Binary Comparison
	div.Format = "GENERIC_BINARY"
	div.Summary = "Bitwise binary format: Structural parser not applicable; byte divergence recorded"
	return div, nil
}

func comparePE(a, b *pe.File, div *StructuralDivergence) {
	secA := make(map[string]*pe.Section)
	for _, s := range a.Sections {
		secA[s.Name] = s
	}

	for _, sB := range b.Sections {
		if sA, ok := secA[sB.Name]; !ok {
			div.SectionsAdded = append(div.SectionsAdded, sB.Name)
		} else {
			if sA.Size != sB.Size || sA.VirtualSize != sB.VirtualSize {
				div.SectionsChanged = append(div.SectionsChanged,
					fmt.Sprintf("%s (size: %d -> %d)", sB.Name, sA.Size, sB.Size))
			}
			delete(secA, sB.Name)
		}
	}

	for name := range secA {
		div.SectionsRemoved = append(div.SectionsRemoved, name)
	}

	// Check Imported Symbols
	impA, _ := a.ImportedSymbols()
	impB, _ := b.ImportedSymbols()
	impAMap := make(map[string]bool)
	for _, sym := range impA {
		impAMap[sym] = true
	}
	for _, sym := range impB {
		if !impAMap[sym] {
			div.ImportsAdded = append(div.ImportsAdded, sym)
		}
	}
}

func compareELF(a, b *elf.File, div *StructuralDivergence) {
	secA := make(map[string]*elf.Section)
	for _, s := range a.Sections {
		secA[s.Name] = s
	}
	for _, sB := range b.Sections {
		if sA, ok := secA[sB.Name]; !ok {
			div.SectionsAdded = append(div.SectionsAdded, sB.Name)
		} else {
			if sA.Size != sB.Size {
				div.SectionsChanged = append(div.SectionsChanged,
					fmt.Sprintf("%s (size: %d -> %d)", sB.Name, sA.Size, sB.Size))
			}
			delete(secA, sB.Name)
		}
	}
	for name := range secA {
		div.SectionsRemoved = append(div.SectionsRemoved, name)
	}
}

func compareZIP(a *zip.ReadCloser, b *zip.ReadCloser, div *StructuralDivergence) {
	filesA := make(map[string]*zip.File)
	for _, f := range a.File {
		filesA[f.Name] = f
	}
	for _, fB := range b.File {
		if fA, ok := filesA[fB.Name]; !ok {
			div.SectionsAdded = append(div.SectionsAdded, fB.Name)
		} else {
			if fA.CRC32 != fB.CRC32 {
				div.SectionsChanged = append(div.SectionsChanged,
					fmt.Sprintf("%s (CRC: %08x -> %08x)", fB.Name, fA.CRC32, fB.CRC32))
			}
			delete(filesA, fB.Name)
		}
	}
	for name := range filesA {
		div.SectionsRemoved = append(div.SectionsRemoved, name)
	}
}

// FormatTerminal prints the structural divergence report
func (d *StructuralDivergence) FormatTerminal() string {
	var sb strings.Builder
	sb.WriteString("================================================================================\n")
	sb.WriteString("                 PROVENANCEX STRUCTURAL BINARY FORENSICS                        \n")
	sb.WriteString("================================================================================\n")
	sb.WriteString(fmt.Sprintf("BINARY FORMAT:      %s\n", d.Format))
	sb.WriteString(fmt.Sprintf("DIVERGENCE TYPE:    %s\n", d.DivergenceType))
	sb.WriteString(fmt.Sprintf("SUMMARY:            %s\n", d.Summary))
	sb.WriteString("--------------------------------------------------------------------------------\n")

	if len(d.SectionsAdded) > 0 {
		sb.WriteString(fmt.Sprintf("SECTIONS ADDED:     %s\n", strings.Join(d.SectionsAdded, ", ")))
	}
	if len(d.SectionsRemoved) > 0 {
		sb.WriteString(fmt.Sprintf("SECTIONS REMOVED:   %s\n", strings.Join(d.SectionsRemoved, ", ")))
	}
	if len(d.SectionsChanged) > 0 {
		sb.WriteString(fmt.Sprintf("SECTIONS CHANGED:   %s\n", strings.Join(d.SectionsChanged, ", ")))
	}
	if len(d.ImportsAdded) > 0 {
		sb.WriteString(fmt.Sprintf("IMPORTS INJECTED:   %s\n", strings.Join(d.ImportsAdded, ", ")))
	}
	if len(d.MetadataChanges) > 0 {
		sb.WriteString(fmt.Sprintf("METADATA DIVERGENCE:%s\n", strings.Join(d.MetadataChanges, "; ")))
	}
	sb.WriteString("================================================================================\n")
	return sb.String()
}
