package emrtd

import (
	"fmt"
	"strings"
)

// MRZData holds parsed MRZ fields from DG1.
type MRZData struct {
	DocumentType string
	IssuingState string
	Name         string // "SURNAME, GIVEN NAMES"
	Surname      string
	GivenNames   string
	DocNumber    string
	Nationality  string
	DateOfBirth  string // YYMMDD
	Sex          string
	DateOfExpiry string // YYMMDD
	MRZLine1     string
	MRZLine2     string
}

// ParseDG1 parses the DG1 data group (MRZ).
// DG1 TLV structure: tag 61 -> tag 5F1F -> MRZ string (88 bytes for TD3).
func ParseDG1(data []byte) (*MRZData, error) {
	// Strip outer TLV wrapper(s) to find the MRZ string
	mrz := extractMRZFromDG1(data)
	if mrz == "" {
		return nil, fmt.Errorf("could not extract MRZ from DG1")
	}

	return ParseMRZString(mrz)
}

// ParseMRZString parses a raw MRZ string (88 chars for TD3 passport).
func ParseMRZString(mrz string) (*MRZData, error) {
	// TD3 passport: 2 lines of 44 chars
	if len(mrz) < 88 {
		return nil, fmt.Errorf("MRZ too short: %d chars", len(mrz))
	}

	line1 := mrz[0:44]
	line2 := mrz[44:88]

	d := &MRZData{
		MRZLine1: line1,
		MRZLine2: line2,
	}

	// Line 1: P<ISSNAME<<GIVEN<NAMES<<<<<<<<<<<<<<<<<<<<
	d.DocumentType = strings.TrimRight(line1[0:2], "<")
	d.IssuingState = line1[2:5]

	// Name field: positions 5-43
	nameField := line1[5:44]
	parts := strings.SplitN(nameField, "<<", 2)
	d.Surname = strings.ReplaceAll(parts[0], "<", " ")
	if len(parts) > 1 {
		d.GivenNames = strings.ReplaceAll(strings.TrimRight(parts[1], "<"), "<", " ")
	}
	d.Name = d.Surname
	if d.GivenNames != "" {
		d.Name += ", " + d.GivenNames
	}

	// Line 2: DDDDDDDDDcNNNDDDDDDcSEEEEEEc...
	d.DocNumber = strings.TrimRight(line2[0:9], "<")
	d.Nationality = line2[10:13]
	d.DateOfBirth = line2[13:19]
	d.Sex = string(line2[20])
	d.DateOfExpiry = line2[21:27]

	return d, nil
}

// extractMRZFromDG1 digs through TLV to find the MRZ string.
func extractMRZFromDG1(data []byte) string {
	// DG1 structure: 61 len [5F1F len <MRZ>]
	// We search for tag 5F1F which contains the raw MRZ bytes.
	pos := 0
	for pos < len(data)-3 {
		if data[pos] == 0x5F && data[pos+1] == 0x1F {
			pos += 2
			length, lenBytes := parseBERLengthAt(data[pos:])
			pos += lenBytes
			if pos+length <= len(data) {
				return string(data[pos : pos+length])
			}
		}
		pos++
	}

	// Fallback: if the data is just the raw MRZ (88+ bytes of printable ASCII)
	if len(data) >= 88 && isPrintableMRZ(data[:88]) {
		return string(data[:88])
	}

	return ""
}

func parseBERLengthAt(data []byte) (int, int) {
	if len(data) == 0 {
		return 0, 0
	}
	if data[0] < 0x80 {
		return int(data[0]), 1
	}
	n := int(data[0] & 0x7F)
	if n == 0 || len(data) < 1+n {
		return 0, 1
	}
	length := 0
	for i := 0; i < n; i++ {
		length = length<<8 | int(data[1+i])
	}
	return length, 1 + n
}

func isPrintableMRZ(data []byte) bool {
	for _, b := range data {
		if b >= 'A' && b <= 'Z' {
			continue
		}
		if b >= '0' && b <= '9' {
			continue
		}
		if b == '<' {
			continue
		}
		return false
	}
	return true
}
