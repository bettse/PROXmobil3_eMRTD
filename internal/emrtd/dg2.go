package emrtd

// ExtractFaceImage extracts a JPEG or JPEG2000 image from DG2 raw data.
// DG2 contains a biometric data structure with nested TLV.
// We scan for JPEG (FFD8FF) or JPEG2000 (0000000C6A502020) headers.
func ExtractFaceImage(data []byte) []byte {
	// Look for JPEG SOI marker (FF D8 FF)
	for i := 0; i < len(data)-3; i++ {
		if data[i] == 0xFF && data[i+1] == 0xD8 && data[i+2] == 0xFF {
			// Find JPEG EOI marker (FF D9)
			for j := i + 3; j < len(data)-1; j++ {
				if data[j] == 0xFF && data[j+1] == 0xD9 {
					return data[i : j+2]
				}
			}
			// No EOI found, return from SOI to end
			return data[i:]
		}
	}

	// Look for JPEG2000 header (00 00 00 0C 6A 50 20 20)
	jp2Header := []byte{0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20}
	for i := 0; i < len(data)-len(jp2Header); i++ {
		match := true
		for j := 0; j < len(jp2Header); j++ {
			if data[i+j] != jp2Header[j] {
				match = false
				break
			}
		}
		if match {
			return data[i:]
		}
	}

	return nil
}
