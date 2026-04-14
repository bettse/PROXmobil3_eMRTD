package bac

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
)

// MRZInfo holds the BAC-relevant fields extracted from the MRZ.
type MRZInfo struct {
	DocumentNumber string // 9 chars + check digit
	DateOfBirth    string // 6 chars YYMMDD + check digit
	DateOfExpiry   string // 6 chars YYMMDD + check digit
}

// ParseMRZ extracts BAC fields from a TD3 (passport) MRZ line 2.
// Line 2 format: PPPPPPPPPcDDDDDDcSEEEEEEc...
// Positions (0-indexed):
//
//	0-8:   document number (9 chars)
//	9:     check digit
//	13-18: date of birth (6 chars)
//	19:    check digit
//	21-26: date of expiry (6 chars)
//	27:    check digit
func ParseMRZ(line2 string) (*MRZInfo, error) {
	if len(line2) < 28 {
		return nil, fmt.Errorf("MRZ line 2 too short: %d chars (need 28+)", len(line2))
	}
	return &MRZInfo{
		DocumentNumber: line2[0:10],  // 9 digits + check
		DateOfBirth:    line2[13:20], // 6 digits + check
		DateOfExpiry:   line2[21:28], // 6 digits + check
	}, nil
}

// ParseMRZTwoLine parses a two-line MRZ string (lines separated by newline,
// or a single 88-char TD3 string that needs splitting at position 44).
func ParseMRZTwoLine(mrz string) (*MRZInfo, error) {
	// Try newline-separated first
	for i := 0; i < len(mrz); i++ {
		if mrz[i] == '\n' {
			return ParseMRZ(mrz[i+1:])
		}
	}
	// No newline — if 88 chars, it's a concatenated TD3 MRZ (line1 + line2)
	if len(mrz) == 88 {
		return ParseMRZ(mrz[44:])
	}
	// Otherwise assume it's just line 2
	return ParseMRZ(mrz)
}

// SessionKeys holds the derived session encryption and MAC keys plus the SSC.
type SessionKeys struct {
	KSenc []byte   // 16-byte 3DES session encryption key
	KSmac []byte   // 16-byte 3DES session MAC key
	SSC   [8]byte  // Send Sequence Counter
}

// Authenticate performs BAC mutual authentication.
// sendAPDU sends a raw APDU (CLA, INS, P1, P2, data, Le) and returns (response data, SW, error).
type APDUSender func(cla, ins, p1, p2 byte, data []byte, le uint16) ([]byte, uint16, error)

func Authenticate(info *MRZInfo, sendAPDU APDUSender) (*SessionKeys, error) {
	// Derive BAC keys from MRZ
	kEnc, kMac := deriveDocumentKeys(info)

	// Step 1: GET CHALLENGE
	resp, sw, err := sendAPDU(0x00, 0x84, 0x00, 0x00, nil, 8)
	if err != nil {
		return nil, fmt.Errorf("GET CHALLENGE: %w", err)
	}
	if sw != 0x9000 {
		return nil, fmt.Errorf("GET CHALLENGE: SW=%04X", sw)
	}
	if len(resp) < 8 {
		return nil, fmt.Errorf("GET CHALLENGE: response too short (%d bytes)", len(resp))
	}
	rndICC := resp[:8]

	// Step 2: Generate random nonce and keying material
	rndIFD := make([]byte, 8)
	kIFD := make([]byte, 16)
	if _, err := rand.Read(rndIFD); err != nil {
		return nil, fmt.Errorf("generate rndIFD: %w", err)
	}
	if _, err := rand.Read(kIFD); err != nil {
		return nil, fmt.Errorf("generate kIFD: %w", err)
	}

	// Step 3: Build S = rndIFD || rndICC || kIFD
	S := make([]byte, 32)
	copy(S[0:8], rndIFD)
	copy(S[8:16], rndICC)
	copy(S[16:32], kIFD)

	// Step 4: Encrypt S with 3DES-CBC using kEnc
	eIFD := encryptCBC(kEnc, S)

	// Step 5: MAC over eIFD using kMac
	mIFD := macISO9797Alg3(kMac, eIFD)

	// Step 6: EXTERNAL AUTHENTICATE with eIFD || mIFD
	authData := make([]byte, 40)
	copy(authData[0:32], eIFD)
	copy(authData[32:40], mIFD)

	resp, sw, err = sendAPDU(0x00, 0x82, 0x00, 0x00, authData, 40)
	if err != nil {
		return nil, fmt.Errorf("EXTERNAL AUTHENTICATE: %w", err)
	}
	if sw != 0x9000 {
		return nil, fmt.Errorf("EXTERNAL AUTHENTICATE: SW=%04X", sw)
	}
	if len(resp) < 40 {
		return nil, fmt.Errorf("EXTERNAL AUTHENTICATE: response too short (%d bytes)", len(resp))
	}

	// Step 7: Verify response
	eICC := resp[:32]
	mICC := resp[32:40]

	// Verify MAC
	expectedMAC := macISO9797Alg3(kMac, eICC)
	if !equal(mICC, expectedMAC) {
		return nil, fmt.Errorf("EXTERNAL AUTHENTICATE: MAC verification failed")
	}

	// Decrypt response
	R := decryptCBC(kEnc, eICC)
	// R = rndICC' || rndIFD' || kICC
	rndICCCheck := R[0:8]
	rndIFDCheck := R[8:16]
	kICC := R[16:32]

	if !equal(rndICCCheck, rndICC) {
		return nil, fmt.Errorf("EXTERNAL AUTHENTICATE: rndICC mismatch")
	}
	if !equal(rndIFDCheck, rndIFD) {
		return nil, fmt.Errorf("EXTERNAL AUTHENTICATE: rndIFD mismatch")
	}

	// Step 8: Derive session keys
	kSeed := make([]byte, 16)
	for i := 0; i < 16; i++ {
		kSeed[i] = kIFD[i] ^ kICC[i]
	}

	ksEnc := deriveKey(kSeed, 1)
	ksMac := deriveKey(kSeed, 2)

	// Step 9: Initialize SSC
	var ssc [8]byte
	copy(ssc[0:4], rndICC[4:8])
	copy(ssc[4:8], rndIFD[4:8])

	return &SessionKeys{
		KSenc: ksEnc,
		KSmac: ksMac,
		SSC:   ssc,
	}, nil
}

// deriveDocumentKeys derives Kenc and Kmac from the MRZ info.
func deriveDocumentKeys(info *MRZInfo) (kEnc, kMac []byte) {
	// Build MRZ_information: docNum+check || DOB+check || DOE+check
	seed := info.DocumentNumber + info.DateOfBirth + info.DateOfExpiry

	h := sha1.Sum([]byte(seed))
	d := h[:16]

	kEnc = deriveKey(d, 1)
	kMac = deriveKey(d, 2)
	return
}

// deriveKey derives a 16-byte 3DES key from seed using the given counter.
func deriveKey(seed []byte, counter byte) []byte {
	// D || counter (4 bytes, big-endian)
	data := make([]byte, len(seed)+4)
	copy(data, seed)
	data[len(seed)+3] = counter

	h := sha1.Sum(data)
	key := make([]byte, 16)
	copy(key, h[:16])

	// Adjust DES parity bits
	adjustParity(key[:8])
	adjustParity(key[8:16])
	return key
}

// adjustParity adjusts the parity bits of a DES key (odd parity per byte).
func adjustParity(key []byte) {
	for i := range key {
		b := key[i]
		// Count bits set in upper 7 bits
		bits := 0
		for j := 1; j < 8; j++ {
			if b&(1<<uint(j)) != 0 {
				bits++
			}
		}
		// Set LSB to make odd parity
		if bits%2 == 0 {
			key[i] |= 1
		} else {
			key[i] &^= 1
		}
	}
}

// encryptCBC encrypts data with 3DES-CBC using zero IV.
func encryptCBC(key, plaintext []byte) []byte {
	block, _ := des.NewTripleDESCipher(expandTo24(key))
	ct := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, make([]byte, 8))
	mode.CryptBlocks(ct, plaintext)
	return ct
}

// decryptCBC decrypts data with 3DES-CBC using zero IV.
func decryptCBC(key, ciphertext []byte) []byte {
	block, _ := des.NewTripleDESCipher(expandTo24(key))
	pt := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, make([]byte, 8))
	mode.CryptBlocks(pt, ciphertext)
	return pt
}

// macISO9797Alg3 computes ISO 9797-1 Algorithm 3 MAC (retail MAC) with padding method 2.
// Uses first 8 bytes of key as K1, last 8 bytes as K2.
func macISO9797Alg3(key, data []byte) []byte {
	k1 := key[:8]
	k2 := key[8:16]

	// Pad with 0x80 then zeros to 8-byte boundary
	padded := padISO9797(data)

	// CBC-MAC with single DES using K1
	block1, _ := des.NewCipher(k1)
	mac := make([]byte, 8)
	for i := 0; i < len(padded); i += 8 {
		xor(mac, padded[i:i+8])
		block1.Encrypt(mac, mac)
	}

	// Final block: decrypt with K2, encrypt with K1
	block2, _ := des.NewCipher(k2)
	block2.Decrypt(mac, mac)
	block1.Encrypt(mac, mac)

	return mac
}

// padISO9797 applies ISO 9797-1 padding method 2 (0x80 + zeros to 8-byte boundary).
func padISO9797(data []byte) []byte {
	padded := make([]byte, len(data)+1)
	copy(padded, data)
	padded[len(data)] = 0x80
	// Pad to 8-byte boundary
	for len(padded)%8 != 0 {
		padded = append(padded, 0x00)
	}
	return padded
}

// expandTo24 expands a 16-byte 2-key 3DES key to 24 bytes (K1||K2||K1).
func expandTo24(key []byte) []byte {
	k := make([]byte, 24)
	copy(k[0:8], key[0:8])
	copy(k[8:16], key[8:16])
	copy(k[16:24], key[0:8])
	return k
}

func xor(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
