package sm

import (
	"crypto/cipher"
	"crypto/des"
	"encoding/binary"
	"fmt"
)

// SecureMessaging handles eMRTD secure messaging (3DES) after BAC.
type SecureMessaging struct {
	ksEnc []byte  // 16-byte session encryption key
	ksMac []byte  // 16-byte session MAC key
	ssc   [8]byte // Send Sequence Counter
}

// New creates a SecureMessaging instance with the given session keys and SSC.
func New(ksEnc, ksMac []byte, ssc [8]byte) *SecureMessaging {
	return &SecureMessaging{
		ksEnc: ksEnc,
		ksMac: ksMac,
		ssc:   ssc,
	}
}

// WrapAPDU wraps a command APDU with secure messaging.
// Returns the protected APDU: CLA=0x0C, same INS/P1/P2, SM data objects in body.
func (sm *SecureMessaging) WrapAPDU(cla, ins, p1, p2 byte, data []byte, le int) (newCLA byte, newData []byte, newLe uint16) {
	sm.incrementSSC()

	var body []byte

	// DO87: encrypted data (if command has data)
	if len(data) > 0 {
		padded := padISO9797(data)
		encrypted := sm.encryptCBC(padded)
		// DO87: tag 87 + length + 01 (padding indicator) + encrypted data
		do87content := append([]byte{0x01}, encrypted...)
		do87 := buildDO(0x87, do87content)
		body = append(body, do87...)
	}

	// DO97: expected length (if Le > 0)
	if le > 0 {
		if le <= 0xFF {
			body = append(body, 0x97, 0x01, byte(le))
		} else {
			body = append(body, 0x97, 0x02, byte(le>>8), byte(le&0xFF))
		}
	}

	// Compute MAC over: SSC || padded command header || DO87 || DO97
	cmdHeader := []byte{0x0C, ins, p1, p2}
	paddedHeader := padISO9797(cmdHeader)

	macInput := make([]byte, 0, 8+len(paddedHeader)+len(body))
	macInput = append(macInput, sm.ssc[:]...)
	macInput = append(macInput, paddedHeader...)
	if len(body) > 0 {
		macInput = append(macInput, padISO9797(body)...)
	}

	mac := sm.macISO9797Alg3(macInput)

	// DO8E: MAC
	do8e := buildDO(0x8E, mac)
	body = append(body, do8e...)

	// Le=0 through the cVEND proxy: non-zero Le values cause proxy errors.
	// The cVEND handles Le=0 and returns whatever data the card sends.
	return 0x0C, body, 0
}

// UnwrapRAPDU unwraps a secure messaging response APDU.
// Returns the decrypted data and verifies the MAC.
func (sm *SecureMessaging) UnwrapRAPDU(data []byte, sw1, sw2 byte) ([]byte, error) {
	sm.incrementSSC()

	var decryptedData []byte
	var do87 []byte
	var do99 []byte
	var do8e []byte

	// Parse TLV data objects from the response
	pos := 0
	for pos < len(data) {
		if pos >= len(data) {
			break
		}
		tag := data[pos]
		pos++

		length, lenBytes := parseBERLength(data[pos:])
		pos += lenBytes

		if pos+length > len(data) {
			return nil, fmt.Errorf("TLV overflow at tag 0x%02X", tag)
		}
		value := data[pos : pos+length]
		pos += length

		switch tag {
		case 0x87:
			do87 = buildDO(0x87, value)
			// Decrypt: skip padding indicator byte (0x01), decrypt rest
			if len(value) < 2 || value[0] != 0x01 {
				return nil, fmt.Errorf("DO87: invalid padding indicator")
			}
			decrypted := sm.decryptCBC(value[1:])
			decryptedData = unpadISO9797(decrypted)
		case 0x99:
			do99 = buildDO(0x99, value)
		case 0x8E:
			do8e = value
		}
	}

	// Verify MAC
	if do8e == nil {
		return nil, fmt.Errorf("no MAC (DO8E) in response")
	}

	// If no DO99, build it from sw1/sw2
	if do99 == nil {
		do99 = []byte{0x99, 0x02, sw1, sw2}
	}

	macInput := make([]byte, 0, 64)
	macInput = append(macInput, sm.ssc[:]...)
	if do87 != nil {
		macInput = append(macInput, do87...)
	}
	macInput = append(macInput, do99...)
	macInput = padISO9797(macInput)

	expectedMAC := sm.macISO9797Alg3(macInput)
	if !equal(do8e, expectedMAC) {
		return nil, fmt.Errorf("MAC verification failed")
	}

	return decryptedData, nil
}

// IncrementSSC advances the SSC by one. Use when the SM response cannot be
// unwrapped (e.g., empty response) but the passport still incremented its SSC.
func (sm *SecureMessaging) IncrementSSC() {
	sm.incrementSSC()
}

func (sm *SecureMessaging) incrementSSC() {
	// Increment SSC as big-endian 8-byte counter
	val := binary.BigEndian.Uint64(sm.ssc[:])
	val++
	binary.BigEndian.PutUint64(sm.ssc[:], val)
}

func (sm *SecureMessaging) encryptCBC(plaintext []byte) []byte {
	block, _ := des.NewTripleDESCipher(expandTo24(sm.ksEnc))
	ct := make([]byte, len(plaintext))
	// BAC-based SM uses zero IV (SSC-derived IV is only for PACE/AES)
	iv := make([]byte, 8)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ct, plaintext)
	return ct
}

func (sm *SecureMessaging) decryptCBC(ciphertext []byte) []byte {
	block, _ := des.NewTripleDESCipher(expandTo24(sm.ksEnc))
	pt := make([]byte, len(ciphertext))
	// BAC-based SM uses zero IV
	iv := make([]byte, 8)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(pt, ciphertext)
	return pt
}

func (sm *SecureMessaging) macISO9797Alg3(data []byte) []byte {
	k1 := sm.ksMac[:8]
	k2 := sm.ksMac[8:16]

	// Ensure data is padded to 8-byte boundary (caller should have padded)
	// But if not, pad it
	padded := data
	if len(padded)%8 != 0 {
		padded = padISO9797(data)
	}

	block1, _ := des.NewCipher(k1)
	mac := make([]byte, 8)
	for i := 0; i < len(padded); i += 8 {
		xorBytes(mac, padded[i:i+8])
		block1.Encrypt(mac, mac)
	}

	block2, _ := des.NewCipher(k2)
	block2.Decrypt(mac, mac)
	block1.Encrypt(mac, mac)

	return mac
}

// buildDO builds a BER-TLV data object: tag + length + value.
func buildDO(tag byte, value []byte) []byte {
	var buf []byte
	buf = append(buf, tag)
	buf = append(buf, berLength(len(value))...)
	buf = append(buf, value...)
	return buf
}

// berLength encodes a length in BER format.
func berLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	if n < 0x100 {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n & 0xFF)}
}

// parseBERLength parses a BER length and returns (length, bytes consumed).
func parseBERLength(data []byte) (int, int) {
	if len(data) == 0 {
		return 0, 0
	}
	if data[0] < 0x80 {
		return int(data[0]), 1
	}
	numBytes := int(data[0] & 0x7F)
	if numBytes == 0 || len(data) < 1+numBytes {
		return 0, 1
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = length<<8 | int(data[1+i])
	}
	return length, 1 + numBytes
}

func padISO9797(data []byte) []byte {
	padded := make([]byte, len(data)+1)
	copy(padded, data)
	padded[len(data)] = 0x80
	for len(padded)%8 != 0 {
		padded = append(padded, 0x00)
	}
	return padded
}

func unpadISO9797(data []byte) []byte {
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == 0x80 {
			return data[:i]
		}
		if data[i] != 0x00 {
			break
		}
	}
	return data // no padding found, return as-is
}

func expandTo24(key []byte) []byte {
	k := make([]byte, 24)
	copy(k[0:8], key[0:8])
	copy(k[8:16], key[8:16])
	copy(k[16:24], key[0:8])
	return k
}

func xorBytes(dst, src []byte) {
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
