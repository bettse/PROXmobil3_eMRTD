package emrtd

import (
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/bettse/emrtd/internal/bac"
	"github.com/bettse/emrtd/internal/ipp"
	"github.com/bettse/emrtd/internal/sm"
)

var emrtdAID, _ = hex.DecodeString("A0000002471001")

// ProgressFunc is called during file reads with (bytesRead, totalBytes).
type ProgressFunc func(bytesRead, totalBytes int)

// ReadResult holds the data read from an eMRTD.
type ReadResult struct {
	MRZ      *MRZData // Parsed DG1
	FaceJPEG []byte   // Raw JPEG/JP2 from DG2
}

// Read performs the full eMRTD reading sequence:
// SELECT AID → BAC → read DG1 → read DG2.
// The optional progress callback is called during DG2 reads.
func Read(reader *ipp.Reader, mrzInfo *bac.MRZInfo, progress ProgressFunc) (*ReadResult, error) {
	// SELECT eMRTD application
	reply, err := reader.SendAPDU(0x00, 0xA4, 0x04, 0x0C, emrtdAID, 0)
	if err != nil {
		return nil, fmt.Errorf("SELECT eMRTD AID: %w", err)
	}
	if reply.SW() != 0x9000 {
		return nil, fmt.Errorf("SELECT eMRTD AID: SW=%04X", reply.SW())
	}
	log.Printf("SELECT eMRTD AID: OK")

	// BAC authentication
	apduSender := func(cla, ins, p1, p2 byte, data []byte, le uint16) ([]byte, uint16, error) {
		r, err := reader.SendAPDU(cla, ins, p1, p2, data, le)
		if err != nil {
			return nil, 0, err
		}
		if r.Status != 0x00 {
			return nil, 0, fmt.Errorf("APDU proxy status=0x%02X", r.Status)
		}
		return r.Data, r.SW(), nil
	}

	keys, err := bac.Authenticate(mrzInfo, apduSender)
	if err != nil {
		return nil, fmt.Errorf("BAC: %w", err)
	}
	log.Printf("BAC authentication successful")

	// Create secure messaging channel
	sec := sm.New(keys.KSenc, keys.KSmac, keys.SSC)

	result := &ReadResult{}

	// Read DG1 (MRZ)
	dg1Raw, err := readFile(reader, sec, 0x01, 0x01, nil)
	if err != nil {
		return nil, fmt.Errorf("read DG1: %w", err)
	}
	log.Printf("DG1: %d bytes", len(dg1Raw))
	result.MRZ, err = ParseDG1(dg1Raw)
	if err != nil {
		log.Printf("DG1 parse warning: %v", err)
	}

	// Read DG2 (face image) with progress callback
	dg2Raw, err := readFile(reader, sec, 0x01, 0x02, progress)
	if err != nil {
		log.Printf("DG2 read failed (non-fatal): %v", err)
	} else {
		log.Printf("DG2: %d bytes", len(dg2Raw))
		result.FaceJPEG = ExtractFaceImage(dg2Raw)
	}

	return result, nil
}

// readFile selects and reads an EF using secure messaging.
func readFile(reader *ipp.Reader, sec *sm.SecureMessaging, fid1, fid2 byte, progress ProgressFunc) ([]byte, error) {
	// SELECT EF
	fileID := []byte{fid1, fid2}
	if err := sendSecure(reader, sec, 0x00, 0xA4, 0x02, 0x0C, fileID, 0); err != nil {
		return nil, fmt.Errorf("SELECT EF %02X%02X: %w", fid1, fid2, err)
	}

	// Read first 4 bytes to get TLV tag + length
	header, err := readBinarySecure(reader, sec, 0, 4)
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	// Parse TLV length to know total file size
	totalLen, headerLen := parseTLVHeader(header)
	if totalLen <= 0 {
		return nil, fmt.Errorf("invalid TLV header")
	}
	fileSize := headerLen + totalLen
	log.Printf("EF %02X%02X: TLV total=%d bytes (headerLen=%d, contentLen=%d)", fid1, fid2, fileSize, headerLen, totalLen)

	// Read the full file in chunks
	const chunkSize = 512 // larger chunks = fewer round-trips through cVEND proxy
	data := make([]byte, 0, fileSize)
	data = append(data, header...)

	offset := len(header)
	for offset < fileSize {
		remaining := fileSize - offset
		readLen := chunkSize
		if remaining < readLen {
			readLen = remaining
		}

		chunk, err := readBinarySecure(reader, sec, offset, readLen)
		if err != nil {
			return nil, fmt.Errorf("read at offset %d: %w", offset, err)
		}
		data = append(data, chunk...)
		offset += len(chunk)
		if progress != nil {
			progress(offset, fileSize)
		}
		if len(chunk) == 0 {
			break
		}
	}

	return data, nil
}

// sendSecureAPDU sends an SM-wrapped APDU using param_7=0x05 to tell the cVEND
// that both data and response are present. All SM commands expect at minimum
// DO99+DO8E in the response.
func sendSecureAPDU(reader *ipp.Reader, newCLA, ins, p1, p2 byte, newData []byte, newLe uint16) (*ipp.APDUReply, error) {
	// SM commands always have data (DO87/DO97/DO8E) and always expect
	// response data (DO99+DO8E). Use param_7=0x05 (bit 2=data, bit 0=response).
	wrapped := ipp.WrapAPDUFull(newCLA, ins, p1, p2, newData, 0x05, newLe)
	if err := reader.SendFrame(ipp.MsgAPDUProx, wrapped); err != nil {
		return nil, fmt.Errorf("send APDU: %w", err)
	}
	f := reader.WaitForFrame([]byte{ipp.MsgAPDUProxReply}, 5*time.Second)
	if f == nil {
		return nil, fmt.Errorf("no APDU reply within 5s")
	}
	return ipp.ParseAPDUReply(f.Payload)
}

// sendSecure wraps and sends an APDU through secure messaging.
func sendSecure(reader *ipp.Reader, sec *sm.SecureMessaging, cla, ins, p1, p2 byte, data []byte, le int) error {
	newCLA, newData, newLe := sec.WrapAPDU(cla, ins, p1, p2, data, le)

	reply, err := sendSecureAPDU(reader, newCLA, ins, p1, p2, newData, newLe)
	if err != nil {
		return err
	}
	if reply.Status != 0x00 {
		return fmt.Errorf("APDU proxy status=0x%02X", reply.Status)
	}

	if reply.SW() != 0x9000 {
		return fmt.Errorf("SW=%04X", reply.SW())
	}

	// Unwrap SM response to verify MAC and keep SSC in sync.
	// The passport always increments SSC for the response, so we must too.
	if len(reply.Data) > 0 {
		_, err = sec.UnwrapRAPDU(reply.Data, reply.SW1, reply.SW2)
		if err != nil {
			return fmt.Errorf("unwrap: %w", err)
		}
	} else {
		// No SM data in response — passport still incremented SSC.
		sec.IncrementSSC()
	}

	return nil
}

// readBinarySecure reads bytes from the selected EF at the given offset using secure messaging.
func readBinarySecure(reader *ipp.Reader, sec *sm.SecureMessaging, offset, length int) ([]byte, error) {
	p1 := byte((offset >> 8) & 0x7F)
	p2 := byte(offset & 0xFF)

	newCLA, newData, newLe := sec.WrapAPDU(0x00, 0xB0, p1, p2, nil, length)

	reply, err := sendSecureAPDU(reader, newCLA, 0xB0, p1, p2, newData, newLe)
	if err != nil {
		return nil, err
	}
	if reply.Status != 0x00 {
		return nil, fmt.Errorf("APDU proxy status=0x%02X", reply.Status)
	}
	if reply.SW() != 0x9000 {
		return nil, fmt.Errorf("SW=%04X", reply.SW())
	}

	if len(reply.Data) == 0 {
		return nil, nil
	}

	decrypted, err := sec.UnwrapRAPDU(reply.Data, reply.SW1, reply.SW2)
	if err != nil {
		return nil, fmt.Errorf("unwrap: %w", err)
	}

	return decrypted, nil
}

// parseTLVHeader parses a BER-TLV tag+length header.
// Returns (content length, header length).
func parseTLVHeader(data []byte) (int, int) {
	if len(data) < 2 {
		return 0, 0
	}

	// Skip tag (1 or 2 bytes)
	tagLen := 1
	if data[0]&0x1F == 0x1F {
		tagLen = 2
	}
	if tagLen >= len(data) {
		return 0, 0
	}

	// Parse length
	pos := tagLen
	if data[pos] < 0x80 {
		return int(data[pos]), pos + 1
	}
	numBytes := int(data[pos] & 0x7F)
	pos++
	if pos+numBytes > len(data) {
		return 0, 0
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = length<<8 | int(data[pos+i])
	}
	return length, pos + numBytes
}
