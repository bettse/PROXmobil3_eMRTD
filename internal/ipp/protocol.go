package ipp

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"sync"
)

// IPP message types
const (
	MsgVersion        = 0x02
	MsgVersionReply   = 0x03
	MsgStatus         = 0x04
	MsgStatusReply    = 0x05
	MsgHeartbeat      = 0x07
	MsgStartup        = 0x0F
	MsgReset          = 0x10
	MsgResetReply     = 0x11
	MsgLED            = 0x20
	MsgBuzzer         = 0x22
	MsgCardRelease    = 0x32
	MsgISORead        = 0xB1
	MsgISOCardRelease = 0xB3
	MsgAPDUProx       = 0xB4
	MsgAPDUProxReply  = 0xB5
	MsgDESFireRead    = 0xB9
	MsgDESFireRemoved = 0xBB
	MsgDESFireCmd     = 0xBC
	MsgDESFireReply   = 0xBD
	MsgUnhandledCard  = 0xBE
	MsgCardConfig     = 0xD1
	MsgProxCardFunc   = 0xE4
	MsgProxCardReply  = 0xE5
	MsgLog            = 0xED
)

// MsgName returns a human-readable name for a message type.
func MsgName(msgType byte) string {
	if name, ok := msgNames[msgType]; ok {
		return name
	}
	return fmt.Sprintf("0x%02X", msgType)
}

var msgNames = map[byte]string{
	MsgVersion:        "Version",
	MsgVersionReply:   "VersionReply",
	MsgStatus:         "Status",
	MsgStatusReply:    "StatusReply",
	MsgHeartbeat:      "Heartbeat",
	MsgStartup:        "Startup",
	MsgReset:          "Reset",
	MsgResetReply:     "ResetReply",
	MsgLED:            "LED",
	MsgBuzzer:         "Buzzer",
	MsgCardRelease:    "CardRelease",
	MsgISORead:        "ISORead",
	MsgISOCardRelease: "ISOCardRelease",
	MsgAPDUProx:       "APDUProx",
	MsgAPDUProxReply:  "APDUProxReply",
	MsgDESFireRead:    "DESFireRead",
	MsgDESFireRemoved: "DESFireRemoved",
	MsgDESFireCmd:     "DESFireCmd",
	MsgDESFireReply:   "DESFireReply",
	MsgUnhandledCard:  "UnhandledCard",
	MsgCardConfig:     "CardConfig",
	MsgProxCardFunc:   "ProxCardFunc",
	MsgProxCardReply:  "ProxCardReply",
	MsgLog:            "Log",
}

// Frame represents a parsed IPP frame.
type Frame struct {
	Seq     byte
	Flags   byte
	MsgType byte
	Payload []byte
}

// Sequencer manages the IPP sequence counter (1-255, wraps skipping 0).
type Sequencer struct {
	mu  sync.Mutex
	seq byte
}

func (s *Sequencer) Next() byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	if s.seq == 0 {
		s.seq = 1
	}
	return s.seq
}

// BuildFrame constructs a complete IPP frame with header CRC and optional message CRC.
func BuildFrame(seq byte, msgType byte, payload []byte) []byte {
	header := []byte{
		0xBC,
		seq,
		0x00, // flags
		msgType,
		byte(len(payload) >> 8),
		byte(len(payload) & 0xFF),
	}
	hcrc := CRC8Maxim(header)
	frame := make([]byte, 0, 7+len(payload)+4)
	frame = append(frame, header...)
	frame = append(frame, hcrc)
	frame = append(frame, payload...)
	if msgType&0x80 != 0 {
		frame = append(frame, CRC32InvLE(payload)...)
	}
	return frame
}

// ParseFrame attempts to parse an IPP frame from the buffer.
// Returns the parsed frame, number of bytes consumed, and any error.
// If the error is non-nil but consumed > 0, those bytes should be skipped.
func ParseFrame(data []byte) (*Frame, int, error) {
	if len(data) < 7 {
		return nil, 0, fmt.Errorf("need at least 7 bytes, have %d", len(data))
	}
	if data[0] != 0xBC {
		// Scan forward for sync byte
		for i := 1; i < len(data); i++ {
			if data[i] == 0xBC {
				return nil, i, fmt.Errorf("skipped %d bytes to sync", i)
			}
		}
		return nil, len(data), fmt.Errorf("no sync byte found")
	}

	payloadLen := int(data[4])<<8 | int(data[5])
	totalLen := 7 + payloadLen
	if data[3]&0x80 != 0 {
		totalLen += 4 // message CRC
	}
	if len(data) < totalLen {
		return nil, 0, fmt.Errorf("incomplete frame: need %d bytes, have %d", totalLen, len(data))
	}

	frame := &Frame{
		Seq:     data[1],
		Flags:   data[2],
		MsgType: data[3],
		Payload: make([]byte, payloadLen),
	}
	copy(frame.Payload, data[7:7+payloadLen])
	return frame, totalLen, nil
}

// CRC-8 Dallas/Maxim (reflected)
func CRC8Maxim(data []byte) byte {
	crc := byte(0)
	for _, b := range data {
		b = reflectByte(b)
		crc ^= b
		for i := 0; i < 8; i++ {
			if crc&0x80 != 0 {
				crc = (crc << 1) ^ 0x31
			} else {
				crc <<= 1
			}
		}
	}
	return reflectByte(crc)
}

func reflectByte(b byte) byte {
	var r byte
	for i := 0; i < 8; i++ {
		r = (r << 1) | (b & 1)
		b >>= 1
	}
	return r
}

// CRC32InvLE computes CRC-32 IEEE, inverts it, and returns as 4 little-endian bytes.
func CRC32InvLE(data []byte) []byte {
	c := crc32.ChecksumIEEE(data)
	inv := c ^ 0xFFFFFFFF
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, inv)
	return buf
}

// WrapAPDU wraps an ISO 7816 APDU into the APDUProx (0xB4) payload format.
//
// The reader firmware reconstructs the over-the-air extended APDU from this.
// It inserts the 0x00 extended marker between P2 and Lc. The trailing bytes
// are forwarded as-is after the data.
//
// For extended Case 2 (no data, Le present), the card expects:
//   CLA INS P1 P2 00 0000 00 Le_hi Le_lo
//   → 3-byte Le encoding (00 + 2-byte Le) per ISO 7816-4 when Lc is absent
//
// For extended Case 4 (data + Le), the card expects:
//   CLA INS P1 P2 00 Lc_hi Lc_lo [Data] Le_hi Le_lo
//   → 2-byte Le encoding per ISO 7816-4 when Lc is present
//
// The B4 trailing_byte (0x00) is part of the 3-byte Le for Case 2, but must
// be omitted for Case 4 to avoid an extra byte that causes SW=6700.
func WrapAPDU(cla, ins, p1, p2 byte, data []byte, le uint16) []byte {
	// param_7 controls how the reader constructs the on-wire APDU.
	// From RE'd NxProx call sites:
	//   0x01, 0x02 — commands without data (Case 2)
	//   0x04, 0x05, 0x0B — commands with data (Case 3/4)
	// Using 0x00 causes SW=6700 for data commands.
	trailing := byte(0x01) // default for no-data commands
	if len(data) > 0 {
		trailing = 0x04 // data commands
	}
	return WrapAPDUFull(cla, ins, p1, p2, data, trailing, le)
}

// WrapAPDUFull allows control of the trailing_byte (param_7 in the RE).
func WrapAPDUFull(cla, ins, p1, p2 byte, data []byte, trailingByte byte, le uint16) []byte {
	lc := uint16(len(data))
	buf := make([]byte, 0, 10+len(data))
	buf = append(buf, 0x00)             // device selector: NFC contactless
	buf = append(buf, cla, ins, p1, p2) // APDU header
	buf = append(buf, byte(lc>>8), byte(lc&0xFF)) // Lc (reader reads from offset 5-6)
	buf = append(buf, data...)          // command data
	buf = append(buf, trailingByte)     // trailing_byte (param_7)
	buf = append(buf, byte(le>>8), byte(le&0xFF)) // Le
	return buf
}

// WrapAPDUShort wraps a Case 2 short APDU (no data, only Le) for the IPP proxy.
// Some JCOP applets don't support extended APDU format for no-data commands.
// Format: [DevSel:1] [CLA INS P1 P2:4] [Lc:2BE=0000] [0x00] [Le:2BE]
// This is identical to WrapAPDU with nil data — provided for clarity.
func WrapAPDUShort(cla, ins, p1, p2 byte, le uint16) []byte {
	return WrapAPDU(cla, ins, p1, p2, nil, le)
}

// APDUReply represents a parsed B5 APDUProx reply.
type APDUReply struct {
	DevSel byte
	Echo   byte
	Status byte // 0x00=success, 0x6C=no session, 0x70=no card, 0x76=retry
	SW1    byte
	SW2    byte
	Data   []byte
}

// ParseAPDUReply parses a B5 reply payload.
func ParseAPDUReply(payload []byte) (*APDUReply, error) {
	if len(payload) < 5 {
		return nil, fmt.Errorf("APDUReply too short: %d bytes", len(payload))
	}
	reply := &APDUReply{
		DevSel: payload[0],
		Echo:   payload[1],
		Status: payload[2],
		SW1:    payload[3],
		SW2:    payload[4],
	}
	if len(payload) > 5 {
		reply.Data = make([]byte, len(payload)-5)
		copy(reply.Data, payload[5:])
	}
	return reply, nil
}

// SW returns the status word as a uint16.
func (r *APDUReply) SW() uint16 {
	return uint16(r.SW1)<<8 | uint16(r.SW2)
}

// Success returns true if the APDU exchange succeeded (status=0x00, SW=9000).
func (r *APDUReply) Success() bool {
	return r.Status == 0x00 && r.SW() == 0x9000
}
