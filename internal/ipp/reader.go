package ipp

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"
)

// Reader provides high-level IPP communication with the cVEND NFC reader.
type Reader struct {
	transport *Transport
	seq       Sequencer
	accum     []byte
	buf       []byte
}

// NewReader creates a Reader on the given transport.
func NewReader(t *Transport) *Reader {
	return &Reader{
		transport: t,
		buf:       make([]byte, 4096),
	}
}

// SendFrame builds and sends an IPP frame.
func (r *Reader) SendFrame(msgType byte, payload []byte) error {
	frame := BuildFrame(r.seq.Next(), msgType, payload)
	log.Printf("TX [%s] payload=%s", MsgName(msgType), hex.EncodeToString(payload))
	return r.transport.Write(frame)
}

// ReadFrames reads and parses all available frames until timeout.
func (r *Reader) ReadFrames(timeout time.Duration) []Frame {
	var frames []Frame
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		n, _ := r.transport.Read(r.buf)
		if n > 0 {
			r.accum = append(r.accum, r.buf[:n]...)
		}
		for {
			frame, consumed, err := ParseFrame(r.accum)
			if err != nil {
				if consumed > 0 {
					r.accum = r.accum[consumed:]
					continue
				}
				break
			}
			r.logFrame(frame)
			frames = append(frames, *frame)
			r.accum = r.accum[consumed:]
		}
		if n == 0 {
			// No data available, brief yield before retry
			time.Sleep(10 * time.Millisecond)
		}
	}
	return frames
}

// WaitForFrame waits for a frame matching one of the given message types.
// Returns nil if timeout expires.
func (r *Reader) WaitForFrame(types []byte, timeout time.Duration) *Frame {
	typeSet := make(map[byte]bool, len(types))
	for _, t := range types {
		typeSet[t] = true
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		n, _ := r.transport.Read(r.buf)
		if n > 0 {
			r.accum = append(r.accum, r.buf[:n]...)
		}
		for {
			frame, consumed, err := ParseFrame(r.accum)
			if err != nil {
				if consumed > 0 {
					r.accum = r.accum[consumed:]
					continue
				}
				break
			}
			r.logFrame(frame)
			if typeSet[frame.MsgType] {
				r.accum = r.accum[consumed:]
				return frame
			}
			r.accum = r.accum[consumed:]
		}
		if n == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	return nil
}

// Drain reads and discards all pending frames.
func (r *Reader) Drain(timeout time.Duration) {
	r.ReadFrames(timeout)
}

// Init performs the reader initialization sequence:
// wait for heartbeat, request version, enable ISO card polling.
func (r *Reader) Init() error {
	// Wake reader
	log.Println("Sending status ping to wake reader...")
	r.SendFrame(MsgStatus, nil)

	log.Println("Waiting for reader heartbeat or status reply...")
	f := r.WaitForFrame([]byte{MsgHeartbeat, MsgStartup, MsgStatusReply}, 30*time.Second)
	if f == nil {
		return fmt.Errorf("no response from reader within 30s — is the cVEND powered on?")
	}
	log.Printf("Reader alive (got %s)", MsgName(f.MsgType))

	// Abort any stale card session
	log.Println("Aborting stale card sessions...")
	r.SendFrame(0x46, nil) // AbortCardHandling
	r.Drain(2 * time.Second)

	r.SendFrame(MsgVersion, nil)
	r.ReadFrames(2 * time.Second)

	// Disable then re-enable ISO polling (clean slate)
	log.Println("Re-enabling ISO card polling (type 6)...")
	r.SendFrame(MsgProxCardFunc, []byte{0x00, 0x06, 0x01, 0x00}) // disable
	r.ReadFrames(1 * time.Second)
	r.SendFrame(MsgProxCardFunc, []byte{0x00, 0x06, 0x01, 0x01}) // enable
	r.ReadFrames(2 * time.Second)

	// Abort again in case re-enable triggered a detection
	r.SendFrame(0x46, nil)
	r.Drain(2 * time.Second)

	return nil
}

// WaitForCard waits for an ISO card detection event.
// Returns the UID (4 bytes) from the ISORead payload.
// ISORead payload bytes 2-8 contain the UID field (7 bytes, zero-padded).
// JCOP cards use 4-byte UIDs; the trailing 3 bytes are padding.
func (r *Reader) WaitForCard(timeout time.Duration) (uid []byte, err error) {
	f := r.WaitForFrame([]byte{MsgISORead, MsgCardConfig}, timeout)
	if f == nil {
		return nil, fmt.Errorf("no card detected within %v", timeout)
	}
	// If we got CardConfig first, wait for the actual ISORead
	if f.MsgType == MsgCardConfig {
		f = r.WaitForFrame([]byte{MsgISORead}, 5*time.Second)
		if f == nil {
			return nil, fmt.Errorf("got CardConfig but no ISORead followed")
		}
	}
	if len(f.Payload) < 9 {
		return nil, fmt.Errorf("ISORead payload too short: %d bytes", len(f.Payload))
	}
	uid = make([]byte, 4)
	copy(uid, f.Payload[2:6])
	return uid, nil
}

// SendAPDU sends an APDU via APDUProx and waits for the reply.
func (r *Reader) SendAPDU(cla, ins, p1, p2 byte, data []byte, le uint16) (*APDUReply, error) {
	wrapped := WrapAPDU(cla, ins, p1, p2, data, le)
	if err := r.SendFrame(MsgAPDUProx, wrapped); err != nil {
		return nil, fmt.Errorf("send APDU: %w", err)
	}
	f := r.WaitForFrame([]byte{MsgAPDUProxReply}, 5*time.Second)
	if f == nil {
		return nil, fmt.Errorf("no APDU reply within 5s")
	}
	return ParseAPDUReply(f.Payload)
}

// ReleaseCard sends CardRelease (0x32) to end the card session.
func (r *Reader) ReleaseCard() error {
	if err := r.SendFrame(MsgCardRelease, nil); err != nil {
		return err
	}
	// Wait briefly for the release confirmation
	r.WaitForFrame([]byte{MsgISOCardRelease, MsgCardConfig}, 2*time.Second)
	return nil
}

// Buzzer sends a buzzer command with the given frequency (Hz) and duration (ms).
func (r *Reader) Buzzer(freqHz, durationMs uint16) error {
	payload := []byte{
		byte(freqHz >> 8), byte(freqHz & 0xFF),
		byte(durationMs >> 8), byte(durationMs & 0xFF),
	}
	return r.SendFrame(MsgBuzzer, payload)
}

// StatusPing sends a status request to keep the reader awake.
func (r *Reader) StatusPing() error {
	return r.SendFrame(MsgStatus, nil)
}

func (r *Reader) logFrame(f *Frame) {
	name := MsgName(f.MsgType)
	extra := ""

	switch f.MsgType {
	case MsgHeartbeat:
		return // suppress heartbeat noise
	case MsgLog:
		if len(f.Payload) > 1 {
			levels := []string{"?", "INFO", "WARN", "ERROR"}
			lvl := int(f.Payload[0])
			msg := string(f.Payload[1:])
			if idx := strings.IndexByte(msg, 0); idx >= 0 {
				msg = msg[:idx]
			}
			if lvl < len(levels) {
				extra = fmt.Sprintf(" [%s] %s", levels[lvl], msg)
			}
		}
	case MsgISORead:
		if len(f.Payload) >= 9 {
			extra = fmt.Sprintf(" UID=%s", hex.EncodeToString(f.Payload[2:9]))
		}
	case MsgAPDUProxReply:
		extra = fmt.Sprintf(" data=%s", hex.EncodeToString(f.Payload))
	}

	log.Printf("RX [%s] seq=%02X payload=%s%s",
		name, f.Seq, hex.EncodeToString(f.Payload), extra)
}
