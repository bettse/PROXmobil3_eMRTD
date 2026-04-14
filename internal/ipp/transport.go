package ipp

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// Transport handles serial port I/O for IPP communication.
type Transport struct {
	fd   int
	path string
}

// OpenTransport opens and configures the serial port for IPP communication.
// Settings: 115200 baud, 8N1, raw mode, no echo.
func OpenTransport(path string) (*Transport, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	var termios unix.Termios
	termios.Cflag = unix.B115200 | unix.CS8 | unix.CREAD | unix.CLOCAL
	termios.Iflag = 0
	termios.Oflag = 0
	termios.Lflag = 0
	termios.Cc[unix.VMIN] = 0
	termios.Cc[unix.VTIME] = 5 // 500ms read timeout

	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &termios); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("configure %s: %w", path, err)
	}
	unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIOFLUSH)

	return &Transport{fd: fd, path: path}, nil
}

// Close closes the serial port.
func (t *Transport) Close() error {
	return unix.Close(t.fd)
}

// Write sends raw bytes to the serial port.
func (t *Transport) Write(data []byte) error {
	for len(data) > 0 {
		n, err := unix.Write(t.fd, data)
		if err != nil {
			return fmt.Errorf("write %s: %w", t.path, err)
		}
		data = data[n:]
	}
	return nil
}

// Read reads available bytes from the serial port into buf.
// Returns the number of bytes read. Non-blocking (returns 0 if no data).
func (t *Transport) Read(buf []byte) (int, error) {
	n, err := unix.Read(t.fd, buf)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", t.path, err)
	}
	return n, nil
}

// ReadWithDeadline reads bytes until the deadline, accumulating into the buffer.
func (t *Transport) ReadWithDeadline(buf []byte, deadline time.Time) (int, error) {
	total := 0
	for time.Now().Before(deadline) {
		n, err := unix.Read(t.fd, buf[total:])
		if err != nil {
			return total, err
		}
		total += n
		if total >= len(buf) {
			break
		}
	}
	return total, nil
}

// Fd returns the underlying file descriptor (for use with polling if needed).
func (t *Transport) Fd() int {
	return t.fd
}

// OpenWatchdog opens the PIC32 watchdog serial port (/dev/ttymxc2).
// Returns an *os.File for writing keepalive bytes.
func OpenWatchdog(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open watchdog %s: %w", path, err)
	}
	return f, nil
}
