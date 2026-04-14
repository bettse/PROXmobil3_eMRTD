package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/bettse/emrtd/internal/bac"
	"github.com/bettse/emrtd/internal/display"
	"github.com/bettse/emrtd/internal/emrtd"
	"github.com/bettse/emrtd/internal/ipp"

	"golang.org/x/sys/unix"
)

const (
	defaultNFCPort     = "/dev/ttymxc3"
	defaultBarcodePort = "/dev/ttyUSB0"
	watchdogPort       = "/dev/ttymxc2"

	statusPingInterval = 25 * time.Second
	watchdogInterval   = 30 * time.Second
	cardWaitTimeout    = 120 * time.Second
	postDetectDelay    = 100 * time.Millisecond
	resultDisplayTime  = 8 * time.Second
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	mrzFlag := flag.String("mrz", "", "MRZ line 2 (or full 2-line MRZ) for BAC authentication")
	nfcPort := flag.String("port", defaultNFCPort, "NFC reader serial port")
	barcodePort := flag.String("barcode", defaultBarcodePort, "barcode scanner serial port")
	flag.Parse()

	log.Println("emrtd starting")

	// Open display
	disp, err := display.Open()
	if err != nil {
		log.Printf("display: %v (continuing without display)", err)
	} else {
		defer disp.Close()
		disp.ShowBooting()
	}

	// Open NFC reader
	transport, err := ipp.OpenTransport(*nfcPort)
	if err != nil {
		log.Fatalf("NFC serial: %v", err)
	}
	defer transport.Close()

	reader := ipp.NewReader(transport)
	if err := reader.Init(); err != nil {
		log.Fatalf("reader init: %v", err)
	}

	// Start background goroutines
	go watchdogLoop()
	go keepaliveLoop(reader)

	sdNotify("READY=1")

	// Ready beep: ascending 4-tone fanfare
	reader.Buzzer(600, 80)
	time.Sleep(120 * time.Millisecond)
	reader.Buzzer(900, 80)
	time.Sleep(120 * time.Millisecond)
	reader.Buzzer(1200, 80)
	time.Sleep(120 * time.Millisecond)
	reader.Buzzer(1800, 200)
	log.Println("Ready")

	// Main loop
	firstRun := true
	for {
		sdNotify("WATCHDOG=1")

		// Step 1: Get MRZ
		var mrzInfo *bac.MRZInfo
		if *mrzFlag != "" {
			mrzInfo, err = bac.ParseMRZTwoLine(*mrzFlag)
			if err != nil {
				log.Fatalf("parse MRZ flag: %v", err)
			}
			log.Printf("MRZ from flag: doc=%s", mrzInfo.DocumentNumber)
		} else {
			// On first run, show the full "SCAN MRZ" screen.
			// On subsequent runs after a successful read, the result screen
			// is still showing with "SCAN MRZ QR CODE" at the bottom.
			if firstRun {
				if disp != nil {
					disp.ShowWaitingForMRZ()
				}
			}
			firstRun = false
			log.Println("Waiting for MRZ QR code scan...")
			mrzString, err := readBarcode(*barcodePort)
			if err != nil {
				log.Printf("barcode: %v", err)
				if disp != nil {
					disp.ShowError(err.Error())
				}
				firstRun = true // show full MRZ screen on retry
				time.Sleep(3 * time.Second)
				continue
			}
			log.Printf("MRZ scanned: %d chars", len(mrzString))
			mrzInfo, err = bac.ParseMRZTwoLine(mrzString)
			if err != nil {
				log.Printf("parse MRZ: %v", err)
				if disp != nil {
					disp.ShowError("BAD MRZ: "+err.Error())
				}
				firstRun = true
				time.Sleep(3 * time.Second)
				continue
			}
			log.Printf("MRZ parsed: doc=%s", mrzInfo.DocumentNumber)
		}

		// Step 2: Wait for passport tap
		if disp != nil {
			disp.ShowWaitingForCard()
		}
		log.Println("Waiting for passport...")
		uid, err := reader.WaitForCard(cardWaitTimeout)
		if err != nil {
			log.Printf("card wait: %v", err)
			continue
		}
		log.Printf("Card detected: UID=%X", uid)

		if disp != nil {
			disp.ShowAuthenticating()
		}

		// Post-detect delay for ISO 14443-4 activation
		time.Sleep(postDetectDelay)
		sdNotify("WATCHDOG=1")

		// Step 3: Read eMRTD (with progress display for DG2)
		var progressFunc emrtd.ProgressFunc
		if disp != nil {
			progressFunc = func(bytesRead, totalBytes int) {
				disp.ShowProgress(bytesRead, totalBytes)
			}
		}
		result, err := emrtd.Read(reader, mrzInfo, progressFunc)

		// Release card regardless of outcome
		reader.ReleaseCard()

		if err != nil {
			log.Printf("eMRTD read error: %v", err)
			if disp != nil {
				disp.ShowError(err.Error())
			}
			reader.Buzzer(300, 500)
			firstRun = true
			time.Sleep(resultDisplayTime)
		} else {
			log.Println("eMRTD read successful")
			if result.MRZ != nil {
				log.Printf("  Name: %s", result.MRZ.Name)
				log.Printf("  Doc:  %s", result.MRZ.DocNumber)
				log.Printf("  Nat:  %s", result.MRZ.Nationality)
				log.Printf("  DOB:  %s", result.MRZ.DateOfBirth)
				log.Printf("  Sex:  %s", result.MRZ.Sex)
				log.Printf("  DOE:  %s", result.MRZ.DateOfExpiry)
			}
			if result.FaceJPEG != nil {
				log.Printf("  Face: %d bytes", len(result.FaceJPEG))
			}
			if disp != nil {
				disp.ShowResult(result.MRZ, result.FaceJPEG)
			}
			reader.Buzzer(2000, 150)

			// When using barcode mode, keep showing results until next scan.
			// The next iteration of the loop will show "SCAN MRZ QR CODE"
			// via the result screen's bottom prompt, then block on barcode read.
			if *mrzFlag != "" {
				time.Sleep(resultDisplayTime)
			}
			// In barcode mode, fall through immediately — the result screen
			// already shows "SCAN MRZ QR CODE" at the bottom, and the next
			// loop iteration will block on readBarcode().
		}
	}
}

// readBarcode reads a QR code from the barcode scanner serial port.
func readBarcode(port string) (string, error) {
	fd, err := unix.Open(port, unix.O_RDONLY|unix.O_NOCTTY, 0)
	if err != nil {
		return "", fmt.Errorf("open barcode scanner %s: %w", port, err)
	}
	defer unix.Close(fd)

	// Configure: 115200 baud, 8N1, raw
	var termios unix.Termios
	termios.Cflag = unix.B115200 | unix.CS8 | unix.CREAD | unix.CLOCAL
	termios.Iflag = 0
	termios.Oflag = 0
	termios.Lflag = 0
	termios.Cc[unix.VMIN] = 1  // block until at least 1 byte
	termios.Cc[unix.VTIME] = 0 // no timeout (wait forever)
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &termios); err != nil {
		return "", fmt.Errorf("configure barcode scanner: %w", err)
	}
	unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIOFLUSH)

	// Read data — QR codes have no CRLF terminator on this device.
	// We accumulate bytes and detect completion by a read timeout gap.
	buf := make([]byte, 512)
	var data []byte

	// First read blocks until data arrives
	n, err := unix.Read(fd, buf)
	if err != nil {
		return "", fmt.Errorf("barcode read: %w", err)
	}
	data = append(data, buf[:n]...)

	// Switch to short timeout to detect end of transmission
	termios.Cc[unix.VMIN] = 0
	termios.Cc[unix.VTIME] = 2 // 200ms timeout
	unix.IoctlSetTermios(fd, unix.TCSETS, &termios)

	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			break
		}
		if n == 0 {
			break // timeout = end of data
		}
		data = append(data, buf[:n]...)
	}

	result := strings.TrimSpace(string(data))
	if result == "" {
		return "", fmt.Errorf("empty barcode scan")
	}
	return result, nil
}

func watchdogLoop() {
	f, err := ipp.OpenWatchdog(watchdogPort)
	if err != nil {
		log.Printf("watchdog: %v (PIC32 watchdog not fed)", err)
		return
	}
	defer f.Close()
	for {
		f.Write([]byte("W"))
		time.Sleep(watchdogInterval)
	}
}

func keepaliveLoop(reader *ipp.Reader) {
	for {
		time.Sleep(statusPingInterval)
		sdNotify("WATCHDOG=1")
		reader.StatusPing()
	}
}

func sdNotify(state string) {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}
	conn, err := net.Dial("unixgram", addr)
	if err != nil {
		return
	}
	conn.Write([]byte(state))
	conn.Close()
}
