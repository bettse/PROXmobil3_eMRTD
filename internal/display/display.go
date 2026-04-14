package display

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"log"
	"os"

	"github.com/bettse/emrtd/internal/emrtd"
)

const (
	Width     = 800
	Height    = 480
	BPP       = 4 // BGRA
	FrameSize = Width * Height * BPP
	FBPath    = "/dev/fb0"
	BlankPath = "/sys/class/graphics/fb0/blank"
)

const (
	ScaleHuge   = 8
	ScaleLarge  = 5
	ScaleMedium = 3
	ScaleSmall  = 2
)

var (
	colorBG      = color.RGBA{0x10, 0x10, 0x20, 0xFF}
	colorWhite   = color.RGBA{0xFF, 0xFF, 0xFF, 0xFF}
	colorGold    = color.RGBA{0xFF, 0xCC, 0x00, 0xFF}
	colorGreen   = color.RGBA{0x00, 0xFF, 0x66, 0xFF}
	colorRed     = color.RGBA{0xFF, 0x44, 0x44, 0xFF}
	colorGray    = color.RGBA{0xAA, 0xAA, 0xAA, 0xFF}
	colorDimGray = color.RGBA{0x66, 0x66, 0x66, 0xFF}
	colorCyan    = color.RGBA{0x00, 0xCC, 0xFF, 0xFF}
)

type Display struct {
	fb *os.File
}

func Open() (*Display, error) {
	fb, err := os.OpenFile(FBPath, os.O_WRONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open framebuffer: %w", err)
	}
	if err := os.WriteFile(BlankPath, []byte("0"), 0644); err != nil {
		log.Printf("warning: could not disable blanking: %v", err)
	}
	return &Display{fb: fb}, nil
}

func (d *Display) Close() error {
	return d.fb.Close()
}

func (d *Display) WriteImage(img *image.RGBA) error {
	if img.Bounds().Dx() != Width || img.Bounds().Dy() != Height {
		return fmt.Errorf("image size %dx%d, want %dx%d", img.Bounds().Dx(), img.Bounds().Dy(), Width, Height)
	}
	buf := make([]byte, FrameSize)
	for y := 0; y < Height; y++ {
		for x := 0; x < Width; x++ {
			srcOff := y*img.Stride + x*4
			dstOff := (y*Width + x) * 4
			buf[dstOff+0] = img.Pix[srcOff+2] // B
			buf[dstOff+1] = img.Pix[srcOff+1] // G
			buf[dstOff+2] = img.Pix[srcOff+0] // R
			buf[dstOff+3] = img.Pix[srcOff+3] // A
		}
	}
	if _, err := d.fb.Seek(0, 0); err != nil {
		return err
	}
	_, err := d.fb.Write(buf)
	return err
}

func (d *Display) ShowBooting() error {
	img := newScreen()
	drawTextCentered(img, "BOOTING", Width/2, Height/2-ScaleHuge*7/2, ScaleHuge, colorDimGray)
	return d.WriteImage(img)
}

func (d *Display) ShowWaitingForMRZ() error {
	img := newScreen()
	drawTextCentered(img, "SCAN MRZ", Width/2, Height/2-ScaleHuge*7/2, ScaleHuge, colorCyan)
	drawTextCentered(img, "SCAN QR CODE", Width/2, Height/2+ScaleHuge*7/2+20, ScaleSmall, colorDimGray)
	return d.WriteImage(img)
}

func (d *Display) ShowWaitingForCard() error {
	img := newScreen()
	drawTextCentered(img, "TAP", Width/2, Height/2-ScaleHuge*7-10, ScaleHuge, colorWhite)
	drawTextCentered(img, "PASSPORT", Width/2, Height/2+10, ScaleHuge, colorWhite)
	return d.WriteImage(img)
}

func (d *Display) ShowAuthenticating() error {
	img := newScreen()
	drawTextCentered(img, "READING...", Width/2, Height/2-ScaleLarge*4, ScaleLarge, colorGold)
	return d.WriteImage(img)
}

// ShowProgress draws a progress bar at the top of the screen.
func (d *Display) ShowProgress(bytesRead, totalBytes int) error {
	img := newScreen()

	// Progress bar at top
	drawProgressBar(img, bytesRead, totalBytes)

	// Status text below
	pct := 0
	if totalBytes > 0 {
		pct = bytesRead * 100 / totalBytes
	}
	text := fmt.Sprintf("READING PHOTO  %d%%", pct)
	drawTextCentered(img, text, Width/2, 30, ScaleMedium, colorGold)

	return d.WriteImage(img)
}

// drawProgressBar draws a horizontal progress bar across the top of the screen.
func drawProgressBar(img *image.RGBA, current, total int) {
	const barY = 4
	const barH = 12
	const barMargin = 20

	// Background bar
	for x := barMargin; x < Width-barMargin; x++ {
		for y := barY; y < barY+barH; y++ {
			img.SetRGBA(x, y, color.RGBA{0x30, 0x30, 0x30, 0xFF})
		}
	}

	// Filled portion
	barW := Width - 2*barMargin
	fillW := 0
	if total > 0 {
		fillW = current * barW / total
		if fillW > barW {
			fillW = barW
		}
	}
	for x := barMargin; x < barMargin+fillW; x++ {
		for y := barY; y < barY+barH; y++ {
			img.SetRGBA(x, y, colorGreen)
		}
	}
}

func (d *Display) ShowResult(mrz *emrtd.MRZData, faceJPEG []byte) error {
	img := newScreen()

	// Layout: text fields on left (x=20..470), face photo on right (x=490..780)
	const textMaxX = 470
	y := 20

	// Title
	drawTextCentered(img, "PASSPORT READ", textMaxX/2, y, ScaleLarge, colorGreen)
	y += ScaleLarge*7 + 20

	if mrz != nil {
		// Last name, first name (last name first for professional look)
		drawTextAt(img, "NAME", 20, y, ScaleSmall, colorDimGray)
		y += ScaleSmall*7 + 4
		surname := mrz.Surname
		if len(surname) > 24 {
			surname = surname[:24]
		}
		drawTextAt(img, surname, 20, y, ScaleMedium, colorWhite)
		y += ScaleMedium*7 + 4
		given := mrz.GivenNames
		if len(given) > 24 {
			given = given[:24]
		}
		drawTextAt(img, given, 20, y, ScaleMedium, colorGray)
		y += ScaleMedium*7 + 16

		// Document number (masked: first 2 chars visible)
		drawTextAt(img, "DOC NUMBER", 20, y, ScaleSmall, colorDimGray)
		y += ScaleSmall*7 + 4
		drawTextAt(img, maskField(mrz.DocNumber, 2), 20, y, ScaleMedium, colorCyan)
		y += ScaleMedium*7 + 16

		// Row: nationality, sex
		drawTextAt(img, "NATIONALITY", 20, y, ScaleSmall, colorDimGray)
		drawTextAt(img, "SEX", 250, y, ScaleSmall, colorDimGray)
		y += ScaleSmall*7 + 4
		drawTextAt(img, mrz.Nationality, 20, y, ScaleMedium, colorWhite)
		drawTextAt(img, mrz.Sex, 250, y, ScaleMedium, colorWhite)
		y += ScaleMedium*7 + 16

		// Row: DOB (masked), DOE (masked)
		drawTextAt(img, "BIRTH", 20, y, ScaleSmall, colorDimGray)
		drawTextAt(img, "EXPIRY", 250, y, ScaleSmall, colorDimGray)
		y += ScaleSmall*7 + 4
		drawTextAt(img, maskField(formatDate(mrz.DateOfBirth), 2), 20, y, ScaleMedium, colorWhite)
		drawTextAt(img, maskField(formatDate(mrz.DateOfExpiry), 2), 250, y, ScaleMedium, colorWhite)
	}

	// Face photo on the right side
	if faceJPEG != nil {
		faceImg := decodeFaceImage(faceJPEG)
		if faceImg != nil {
			drawScaledImage(img, faceImg, 490, 20, 280, 420)
		} else {
			drawTextAt(img, fmt.Sprintf("FACE: %dB", len(faceJPEG)), 500, 200, ScaleSmall, colorGold)
		}
	}

	// "Scan again" prompt at bottom
	drawTextCentered(img, "SCAN MRZ QR CODE FOR NEXT READ", Width/2, Height-ScaleSmall*7-8, ScaleSmall, colorDimGray)

	return d.WriteImage(img)
}

// maskField replaces characters after position `visible` with asterisks.
func maskField(s string, visible int) string {
	if len(s) <= visible {
		return s
	}
	masked := []byte(s)
	for i := visible; i < len(masked); i++ {
		if masked[i] != '/' { // preserve date separators
			masked[i] = '*'
		}
	}
	return string(masked)
}

// decodeFaceImage decodes a JPEG face image from DG2.
func decodeFaceImage(data []byte) image.Image {
	reader := bytes.NewReader(data)
	img, err := jpeg.Decode(reader)
	if err != nil {
		log.Printf("JPEG decode failed: %v", err)
		return nil
	}
	return img
}

// drawScaledImage draws a source image scaled to fit within the given rectangle.
func drawScaledImage(dst *image.RGBA, src image.Image, x, y, maxW, maxH int) {
	bounds := src.Bounds()
	srcW := bounds.Dx()
	srcH := bounds.Dy()
	if srcW == 0 || srcH == 0 {
		return
	}

	// Calculate scale to fit within maxW x maxH
	scaleX := float64(maxW) / float64(srcW)
	scaleY := float64(maxH) / float64(srcH)
	scale := scaleX
	if scaleY < scale {
		scale = scaleY
	}

	dstW := int(float64(srcW) * scale)
	dstH := int(float64(srcH) * scale)

	// Center within the target area
	offsetX := x + (maxW-dstW)/2
	offsetY := y + (maxH-dstH)/2

	// Nearest-neighbor scaling
	for dy := 0; dy < dstH; dy++ {
		srcY := bounds.Min.Y + int(float64(dy)/scale)
		for dx := 0; dx < dstW; dx++ {
			srcX := bounds.Min.X + int(float64(dx)/scale)
			px := offsetX + dx
			py := offsetY + dy
			if px >= 0 && px < Width && py >= 0 && py < Height {
				r, g, b, a := src.At(srcX, srcY).RGBA()
				dst.SetRGBA(px, py, color.RGBA{
					R: uint8(r >> 8),
					G: uint8(g >> 8),
					B: uint8(b >> 8),
					A: uint8(a >> 8),
				})
			}
		}
	}
}

func (d *Display) ShowError(msg string) error {
	img := newScreen()
	drawTextCentered(img, "ERROR", Width/2, Height/2-ScaleLarge*7, ScaleLarge, colorRed)
	// Wrap long messages
	if len(msg) > 50 {
		drawTextCentered(img, msg[:50], Width/2, Height/2+20, ScaleSmall, colorGray)
		drawTextCentered(img, msg[50:], Width/2, Height/2+20+ScaleSmall*7+5, ScaleSmall, colorGray)
	} else {
		drawTextCentered(img, msg, Width/2, Height/2+20, ScaleSmall, colorGray)
	}
	return d.WriteImage(img)
}

// formatDate converts YYMMDD to YY/MM/DD for display.
func formatDate(d string) string {
	if len(d) != 6 {
		return d
	}
	return d[0:2] + "/" + d[2:4] + "/" + d[4:6]
}

func newScreen() *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, Width, Height))
	draw.Draw(img, img.Bounds(), &image.Uniform{colorBG}, image.Point{}, draw.Src)
	return img
}

func drawTextCentered(img *image.RGBA, text string, cx, y, scale int, c color.RGBA) {
	charW := 6 * scale
	totalW := len(text) * charW
	drawTextAt(img, text, cx-totalW/2, y, scale, c)
}

func drawTextAt(img *image.RGBA, text string, x, y, scale int, c color.RGBA) {
	charW := 6 * scale
	for i, ch := range text {
		drawCharScaled(img, byte(ch), x+i*charW, y, scale, c)
	}
}

func drawCharScaled(img *image.RGBA, ch byte, x, y, scale int, c color.RGBA) {
	glyph := getGlyph(ch)
	for row := 0; row < 7; row++ {
		for col := 0; col < 5; col++ {
			if glyph[row]&(1<<(4-col)) != 0 {
				for dy := 0; dy < scale; dy++ {
					for dx := 0; dx < scale; dx++ {
						px := x + col*scale + dx
						py := y + row*scale + dy
						if px >= 0 && px < Width && py >= 0 && py < Height {
							img.SetRGBA(px, py, c)
						}
					}
				}
			}
		}
	}
}

func getGlyph(ch byte) [7]byte {
	if ch >= 'A' && ch <= 'Z' {
		return upperGlyphs[ch-'A']
	}
	if ch >= 'a' && ch <= 'z' {
		return upperGlyphs[ch-'a']
	}
	if ch >= '0' && ch <= '9' {
		return digitGlyphs[ch-'0']
	}
	switch ch {
	case ' ':
		return [7]byte{}
	case '<':
		return [7]byte{0x02, 0x04, 0x08, 0x10, 0x08, 0x04, 0x02}
	case ',':
		return [7]byte{0x00, 0x00, 0x00, 0x00, 0x04, 0x04, 0x08}
	case ':':
		return [7]byte{0x00, 0x04, 0x00, 0x00, 0x04, 0x00, 0x00}
	case '.':
		return [7]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00}
	case '*':
		return [7]byte{0x00, 0x0A, 0x04, 0x1F, 0x04, 0x0A, 0x00}
	case '/':
		return [7]byte{0x01, 0x02, 0x04, 0x04, 0x08, 0x10, 0x00}
	case '-':
		return [7]byte{0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00}
	}
	return [7]byte{0x1F, 0x11, 0x11, 0x11, 0x11, 0x1F, 0x00}
}

var upperGlyphs = [26][7]byte{
	{0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x00}, // A
	{0x1E, 0x11, 0x1E, 0x11, 0x11, 0x1E, 0x00}, // B
	{0x0E, 0x11, 0x10, 0x10, 0x11, 0x0E, 0x00}, // C
	{0x1E, 0x11, 0x11, 0x11, 0x11, 0x1E, 0x00}, // D
	{0x1F, 0x10, 0x1E, 0x10, 0x10, 0x1F, 0x00}, // E
	{0x1F, 0x10, 0x1E, 0x10, 0x10, 0x10, 0x00}, // F
	{0x0E, 0x11, 0x10, 0x17, 0x11, 0x0E, 0x00}, // G
	{0x11, 0x11, 0x1F, 0x11, 0x11, 0x11, 0x00}, // H
	{0x0E, 0x04, 0x04, 0x04, 0x04, 0x0E, 0x00}, // I
	{0x01, 0x01, 0x01, 0x01, 0x11, 0x0E, 0x00}, // J
	{0x11, 0x12, 0x1C, 0x12, 0x11, 0x11, 0x00}, // K
	{0x10, 0x10, 0x10, 0x10, 0x10, 0x1F, 0x00}, // L
	{0x11, 0x1B, 0x15, 0x11, 0x11, 0x11, 0x00}, // M
	{0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x00}, // N
	{0x0E, 0x11, 0x11, 0x11, 0x11, 0x0E, 0x00}, // O
	{0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x00}, // P
	{0x0E, 0x11, 0x11, 0x15, 0x12, 0x0D, 0x00}, // Q
	{0x1E, 0x11, 0x11, 0x1E, 0x12, 0x11, 0x00}, // R
	{0x0E, 0x10, 0x0E, 0x01, 0x11, 0x0E, 0x00}, // S
	{0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x00}, // T
	{0x11, 0x11, 0x11, 0x11, 0x11, 0x0E, 0x00}, // U
	{0x11, 0x11, 0x11, 0x11, 0x0A, 0x04, 0x00}, // V
	{0x11, 0x11, 0x11, 0x15, 0x1B, 0x11, 0x00}, // W
	{0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11, 0x00}, // X
	{0x11, 0x0A, 0x04, 0x04, 0x04, 0x04, 0x00}, // Y
	{0x1F, 0x01, 0x02, 0x04, 0x08, 0x1F, 0x00}, // Z
}

var digitGlyphs = [10][7]byte{
	{0x0E, 0x11, 0x13, 0x15, 0x19, 0x0E, 0x00}, // 0
	{0x04, 0x0C, 0x04, 0x04, 0x04, 0x0E, 0x00}, // 1
	{0x0E, 0x11, 0x01, 0x06, 0x08, 0x1F, 0x00}, // 2
	{0x0E, 0x11, 0x06, 0x01, 0x11, 0x0E, 0x00}, // 3
	{0x02, 0x06, 0x0A, 0x1F, 0x02, 0x02, 0x00}, // 4
	{0x1F, 0x10, 0x1E, 0x01, 0x11, 0x0E, 0x00}, // 5
	{0x06, 0x08, 0x1E, 0x11, 0x11, 0x0E, 0x00}, // 6
	{0x1F, 0x01, 0x02, 0x04, 0x04, 0x04, 0x00}, // 7
	{0x0E, 0x11, 0x0E, 0x11, 0x11, 0x0E, 0x00}, // 8
	{0x0E, 0x11, 0x0F, 0x01, 0x02, 0x0C, 0x00}, // 9
}
