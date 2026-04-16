# eMRTD Reader for PROXmobil3

Reads eMRTD (electronic Machine Readable Travel Documents) using the PROXmobil3's cVEND NFC reader with BAC (Basic Access Control) authentication.

## How It Works

1. **MRZ Input**: Scan a QR code containing the MRZ via the built-in barcode reader, or pass it via `-mrz` flag
2. **Tap Passport**: Place passport on the PROXmobil3's NFC reader
3. **BAC Authentication**: Derives encryption keys from MRZ data (document number, DOB, DOE), performs mutual authentication with the passport chip
4. **Read Data**: Reads DG1 (MRZ data) and DG2 (facial image) via secure messaging
5. **Display**: Shows parsed passport fields on the 800x480 framebuffer

## Building

Cross-compile for the PROXmobil3 (ARM Cortex-A9):

```sh
make build
```

Or manually:

```sh
GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -ldflags="-s -w" -o emrtd ./cmd/emrtd/
```

## Deploying

```sh
make deploy-binary
```

This copies the binary to `/init/emrtd/` on the device and makes it executable.

## Usage

On the PROXmobil3:

```sh
# Using barcode scanner for MRZ input (default)
/init/emrtd/emrtd

# Using MRZ from command line (for testing)
/init/emrtd/emrtd -mrz "L898902C<3UTO6908061F9406236ZE184226B<<<<<14"
```

### Flags

- `-mrz`: MRZ line 2 (or full 2-line MRZ) — bypasses barcode scanner
- `-port`: NFC reader serial port (default: `/dev/ttymxc3`)
- `-barcode`: Barcode scanner serial port (default: `/dev/ttyUSB0`)

## Architecture

```
cmd/emrtd/         Main entry point, card loop, MRZ input
internal/
  ipp/             IPP protocol (from stamper) — serial framing, APDU proxy
  bac/             BAC key derivation + mutual authentication
  sm/              Secure Messaging — 3DES APDU wrap/unwrap
  emrtd/           eMRTD operations — SELECT, READ BINARY, DG parsing
  display/         800x480 BGRA framebuffer rendering
```

## Protocol Stack

```
 ┌─────────────────────┐
 │  eMRTD Application  │  DG1/DG2 reading, MRZ parsing
 ├─────────────────────┤
 │  Secure Messaging   │  3DES-CBC encryption + ISO 9797-1 MAC
 ├─────────────────────┤
 │  BAC Authentication │  MRZ key derivation, mutual auth
 ├─────────────────────┤
 │  ISO 7816 APDU      │  SELECT, READ BINARY, GET CHALLENGE, EXT AUTH
 ├─────────────────────┤
 │  IPP / APDUProx     │  cVEND NFC reader protocol (0xB4/0xB5)
 ├─────────────────────┤
 │  Serial (UART)      │  /dev/ttymxc3 @ 115200 baud
 └─────────────────────┘
```

## Security Notes

- Only supports BAC (Basic Access Control), not PACE
- MRZ data is required to authenticate — the passport chip cannot be read without it
- All post-authentication communication is encrypted with 3DES session keys
